use std::path::PathBuf;

use axum::extract::{Multipart, Path as AxPath, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use serde::Deserialize;
use tokio::fs;

mod state;
mod templates;

use state::{AppState, Templates};

const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100 MB per file

#[tokio::main]
async fn main() {
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    // Optional: preconfigure storage via env var (otherwise server starts "unconfigured")
    let initial_storage = std::env::var("STORAGE_DIR").ok().map(PathBuf::from);
    if let Some(dir) = &initial_storage {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("Не удалось создать директорию {dir:?}: {e}");
            std::process::exit(1);
        }
    }

    // HTML pages live in static/*.html — load them once at startup.
    let templates = Templates::load();
    let state = AppState::new(templates);
    state.set_storage_dir(initial_storage);

    let app = Router::new()
        .route("/", get(index))
        .route("/upload", axum::routing::post(upload))
        .route("/download/{*name}", get(download))
        .route("/delete/{*name}", axum::routing::post(delete_file))
        .route("/admin", get(admin_page).post(admin_submit))
        // CSS is embedded into the binary too, so the server needs no files at runtime.
        .route("/style.css", get(|| async {
            ([(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")], templates::STYLE_CSS)
        }))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Не удалось привязаться к {bind}: {e}");
            std::process::exit(1);
        }
    };
    println!("Файловый сервер запущен на http://{bind}");
    println!("  Главная:      http://{bind}/");
    println!("  Админ-панель: http://{bind}/admin");

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Ошибка сервера: {e}");
        std::process::exit(1);
    }
}

/// Main page. If the server is not configured yet — show the "not configured" stub.
async fn index(State(state): State<AppState>) -> Response {
    let dir = match state.storage_dir() {
        None => return Html(state.templates.not_configured).into_response(),
        Some(d) => d,
    };

    let mut files = list_files(&dir).await;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let files_html = render_file_list(&files);
    Html(templates::render(
        &state.templates.main_page,
        &[
            ("flash", ""),
            ("dir", &templates::html_escape(&dir.display().to_string())),
            ("files", &files_html),
        ],
    ))
    .into_response()
}

/// Build the file-list fragment (rows of `static/main_page.html`'s {{files}} placeholder).
fn render_file_list(files: &[(String, u64)]) -> String {
    if files.is_empty() {
        return r#"<div class="empty">Пока нет ни одного файла — загрузите первый!</div>"#.to_string();
    }
    let items: String = files
        .iter()
        .map(|(name, size)| {
            let esc = templates::html_escape(name);
            let url = templates::url_encode(name);
            format!(
                r#"<li><div><div class="fname">{esc}</div><div class="fsize">{}</div></div>
<div class="actions"><a class="dl" href="/download/{url}">Скачать</a>
<button class="danger" onclick="delFile('{url}')">Удалить</button></div></li>"#,
                templates::human_size(*size)
            )
        })
        .collect();
    format!(r#"<ul class="files">{items}</ul>"#)
}

async fn list_files(dir: &PathBuf) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    if let Ok(mut entries) = fs::read_dir(dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(meta) = entry.metadata().await {
                if meta.is_file() {
                    if let Some(name) = entry.file_name().to_str() {
                        out.push((name.to_string(), meta.len()));
                    }
                }
            }
        }
    }
    out
}

/// Handle multipart upload of one or more files.
async fn upload(State(state): State<AppState>, mut multipart: Multipart) -> Response {
    let dir = match state.storage_dir() {
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Сервер не настроен: администратор должен указать директорию в /admin",
            )
                .into_response()
        }
        Some(d) => d,
    };

    let mut saved: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                errors.push(format!("Ошибка чтения данных: {e}"));
                break;
            }
        };

        let raw_name = field
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "file".to_string());
        let name = AppState::sanitize_name(&raw_name);
        let path = unique_path(&dir, &name).await;

        // stream the field to disk in chunks to avoid loading whole file into memory
        let mut data = match fs::File::create(&path).await {
            Ok(f) => f,
            Err(e) => {
                errors.push(format!("Не удалось создать файл {name}: {e}"));
                continue;
            }
        };

        let mut written: usize = 0;
        let mut failed = false;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    written += chunk.len();
                    if written > MAX_FILE_SIZE {
                        failed = true;
                        errors.push(format!(
                            "Файл {name} превышает лимит {} МБ",
                            MAX_FILE_SIZE / 1024 / 1024
                        ));
                        break;
                    }
                    if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut data, &chunk).await {
                        failed = true;
                        errors.push(format!("Ошибка записи {name}: {e}"));
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    failed = true;
                    errors.push(format!("Ошибка загрузки {name}: {e}"));
                    break;
                }
            }
        }

        drop(data);
        if failed {
            let _ = fs::remove_file(&path).await;
        } else {
            saved.push(name);
        }
    }

    if !saved.is_empty() {
        let msg = format!("Загружено файлов: {}", saved.len());
        let mut body = String::new();
        for (i, f) in saved.iter().enumerate() {
            let url = templates::url_encode(f);
            if i > 0 {
                body.push_str(", ");
            }
            body.push_str(&format!(
                "<a href=\"/download/{url}\" style=\"color:#166534\">{f}</a>"
            ));
        }
        let mut extra = String::new();
        if !errors.is_empty() {
            extra = format!("<br>Часть файлов не загружена: {}", errors.join("; "));
        }
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            format!(
                "<div style=\"font-family:sans-serif;padding:20px\">&#9989; {msg}: {body}{extra}\
                 <br><a href=\"/\" style=\"color:#2563eb\">&larr; Вернуться</a></div>"
            ),
        )
            .into_response()
    } else {
        let msg = if errors.is_empty() {
            "Файлы не были получены"
        } else {
            "Ни один файл не был загружен"
        };
        (
            StatusCode::BAD_REQUEST,
            format!("{msg}: {}", errors.join("; ")),
        )
            .into_response()
    }
}

/// Pick a non-colliding path inside the storage dir (`name`, `name (1)`, `name (2)`, …).
async fn unique_path(dir: &PathBuf, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    let mut i = 1u32;
    loop {
        let p = dir.join(format!("{stem} ({i}){ext}"));
        if !p.exists() {
            return p;
        }
        i += 1;
    }
}

/// Download a stored file by name.
async fn download(State(state): State<AppState>, AxPath(raw): AxPath<String>) -> Response {
    let dir = match state.storage_dir() {
        None => return Html(state.templates.not_configured).into_response(),
        Some(d) => d,
    };

    let decoded = decode_percent(&raw);
    let Some(path) = AppState::resolve_file(&dir, &decoded) else {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "Файл не найден",
        )
            .into_response();
    };

    match tokio::fs::File::open(&path).await {
        Ok(file) => {
            let io = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(file));
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
            let disposition = format!("attachment; filename=\"{}\"", sanitize_header(filename));
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (header::CONTENT_DISPOSITION, disposition.as_str()),
                ],
                io,
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Не удалось открыть файл").into_response(),
    }
}

/// Delete a stored file (used from the main page UI).
async fn delete_file(State(state): State<AppState>, AxPath(raw): AxPath<String>) -> Response {
    let dir = match state.storage_dir() {
        Some(d) => d,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let decoded = decode_percent(&raw);
    match AppState::resolve_file(&dir, &decoded) {
        Some(path) => match fs::remove_file(&path).await {
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
struct AdminForm {
    directory: Option<String>,
    clear: Option<String>,
}

#[derive(Deserialize)]
struct AdminQuery {
    msg: Option<String>,
}

async fn admin_page(State(state): State<AppState>, query: axum::extract::Query<AdminQuery>) -> Response {
    let current = state.storage_dir().map(|d| d.display().to_string());
    let message = match query.msg.as_deref() {
        Some("saved") => Some("Настройка сохранена: обмен файлами работает."),
        Some("cleared") => Some("Настройка сброшена: пользователи снова видят заглушку."),
        _ => None,
    };
    render_admin(&state, current.as_deref(), message, None)
}

async fn admin_submit(State(state): State<AppState>, Form(form): Form<AdminForm>) -> Response {
    if form.clear.as_deref() == Some("1") {
        state.set_storage_dir(None);
        return Redirect::to("/admin?msg=cleared").into_response();
    }

    let raw = form.directory.unwrap_or_default().trim().to_string();
    if raw.is_empty() {
        return render_admin_error(&state, "Укажите путь к директории.");
    }
    let path = PathBuf::from(&raw);
    if !path.is_absolute() {
        return render_admin_error(&state, "Путь должен быть абсолютным (начинаться с «/»).");
    }
    if let Err(e) = fs::create_dir_all(&path).await {
        return render_admin_error(&state, &format!("Не удалось создать директорию: {e}"));
    }
    state.set_storage_dir(Some(path));
    Redirect::to("/admin?msg=saved").into_response()
}

fn render_admin_error(state: &AppState, msg: &str) -> Response {
    render_admin(state, None, None, Some(msg))
}

/// Render `static/admin.html` with escaped dynamic values.
fn render_admin(
    state: &AppState,
    current: Option<&str>,
    message: Option<&str>,
    error: Option<&str>,
) -> Response {
    let msg = match (error, message) {
        (Some(e), _) => format!("<div class=\"banner\">{}</div>", templates::html_escape(e)),
        (None, Some(m)) => format!("<div class=\"ok\">{}</div>", templates::html_escape(m)),
        (None, None) => String::new(),
    };
    let value = current.map(templates::html_escape).unwrap_or_default();
    let status = match current {
        Some(_) => "<div class=\"ok\">Сервер настроен: обмен файлами работает.</div>",
        None => "<div class=\"banner\">Сервер не настроен: пользователи видят заглушку.</div>",
    };

    Html(templates::render(
        &state.templates.admin,
        &[
            ("message", &msg),
            ("status", status),
            ("current", &value),
        ],
    ))
    .into_response()
}

/// Percent-decode a path segment (UTF-8 aware).
fn decode_percent(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Strip characters that would break an HTTP header value.
fn sanitize_header(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect()
}
