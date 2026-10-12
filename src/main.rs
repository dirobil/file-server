use std::path::PathBuf;

use axum::extract::{Multipart, Path as AxPath, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use serde::Deserialize;
use tokio::fs;

mod auth;
mod config;
mod crypto;
mod gui;
mod state;
mod templates;

use auth::AdminCookie;
use state::{AppState, Templates};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Флаг --gui (или FILE_SERVER_GUI=1): запускаем нативное окно с адресом и QR-кодом.
    if args.iter().any(|a| a == "--gui") || std::env::var("FILE_SERVER_GUI").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
        gui::run_from_cli(&args);
        return;
    }

    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    // Конфиг лежит в «домашней директории приложения» (Windows/Linux/Mac — свои пути),
    // формат TOML по умолчанию; переопределяется переменной FILE_SERVER_CONFIG.
    let config_path = config::config_path();
    let mut cfg = match config::Config::load(&config_path) {
        Ok(Some(c)) => c,
        Ok(None) => config::Config::with_storage(None),
        Err(e) => {
            eprintln!("Предупреждение: {e} — начинаем с чистого конфига");
            config::Config::with_storage(None)
        }
    };

    // Первый запуск: пароль администратора можно задать переменной окружения,
    // иначе он будет создан автоматически на странице /admin.
    if !cfg.has_admin_password() {
        if let Ok(pwd) = std::env::var("ADMIN_PASSWORD") {
            cfg.admin.password_hash = auth::hash_password(&pwd);
            if let Err(e) = cfg.save(&config_path) {
                eprintln!("Не удалось сохранить конфиг: {e}");
            }
        }
    }

    // Переменная STORAGE_DIR остаётся как способ предзадать директорию (например, в Docker).
    if let Some(dir) = std::env::var("STORAGE_DIR").ok().map(PathBuf::from) {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("Не удалось создать директорию {dir:?}: {e}");
            std::process::exit(1);
        }
        if cfg.storage_dir.as_ref() != Some(&dir) {
            cfg.storage_dir = Some(dir);
            if let Err(e) = cfg.save(&config_path) {
                eprintln!("Не удалось сохранить конфиг: {e}");
            }
        }
    }

    let templates = Templates::load();
    let state = AppState::new(templates, config_path.clone(), cfg.clone());

    let app = build_router(state);

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
    println!("  Конфиг:       {}", config_path.display());

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Ошибка сервера: {e}");
        std::process::exit(1);
    }
}

/// Собирает HTTP-роутер сервера. Используется и консольным `main`, и GUI-окном.
pub fn build_router(state: AppState) -> Router {
    // Админ-зона (/admin, /logout) закрыта middleware require_admin:
    // пользователи без сессии видят страницу «нет доступа».
    let admin_zone = Router::new()
        .route("/admin", get(admin_page).post(admin_submit))
        .route("/logout", get(logout))
        // Удаление файлов — тоже админская операция: пользователи могут только
        // загружать и скачивать, но не стирать чужие файлы.
        .route("/delete/{*name}", axum::routing::post(delete_file))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::require_admin));

    Router::new()
        .route("/", get(index))
        // Лимит размера загрузки задаётся в админ-панели (config.max_upload_mb)
        // и проверяется потоково внутри хендлера upload(); предохранитель от
        // гигантских тел ставит middleware `body_limit` — он перечитывает конфиг
        // на каждый запрос, поэтому настройка применяется без перезапуска.
        .route("/upload", axum::routing::post(upload))
        .route("/download/{*name}", get(download))
        // Открытая зона входа — только если пароль уже установлен.
        .route("/login", get(login_page).post(login_submit))
        .merge(admin_zone)
        // CSS is embedded into the binary too, so the server needs no files at runtime.
        .route("/style.css", get(|| async {
            ([(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")], templates::STYLE_CSS)
        }))
        .layer(middleware::from_fn_with_state(state.clone(), body_limit))
        .with_state(state)
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
                        // Файлы метаданных (*.meta.json) — служебные, не показываем.
                        if name.ends_with(".meta.json") {
                            continue;
                        }
                        // Для шифрованных файлов показываем размер оригинала.
                        let size = match crypto::has_meta(dir, name) {
                            true => fs::read(crypto::meta_path(dir, name))
                                .await
                                .ok()
                                .and_then(|b| serde_json::from_slice::<crypto::FileMeta>(&b).ok())
                                .map(|m| m.size)
                                .unwrap_or_else(|| meta.len()),
                            false => meta.len(),
                        };
                        out.push((name.to_string(), size));
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

    // Лимит размера файла берём из конфигурации — его можно менять в админ-панели.
    let max_file_size = state.config().max_upload_bytes();
    let limit_label = templates::human_size(state.config().max_upload_mb * 1024 * 1024);

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
        let content_type = field
            .content_type()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let path = unique_path(&dir, &name).await;
        // Имя, под которым файл реально лежит на диске (может отличаться из-за дубликатов).
        let stored_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
        let enc_key = state.encryption_key();

        // Случайная «база» nonce для потока шифрования (уникальна на каждый файл).
        let mut nonce_base = [0u8; 8];
        use rand::TryRngCore;
        let _ = rand::rngs::OsRng.try_fill_bytes(&mut nonce_base);
        let mut seq: u32 = 0;
        let mut plain_size: u64 = 0;

        // stream the field to disk in chunks to avoid loading whole file into memory
        let mut data = match fs::File::create(&path).await {
            Ok(f) => f,
            Err(e) => {
                errors.push(format!("Не удалось создать файл {name}: {e}"));
                continue;
            }
        };

        // Для шифрованных файлов пишем заголовок: MAGIC(4) + случайная база nonce(8).
        if enc_key.is_some() {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = data.write_all(crypto::MAGIC).await {
                drop(data);
                let _ = fs::remove_file(&path).await;
                errors.push(format!("Ошибка записи заголовка {name}: {e}"));
                continue;
            }
            if let Err(e) = data.write_all(&nonce_base).await {
                drop(data);
                let _ = fs::remove_file(&path).await;
                errors.push(format!("Ошибка записи заголовка {name}: {e}"));
                continue;
            }
        }

        let mut written: usize = 0;
        let mut failed = false;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    written += chunk.len();
                    if written > max_file_size {
                        failed = true;
                        errors.push(format!(
                            "Файл {name} превышает лимит {limit_label}. \
                             Администратор может увеличить его в /admin."
                        ));
                        break;
                    }
                    plain_size += chunk.len() as u64;
                    // Шифруем чанк на лету, если ключ включён. Формат блока: len_u32_le + ciphertext+tag.
                    let out_buf: Vec<u8> = match &enc_key {
                        Some(key) => {
                            match crypto::encrypt_chunk(key, &nonce_base, seq, &chunk) {
                                Ok(enc) => {
                                    seq += 1;
                                    let mut buf = Vec::with_capacity(4 + enc.len());
                                    buf.extend_from_slice(&(enc.len() as u32).to_le_bytes());
                                    buf.extend_from_slice(&enc);
                                    buf
                                }
                                Err(e) => {
                                    failed = true;
                                    errors.push(format!("Ошибка шифрования {name}: {e}"));
                                    break;
                                }
                            }
                        }
                        None => chunk.to_vec(),
                    };
                    if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut data, &out_buf).await {
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
            // Для шифрованных файлов пишем метаданные (имя/MIME/размер),
            // чтобы при скачивании вернуть обычный файл с правильным типом.
            if enc_key.is_some() {
                let meta = crypto::FileMeta {
                    name: stored_name.clone(),
                    content_type,
                    size: plain_size,
                };
                if let Ok(json) = serde_json::to_vec(&meta) {
                    let _ = fs::write(crypto::meta_path(&dir, &stored_name), json).await;
                }
            }
            saved.push(stored_name);
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

/// Download a stored file by name. If the file is encrypted on disk —
/// transparently decrypt it on the fly, so the user just gets a normal file.
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

    // Шифрованный файл? Проверяем магическую сигнатуру в начале файла.
    let enc_key = state.encryption_key();
    let encrypted = head_is_magic(&path).await.unwrap_or(false);

    if encrypted {
        let Some(key) = enc_key else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "Файл зашифрован, но шифрование сейчас выключено или ключ недоступен.",
            )
                .into_response();
        };
        // Читаем метаданные (content-type оригинала).
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
        let meta = fs::read(crypto::meta_path(&dir, &name))
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<crypto::FileMeta>(&b).ok());
        let content_type = meta
            .as_ref()
            .map(|m| m.content_type.clone())
            .unwrap_or_else(|| "application/octet-stream".to_string());

        match decrypt_whole_file(&path, &key).await {
            Ok(plain) => {
                let disposition = format!("attachment; filename=\"{}\"", sanitize_header(&name));
                (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, content_type),
                        (header::CONTENT_DISPOSITION, disposition),
                    ],
                    plain,
                )
                    .into_response()
            }
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        }
    } else {
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
}

/// Проверить первые байты файла на магическую сигнатуру `FSenc1`.
async fn head_is_magic(path: &std::path::Path) -> Option<bool> {
    use tokio::io::AsyncReadExt;
    let mut f = fs::File::open(path).await.ok()?;
    let len = f.metadata().await.ok()?.len();
    if len < crypto::MAGIC.len() as u64 {
        return Some(false);
    }
    let mut buf = [0u8; 6];
    f.read_exact(&mut buf).await.ok()?;
    Some(buf == *crypto::MAGIC)
}

/// Расшифровать весь файл в оперативную память и вернуть как тело ответа.
/// Формат на диске: MAGIC(4) | base(8) | для каждого чанка: len_u32_le + ciphertext+tag.
/// (Размер файла ограничен настройкой «макс. размер загрузки» — приемлемо.)
async fn decrypt_whole_file(path: &std::path::Path, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = fs::File::open(path).await.map_err(|e| format!("не удалось открыть файл: {e}"))?;
    f.seek(std::io::SeekFrom::Start(crypto::MAGIC.len() as u64)).await.map_err(|e| e.to_string())?;
    let mut base = [0u8; 8];
    f.read_exact(&mut base).await.map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    let mut seq: u32 = 0;
    loop {
        // длина следующего шифротекста (u32 LE); конец потока — EOF
        match read_u32_le(&mut f).await {
            Ok(Some(clen)) => {
                let mut cbuf = vec![0u8; clen as usize];
                f.read_exact(&mut cbuf).await.map_err(|e| e.to_string())?;
                let dec = crypto::decrypt_chunk(key, &base, seq, &cbuf)?;
                out.extend_from_slice(&dec);
                seq += 1;
            }
            Ok(None) => break, // EOF — всё прочитано
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Прочитать u32 little-endian; `None` если достигнут EOF ровно на границе.
async fn read_u32_le<R: tokio::io::AsyncReadExt + Unpin>(r: &mut R) -> Result<Option<u32>, String> {
    let mut b = [0u8; 4];
    // читаем побайтово, чтобы отличить «чистый EOF» от «оборванный заголовок»
    let mut got = 0usize;
    while got < 4 {
        match r.read(&mut b[got..got + 1]).await {
            Ok(0) => break,
            Ok(_) => got += 1,
            Err(e) => return Err(format!("ошибка чтения: {e}")),
        }
    }
    if got == 0 {
        Ok(None) // EOF
    } else if got < 4 {
        Err("битый зашифрованный файл (оборванный блок)".to_string())
    } else {
        Ok(Some(u32::from_le_bytes(b)))
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
    new_password: Option<String>,
    /// Чекбокс «Шифровать файлы на диске» (значение «1», если отмечен).
    encrypt: Option<String>,
    /// Кнопка отдельной формы «Применить лимит» (значение «1»).
    apply_limit: Option<String>,
    /// Новое значение лимита размера загрузки, МБ (поле в /admin).
    max_upload_mb: Option<String>,
}

#[derive(Deserialize)]
struct AdminQuery {
    msg: Option<String>,
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn admin_page(State(state): State<AppState>, query: axum::extract::Query<AdminQuery>) -> Response {
    let current = state.storage_dir().map(|d| d.display().to_string());
    let message = match query.msg.as_deref() {
        Some("saved") => Some("Настройка сохранена: обмен файлами работает."),
        Some("cleared") => Some("Настройка сброшена: пользователи снова видят заглушку."),
        Some("password") => Some("Пароль администратора обновлён."),
        Some("enc_on") => Some("Шифрование включено: новые файлы будут зашифрованы (AES-256-GCM)."),
        Some("enc_off") => Some("Шифрование выключено: новые файлы сохраняются как есть."),
        Some("limit") => Some("Лимит размера загружаемых файлов обновлён."),
        _ => None,
    };
    render_admin(&state, current.as_deref(), message, None)
}

async fn admin_submit(State(state): State<AppState>, Form(form): Form<AdminForm>) -> Response {
    // Смена пароля — необязательное поле; заполняется только если админ хочет его поменять.
    let new_password = form.new_password.unwrap_or_default();
    if !new_password.is_empty() {
        if new_password.len() < 6 {
            return render_admin_error(&state, "Пароль должен быть не короче 6 символов.");
        }
        if let Err(e) = state.set_admin_password_hash(auth::hash_password(&new_password)) {
            return render_admin_error(&state, &format!("Не удалось сохранить пароль: {e}"));
        }
    }

    // Лимит размера загрузки — отдельная форма со своей кнопкой (name="apply_limit" value="1"),
    // чтобы не путать его с сохранением директории.
    if form.apply_limit.as_deref() == Some("1") {
        let raw = form.max_upload_mb.unwrap_or_default();
        let mb: u64 = match raw.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                return render_admin_error(
                    &state,
                    "Лимит должен быть целым числом мегабайт (например, 500).",
                )
            }
        };
        if mb == 0 || mb > crate::config::HARD_MAX_UPLOAD_MB {
            return render_admin_error(&state, &format!(
                "Лимит должен быть от 1 до {} МБ.",
                crate::config::HARD_MAX_UPLOAD_MB
            ));
        }
        if let Err(e) = state.set_max_upload_mb(mb) {
            return render_admin_error(&state, &format!("Не удалось сохранить лимит: {e}"));
        }
        return Redirect::to("/admin?msg=limit").into_response();
    }

    if form.clear.as_deref() == Some("1") {
        if let Err(e) = state.set_storage_dir(None) {
            return render_admin_error(&state, &format!("Не удалось сохранить конфиг: {e}"));
        }
        return Redirect::to("/admin?msg=cleared").into_response();
    }

    // Шифрование — отдельная кнопка-переключатель (name="toggle_encrypt"),
    // чтобы не зависеть от поведения чекбоксов в форме.
    if form.encrypt.as_deref() == Some("toggle") {
        let new_state = !state.config().encryption.enabled;
        if let Err(e) = state.set_encryption(new_state) {
            return render_admin_error(&state, &format!("Не удалось сохранить настройку шифрования: {e}"));
        }
        return Redirect::to(if new_state { "/admin?msg=enc_on" } else { "/admin?msg=enc_off" })
            .into_response();
    }

    let raw = form.directory.unwrap_or_default().trim().to_string();
    if raw.is_empty() {
        return if new_password.is_empty() {
            render_admin_error(&state, "Укажите путь к директории.")
        } else {
            // Пароль сохранён, директория не менялась.
            Redirect::to("/admin?msg=password").into_response()
        };
    }
    let path = PathBuf::from(&raw);
    if !path.is_absolute() {
        return render_admin_error(&state, "Путь должен быть абсолютным («/…» или «C:\\…»).");
    }
    if let Err(e) = fs::create_dir_all(&path).await {
        return render_admin_error(&state, &format!("Не удалось создать директорию: {e}"));
    }
    if let Err(e) = state.set_storage_dir(Some(path)) {
        return render_admin_error(&state, &format!("Не удалось сохранить конфиг: {e}"));
    }
    Redirect::to(if new_password.is_empty() { "/admin?msg=saved" } else { "/admin?msg=password" })
        .into_response()
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
    let pwd_hint = if state.config().has_admin_password() {
        "Оставьте пустым, чтобы не менять текущий пароль."
    } else {
        "Пароль ещё не установлен — задайте его прямо сейчас (минимум 6 символов)."
    };
    let cfg = state.config();
    let enc_badge = if cfg.encryption.enabled {
        "<span class=\"ok\">Шифрование включено (AES-256-GCM). Новые файлы шифруются на диске; при скачивании сервер расшифровывает их сам — пользователь получает обычный файл.</span>"
    } else {
        "<span class=\"banner\">Шифрование выключено: файлы лежат на диске в открытом виде.</span>"
    };
    // Текущий лимит размера загрузки + подсказка для поля ввода.
    let limit_mb = cfg.max_upload_mb.to_string();
    let limit_hint = format!(
        "Сейчас разрешено загружать файлы размером до {}.",
        templates::human_size(cfg.max_upload_bytes() as u64)
    );

    Html(templates::render(
        &state.templates.admin,
        &[
            ("message", &msg),
            ("status", status),
            ("current", &value),
            ("pwd_hint", &templates::html_escape(pwd_hint)),
            ("enc_badge", enc_badge),
            ("enc_button", if cfg.encryption.enabled { "Выключить шифрование" } else { "Включить шифрование" }),
            ("max_upload_mb", &limit_mb),
            ("limit_hint", &templates::html_escape(&limit_hint)),
            ("hard_max_mb", &crate::config::HARD_MAX_UPLOAD_MB.to_string()),
        ],
    ))
    .into_response()
}

/// Страница входа в админку. Если пароль ещё не установлен — форма первичной настройки.
async fn login_page(State(state): State<AppState>) -> Response {
    let cfg = state.config();
    if !cfg.has_admin_password() {
        // Пароля нет: /admin открыт без входа, ссылка на логин не нужна.
        return Redirect::to("/admin").into_response();
    }
    Html(render_login(&state.templates, "", "Вход в админ-панель",
        "Админ-панель доступна только создателю сервера. Введите пароль.",
        "/login", "", "Войти")).into_response()
}

/// Обработка формы входа: проверяем пароль, заводим cookie-сессию.
async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Response {
    let cfg = state.config();
    if !cfg.has_admin_password() {
        return Redirect::to("/admin").into_response();
    }
    if auth::verify_password(&form.password, &cfg.admin.password_hash) {
        let token = state.create_session();
        (
            StatusCode::SEE_OTHER,
            [(header::SET_COOKIE, auth::session_cookie(&token))],
            [(header::LOCATION, "/admin")],
        )
            .into_response()
    } else {
        Html(render_login(
            &state.templates,
            "<div class=\"banner\">Неверный пароль.</div>",
            "Вход в админ-панель",
            "Админ-панель доступна только создателю сервера. Введите пароль.",
            "/login",
            "",
            "Войти",
        ))
        .into_response()
    }
}

/// Выход из админ-сессии.
async fn logout(State(state): State<AppState>, cookie: AdminCookie) -> Response {
    if let Some(token) = cookie.0 {
        state.revoke_session(&token);
    }
    (
        StatusCode::SEE_OTHER,
        [(header::SET_COOKIE, auth::clear_cookie())],
        [(header::LOCATION, "/")],
    )
        .into_response()
}

/// Рендер `static/login.html` с подстановкой текстов режима (вход / первая настройка).
fn render_login(
    templates_: &Templates,
    message: &str,
    heading: &str,
    intro: &str,
    action: &str,
    second_field: &str,
    button: &str,
) -> String {
    templates::render(
        templates_.login,
        &[
            ("message", message),
            ("heading", heading),
            ("intro", intro),
            ("action", action),
            ("second_field", second_field),
            ("button", button),
        ],
    )
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

/// Middleware-предохранитель: ограничивает размер тела запроса текущим
/// `max_upload_mb` из конфига + запас на рамки multipart. Axum по умолчанию
/// ничего не лимитирует сам (для потоковых экстракторов вроде Multipart
/// встроенный DefaultBodyLimit не применяется), поэтому весь контроль размера
/// держится здесь и в потоковой проверке внутри хендлера upload().
///
/// Схема работы (без перечитывания тела и без ложных срабатываний):
///  - если клиент объявил `Content-Length` больше лимита — сразу отвечаем
///    «413» с понятным сообщением, не читая тело;
///  - иначе тело передаётся дальше как есть, а реальный порог по фактическим
///    байтам обеспечивает потоковая проверка в `upload()`;
///  - если во время разбора multipart поток оборвался ошибкой (например,
///    клиент закрыл соединение), гипер-соединение корректно завершается,
///    а не «зависает» без ответа.
async fn body_limit(
    State(state): State<AppState>,
    req: Request,
    next: middleware::Next,
) -> Response {
    let limit = state.config().max_upload_bytes();
    // Запас на служебные части multipart (границы, заголовки частей) и на то,
    // что файл может быть ровно `limit` байт.
    let cap = limit + limit / 8 + 1024 * 1024;

    // Быстрая проверка по заявленной длине (если она известна).
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    if let Some(len) = declared {
        if len > cap as u64 {
            return too_large_response(limit);
        }
    }

    let resp = next.run(req).await;
    drain_unfinished_request(resp, declared.is_some()).await
}

/// Ответ «запрос слишком большой» с человекочитаемым текстом (его покажет
/// страница загрузки при ajax-ошибке вместо бессмысленного «Ошибка загрузки»).
fn too_large_response(limit: usize) -> Response {
    let label = templates::human_size(limit as u64);
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        format!(
            "Файл слишком большой: превышен лимит {label}. \
             Администратор может увеличить его в /admin."
        ),
    )
        .into_response()
}

/// Если хендлер вернул ошибку 400 (например, multipart-экстрактор отказал,
/// не начав читать тело), а клиент объявил `Content-Length`, hyper не может
/// корректно завершить соединение с незавершённым телом: браузер не получает
/// ответ, и на странице «ничего не происходит». В этом случае возвращаем
/// ответ с заголовком `Connection: close` — гипер допишет ответ и корректно
/// закроет соединение, xhr увидит сетевую ошибку и покажет понятное сообщение.
fn drain_unfinished_request(resp: Response, req_had_known_length: bool) -> Response {
    if !(req_had_known_length && resp.status() == StatusCode::BAD_REQUEST) {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    parts.headers.insert(
        header::CONNECTION,
        HeaderValue::from_static("close"),
    );
    axum::response::Response::from_parts(parts, body).into_response()
}
