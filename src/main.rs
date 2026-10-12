use std::path::PathBuf;

use axum::extract::{Multipart, Path as AxPath, State};
use axum::http::{header, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use serde::Deserialize;
use tokio::fs;

mod auth;
mod config;
mod crypto;
mod state;
mod templates;
mod tls;

use auth::AdminCookie;
use state::{AppState, Templates};

const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100 MB per file

#[tokio::main]
async fn main() {
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

    // Админ-зона (/admin, /logout) закрыта middleware require_admin:
    // пользователи без сессии видят страницу «нет доступа».
    let admin_zone = Router::new()
        .route("/admin", get(admin_page).post(admin_submit))
        .route("/logout", get(logout))
        // Удаление файлов — тоже админская операция: пользователи могут только
        // загружать и скачивать, но не стирать чужие файлы.
        .route("/delete/{*name}", axum::routing::post(delete_file))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::require_admin));

    let app = Router::new()
        .route("/", get(index))
        .route("/upload", axum::routing::post(upload))
        .route("/download/{*name}", get(download))
        // Открытая зона входа — только если пароль уже установлен.
        .route("/login", get(login_page).post(login_submit))
        // Публичный ECDH-ключ сервера — браузер добавляет его получателем ключа
        // файла, чтобы зашифрованное «в браузере» можно было скачать позже.
        .route("/ecdh_pubkey", get(ecdh_pubkey))
        // PEM самоподписанного сертификата — добавить в доверенные один раз.
        .route("/ca.crt", get(ca_crt))
        .merge(admin_zone)
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
    println!("  Конфиг:       {}", config_path.display());

    // HTTPS (нужен для WebCrypto на не-local адресе вроде 192.168.0.16).
    // Сертификат — самоподписанный, выпускается автоматически при первом включении.
    let cfg_now = state.config();
    let https_task = if cfg_now.tls.enabled {
        let addr = cfg_now.tls.addr.clone();
        match tls::server_config(&addr) {
            Ok((tls_cfg, _pem)) => {
                let https_bind = https_bind_addr(&bind);
                match tokio::net::TcpListener::bind(&https_bind).await {
                    Ok(l) => {
                        println!("  HTTPS:        https://{https_bind}  (сертификат для {addr})");
                        println!("  Корневой сертификат: https://{https_bind}/ca.crt");
                        let app2 = app.clone();
                        Some(tokio::spawn(async move {
                            let acceptor = tls::TlsListener::new(l, tls_cfg);
                            if let Err(e) = axum::serve(acceptor, app2.into_make_service()).await {
                                eprintln!("Ошибка HTTPS-сервера: {e}");
                            }
                        }))
                    }
                    Err(e) => {
                        eprintln!("Не удалось привязаться к https://{https_bind}: {e}");
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("HTTPS выключен: {e}");
                None
            }
        }
    } else {
        println!("  HTTPS:        выключен (включите в /admin — нужен для шифрования в браузере)");
        None
    };

    let result = axum::serve(listener, app).await;
    if let Some(t) = https_task {
        t.abort();
    }
    if let Err(e) = result {
        eprintln!("Ошибка сервера: {e}");
        std::process::exit(1);
    }
}

/// Адрес HTTPS-слушателя: тот же хост, порт HTTP + 1000 (3000 → 4000).
fn https_bind_addr(bind: &str) -> String {
    match bind.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(p) => format!("{host}:{}", p.saturating_add(1000)),
            Err(_) => bind.to_string(),
        },
        None => bind.to_string(),
    }
}

/// Только порт из адреса HTTPS-слушателя (для подсказки в админке).
fn https_port_from_bind(bind: &str) -> u16 {
    bind.rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .map(|p| p.saturating_add(1000))
        .unwrap_or(4000)
}

/// Main page. If the server is not configured yet — show the "not configured" stub.
async fn index(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Запомним, как именно открыли страницу (https или http, какой хост) —
    // это определяет доступность WebCrypto для тумблера «Шифрование в браузере».
    {
        let host = headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let proto = headers
            .get("x-forwarded-proto")
            .or_else(|| headers.get("forwarded"))
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                if v.contains("https") { "https" } else { "http" }
            })
            .unwrap_or("")
            .to_string();
        state.note_request_ctx(&host, &proto);
    }
    let dir = match state.storage_dir() {
        None => return Html(state.templates.not_configured).into_response(),
        Some(d) => d,
    };

    let mut files = list_files(&dir).await;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let files_html = render_file_list(&dir, &files);
    let secure = state.is_secure_context();
    Html(templates::render(
        &state.templates.main_page,
        &[
            ("flash", ""),
            ("dir", &templates::html_escape(&dir.display().to_string())),
            ("files", &files_html),
            ("tls_enabled", if state.config().tls.enabled { "1" } else { "0" }),
            (
                "https_hint",
                if secure {
                    ""
                } else if state.config().tls.enabled {
                    "<div class=\"banner\">&#9888;&#65039; Шифрование в браузере (WebCrypto) требует HTTPS.                      Откройте эту страницу по адресу <code>https://…</code> — см. ссылку в админ-панели.</div>"
                } else {
                    "<div class=\"banner\">&#9888;&#65039; Для шифрования файлов в браузере включите HTTPS                      в <a href=\"/admin\">админ-панели</a>.</div>"
                },
            ),
            ("secure", if secure { "1" } else { "0" }),
        ],
    ))
    .into_response()
}

/// Build the file-list fragment (rows of `static/main_page.html`'s {{files}} placeholder).
fn render_file_list(files_dir: &PathBuf, files: &[(String, u64)]) -> String {
    if files.is_empty() {
        return r#"<div class="empty">Пока нет ни одного файла — загрузите первый!</div>"#.to_string();
    }
    let items: String = files
        .iter()
        .map(|(name, size)| {
            let esc = templates::html_escape(name);
            let url = templates::url_encode(name);
            let lock = if crypto::has_ekey(files_dir, name) {
                r#" <span class="lock" title="Зашифровано в браузере (сквозное шифрование)">&#128274;</span>"#
            } else {
                ""
            };
            format!(
                r#"<li><div><div class="fname">{esc}{lock}</div><div class="fsize">{}</div></div>
<div class="actions"><a class="dl" id="dl-{url}" href="/download/{url}">Скачать</a>
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
                        // Служебные файлы (метаданные / конверты ключей) не показываем.
                        if name.ends_with(".meta.json") || name.ends_with(crypto::EKEY_EXT) {
                            continue;
                        }
                        // Сквозное шифрование: имя и размер берём из конверта.
                        if crypto::has_ekey(dir, name) {
                            if let Some(wm) = read_web_meta(dir, name).await {
                                out.push((wm.name, wm.size));
                                continue;
                            }
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
        // Файл зашифрован в браузере (WebCrypto)? Магическая сигнатура FSweb1.
        let mut peek = [0u8; 6];
        let is_web_enc = match field.fill_bytes(&mut peek).await {
            Ok(()) => peek == *crypto::MAGIC_WEB,
            Err(_) => false,
        };

        if is_web_enc {
            // Сквозное шифрование: сервер хранит только шифртекст + конверт параметров.
            // Ключ файла знает лишь браузер-отправитель и получатели из конверта.
            let base_name = if crypto::has_ekey(&dir, &name) {
                // дубликат имени — добавим суффикс (1), (2)…
                unique_path(&dir, &name).await
            } else {
                dir.join(&name)
            };
            let stem = base_name.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
            let ekey = crypto::ekey_path(&dir, &stem);
            let mut out = match fs::File::create(&base_name).await {
                Ok(f) => f,
                Err(e) => {
                    errors.push(format!("Не удалось создать файл {name}: {e}"));
                    continue;
                }
            };
            let mut written: usize = 0;
            let mut failed = false;
            use tokio::io::AsyncWriteExt;
            // первые 6 байт уже прочитаны в peek
            if out.write_all(&peek).await.is_err() {
                failed = true;
            }
            while !failed {
                match field.chunk().await {
                    Ok(Some(chunk)) => {
                        written += chunk.len();
                        if written > MAX_FILE_SIZE {
                            errors.push(format!(
                                "Файл {name} превышает лимит {} МБ",
                                MAX_FILE_SIZE / 1024 / 1024
                            ));
                            failed = true;
                            break;
                        }
                        if out.write_all(&chunk).await.is_err() {
                            failed = true;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        errors.push(format!("Ошибка загрузки {name}: {e}"));
                        failed = true;
                    }
                }
            }
            // читаем конверт из второго поля формы (meta_<имя>)
            drop(out);
            let mut meta_ok = false;
            {
                let mf = multipart.next_field().await.ok().flatten();
                if let Some(mf) = mf {
                    let fname = mf.name().unwrap_or_default().to_string();
                    if let Some(orig) = fname.strip_prefix("meta_") {
                        if let Ok(bytes) = mf.bytes().await {
                            meta_ok = save_web_meta(&dir, &stem, orig, &bytes).await;
                        }
                    }
                }
            }
            if failed || !meta_ok {
                let _ = fs::remove_file(&base_name).await;
                let _ = fs::remove_file(&ekey).await;
                if !meta_ok && !failed {
                    errors.push(format!("Файл {name}: повреждён конверт ключей"));
                }
            } else {
                saved.push(stem);
            }
            continue;
        }

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
                    if written > MAX_FILE_SIZE {
                        failed = true;
                        errors.push(format!(
                            "Файл {name} превышает лимит {} МБ",
                            MAX_FILE_SIZE / 1024 / 1024
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

/// Прочитать конверт сквозного шифрования `<имя>.ekey.json`.
async fn read_web_meta(dir: &PathBuf, name: &str) -> Option<crypto::WebMeta> {
    let bytes = fs::read(crypto::ekey_path(dir, name)).await.ok()?;
    serde_json::from_slice::<crypto::WebMeta>(&bytes).ok()
}

/// Проверить и сохранить конверт ключей для веб-шифрованного файла.
/// `orig_name` — имя из формы (`meta_<имя>`), сверяется с именем внутри JSON.
async fn save_web_meta(dir: &PathBuf, stored: &str, orig_name: &str, json: &[u8]) -> bool {
    let Ok(meta) = serde_json::from_slice::<crypto::WebMeta>(json) else {
        return false;
    };
    // Имя в конверте должно совпадать с тем, под которым пришёл файл,
    // и быть безопасным (без путей/управляющих символов).
    if meta.name != orig_name || AppState::sanitize_name(&meta.name) != meta.name {
        return false;
    }
    if meta.recipients.is_empty() || meta.recipients.len() > 64 {
        return false;
    }
    // Все публичные ключи получателей обязаны быть валидными точками P-256.
    for r in &meta.recipients {
        let Some(sec1) = crypto::b64url_decode(&r.pubkey) else {
            return false;
        };
        if crypto::validate_ecdh_public(&sec1).is_none() {
            return false;
        }
    }
    if crypto::b64url_decode(&meta.iv).map(|v| v.len() != 12).unwrap_or(true) {
        return false;
    }
    let compact = match serde_json::to_vec(&meta) {
        Ok(v) => v,
        Err(_) => return false,
    };
    fs::write(crypto::ekey_path(dir, stored), compact).await.is_ok()
}

/// Публичный ECDH-ключ сервера (P-256, uncompressed SEC1 base64url).
/// Браузер добавляет сервера получателем ключа каждого сквозного файла,
/// чтобы файл можно было скачать позже с любого устройства.
async fn ecdh_pubkey(State(state): State<AppState>) -> Response {
    let json = state.server_ecdh_pub();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json,
    )
        .into_response()
}

/// PEM сертификата сервера — пользователь может один раз добавить его
/// в доверенные на устройстве, тогда предупреждение браузера не появится.
async fn ca_crt(State(state): State<AppState>) -> Response {
    match tls::server_config(&state.config().tls.addr) {
        Ok((_cfg, pem)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/x-pem-file"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"file-server.crt\""),
            ],
            String::from_utf8_lossy(&pem).into_owned(),
        )
            .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
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

    // Сквозное шифрование «в браузере»: сервер не знает ключ — отдаём шифртекст
    // как есть; браузер получателя расшифрует его сам (WebCrypto).
    if crypto::has_ekey(&dir, path.file_name().and_then(|n| n.to_str()).unwrap_or("")) {
        match tokio::fs::File::open(&path).await {
            Ok(file) => {
                let io = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(file));
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    io,
                )
                    .into_response();
            }
            Err(_) => return (StatusCode::NOT_FOUND, "Не удалось открыть файл").into_response(),
        }
    }

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
/// (У нас лимит 100 МБ на файл — приемлемо.)
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
    /// Переключатель HTTPS («toggle» при нажатии кнопки).
    tls: Option<String>,
    /// Адрес (IP/имя) для TLS-сертификата.
    tls_addr: Option<String>,
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
        Some("tls_on") => Some("HTTPS включён. Откройте https://адрес:порт и примите сертификат один раз — после этого доступен тумблер «Шифрование в браузере»."),
        Some("tls_off") => Some("HTTPS выключен."),
        Some("tls_addr") => Some("Адрес для сертификата обновлён. При следующем перезапуске будет выпущен новый сертификат."),
        Some(e) if e.starts_with("tls_err:") => Some(&format!("Не удалось включить HTTPS: {}", &e["tls_err:".len()..])),
        _ => None,
    };
    // сообщение может быть сформировано локально — копируем до заимствования
    let message_owned = message.map(|s| s.to_string());
    render_admin(&state, current.as_deref(), message_owned.as_deref(), None)
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

    // HTTPS — отдельная кнопка-переключатель; адрес сертификата можно менять отдельно.
    if form.tls.as_deref() == Some("toggle") {
        let new_state = !state.config().tls.enabled;
        if let Err(e) = state.set_tls(new_state) {
            return Redirect::to(&format!("/admin?msg=tls_err:{}", templates::url_encode(&e)))
                .into_response();
        }
        return Redirect::to(if new_state { "/admin?msg=tls_on" } else { "/admin?msg=tls_off" })
            .into_response();
    }
    if let Some(addr) = form.tls_addr.map(|a| a.trim().to_string()).filter(|a| !a.is_empty()) {
        let cur = state.config().tls.addr.clone();
        if cur != addr {
            if let Err(e) = state.set_tls_addr(&addr) {
                return render_admin_error(&state, &format!("Не удалось сохранить адрес TLS: {e}"));
            }
            return Redirect::to("/admin?msg=tls_addr").into_response();
        }
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

    let https_url = match std::env::var("BIND") {
        Ok(b) => format!("https://{}:{}", b.rsplit_once(':').map(|(h, _)| h).unwrap_or("localhost"), https_port_from_bind(&b)),
        Err(_) => format!("https://{}:4000", cfg.tls.addr),
    };
    let tls_badge = if cfg.tls.enabled {
        format!(
            "<span class=\"ok\">HTTPS включён: <a href=\"{https_url}\" target=\"_blank\">{https_url}</a>              (сертификат для <code>{}</code>). При первом открытии браузер покажет предупреждение —              нажмите «Дополнительно → Перейти на сайт», либо один раз добавьте сертификат из              <a href=\"/ca.crt\">/ca.crt</a> в доверенные на устройстве.              Только на HTTPS-адресе работает тумблер «Шифрование в браузере».</span>",
            templates::html_escape(&cfg.tls.addr)
        )
    } else {
        "<span class=\"banner\">HTTPS выключен. Без него страница по IP-адресу (например, http://192.168.0.16)          не сможет использовать WebCrypto — браузер разрешает это только на HTTPS или localhost.</span>".to_string()
    };

    Html(templates::render(
        &state.templates.admin,
        &[
            ("message", &msg),
            ("status", status),
            ("current", &value),
            ("pwd_hint", &templates::html_escape(pwd_hint)),
            ("enc_badge", enc_badge),
            ("enc_button", if cfg.encryption.enabled { "Выключить шифрование" } else { "Включить шифрование" }),
            ("tls_badge", &tls_badge),
            ("tls_button", if cfg.tls.enabled { "Выключить HTTPS" } else { "Включить HTTPS" }),
            ("tls_addr", &templates::html_escape(&cfg.tls.addr)),
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
