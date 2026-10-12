use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use crate::config::Config;
use crate::templates;

/// Время жизни админ-сессии с момента последней активности (продлевается при запросах).
pub const SESSION_TTL_SECS: u64 = 8 * 60 * 60; // 8 часов

/// HTML templates embedded into the binary at compile time (`include_str!`).
/// `'static` references — no allocation, works from any working directory.
#[derive(Clone, Copy)]
pub struct Templates {
    pub not_configured: &'static str,
    pub main_page: &'static str,
    pub admin: &'static str,
    pub login: &'static str,
    /// Страница «нет доступа» для пользователей без админ-сессии.
    pub denied: &'static str,
}

impl Templates {
    /// Return the compiled-in templates.
    pub fn load() -> Self {
        Self {
            not_configured: templates::load_template("not_configured.html"),
            main_page: templates::load_template("main_page.html"),
            admin: templates::load_template("admin.html"),
            login: templates::load_template("login.html"),
            denied: templates::load_template("denied.html"),
        }
    }
}

/// Shared application state: the (optional) storage directory configured by admin.
/// Cheap to clone because the directory lives behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub storage: std::sync::Arc<RwLock<Option<PathBuf>>>,
    pub templates: Templates,
    /// Путь к файлу конфига — настройки сохраняются сюда.
    pub config_path: std::sync::Arc<PathBuf>,
    /// Текущая конфигурация на диске (пароль админа и т.п.).
    pub config: std::sync::Arc<RwLock<Config>>,
    /// Активные админ-сессии: список токенов из cookie `fs_admin`.
    pub sessions: std::sync::Arc<Mutex<Vec<String>>>,
    /// Временный ECDH-ключ сервера (создаётся лениво при первом запросе /ecdh_pubkey).
    server_ecdh: std::sync::Arc<Mutex<Option<p256::SecretKey>>>,
    /// Host последнего запроса к главной — для определения «безопасного контекста».
    last_host: std::sync::Arc<RwLock<String>>,
    /// Протокол из Forwarded/X-Forwarded-Proto последнего запроса.
    last_forwarded: std::sync::Arc<RwLock<String>>,
}

impl AppState {
    pub fn new(templates: Templates, config_path: PathBuf, config: Config) -> Self {
        Self {
            storage: std::sync::Arc::new(RwLock::new(config.storage_dir.clone())),
            templates,
            config_path: std::sync::Arc::new(config_path),
            config: std::sync::Arc::new(RwLock::new(config)),
            sessions: std::sync::Arc::new(Mutex::new(Vec::new())),
            server_ecdh: std::sync::Arc::new(Mutex::new(None)),
            last_host: std::sync::Arc::new(RwLock::new(String::new())),
            last_forwarded: std::sync::Arc::new(RwLock::new(String::new())),
        }
    }

    /// Currently configured storage directory, if any.
    pub fn storage_dir(&self) -> Option<PathBuf> {
        self.storage.read().expect("state lock poisoned").clone()
    }

    /// Set (or clear with `None`) the storage directory **and persist it** to the
    /// config file. Returns Err(reason) if the file could not be written.
    pub fn set_storage_dir(&self, dir: Option<PathBuf>) -> Result<(), String> {
        let cfg = {
            let mut cur = self.config.write().expect("config lock poisoned");
            cur.version = crate::config::CONFIG_VERSION;
            cur.storage_dir = dir.clone();
            cur.clone()
        };
        cfg.save(&self.config_path)?;
        *self.storage.write().expect("state lock poisoned") = dir;
        Ok(())
    }

    // ---------- Конфигурация / пароль администратора ----------

    pub fn config(&self) -> Config {
        self.config.read().expect("config lock poisoned").clone()
    }

    /// Обновить хеш пароля администратора и сохранить конфиг на диск.
    pub fn set_admin_password_hash(&self, hash: String) -> Result<(), String> {
        let cfg = {
            let mut cur = self.config.write().expect("config lock poisoned");
            cur.version = crate::config::CONFIG_VERSION;
            cur.admin.password_hash = hash;
            cur.clone()
        };
        cfg.save(&self.config_path)
    }

    /// Включить/выключить шифрование файлов на диске. При первом включении
    /// генерируется ключ (32 байта от OS CSPRNG) и сохраняется в конфиг.
    pub fn set_encryption(&self, enabled: bool) -> Result<(), String> {
        let cfg = {
            let mut cur = self.config.write().expect("config lock poisoned");
            cur.version = crate::config::CONFIG_VERSION;
            cur.encryption.enabled = enabled;
            if enabled && crate::crypto::key_from_hex(&cur.encryption.key_hex).is_none() {
                cur.encryption.key_hex = crate::crypto::key_to_hex(&crate::crypto::generate_key());
            }
            cur.clone()
        };
        cfg.save(&self.config_path)
    }

    /// Текущий рабочий ключ шифрования (`None` — шифрование выключено).
    pub fn encryption_key(&self) -> Option<[u8; 32]> {
        self.config.read().expect("config lock poisoned").encryption_key()
    }

    // ---------- TLS (HTTPS) ----------

    /// Включить/выключить HTTPS-слушатель. При включении сертификат выпускается
    /// (или читается с диска) сразу — чтобы ошибка была видна админу немедленно.
    /// Возвращает текст ошибки, если сертификат выпустить не удалось.
    pub fn set_tls(&self, enabled: bool) -> Result<(), String> {
        let addr = self.config().tls.addr.clone();
        if enabled {
            // Проверим, что сертификат можно подготовить, ещё до записи конфига.
            crate::tls::server_config(&addr)?;
        }
        let cfg = {
            let mut cur = self.config.write().expect("config lock poisoned");
            cur.version = crate::config::CONFIG_VERSION;
            cur.tls.enabled = enabled;
            cur.clone()
        };
        cfg.save(&self.config_path)
    }

    /// Требует ли страница «безопасного контекста» для WebCrypto: https:// или
    /// localhost/127.0.0.1/[::1]. Определяется по заголовкам запроса
    /// (Forwarded/X-Forwarded-Proto) и имени хоста.
    pub fn is_secure_context(&self) -> bool {
        let fwd = self.last_forwarded.read().expect("lock poisoned").clone();
        if fwd == "https" {
            return true;
        }
        let host = self.last_host.read().expect("lock poisoned").clone();
        let host = match host.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
            _ => &host,
        };
        host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
    }

    /// Запомнить значения Host/Forwarded из последнего запроса к главной
    /// (этого достаточно, чтобы понять, открыта ли страница по HTTPS).
    pub fn note_request_ctx(&self, host: &str, proto: &str) {
        *self.last_host.write().expect("lock poisoned") = host.to_string();
        if !proto.is_empty() {
            *self.last_forwarded.write().expect("lock poisoned") = proto.to_string();
        }
    }

    /// Сменить адрес для сертификата (IP/имя сервера). Если сертификат уже
    /// выпущен для другого адреса — удаляем старый, новый будет создан при
    /// следующем включении/перезапуске.
    pub fn set_tls_addr(&self, addr: &str) -> Result<(), String> {
        let old = self.config().tls.addr.clone();
        let cfg = {
            let mut cur = self.config.write().expect("config lock poisoned");
            cur.version = crate::config::CONFIG_VERSION;
            cur.tls.addr = addr.to_string();
            cur.clone()
        };
        cfg.save(&self.config_path)?;
        if old != addr {
            let _ = std::fs::remove_file(crate::tls::cert_path());
        }
        Ok(())
    }

    // ---------- ECDH-ключ сервера (для сквозного шифрования в браузере) ----------

    /// Публичный ECDH-ключ сервера (P-256), base64url uncompressed SEC1.
    /// Генерируется один раз на запуск процесса и отдаётся браузеру по
    /// `/ecdh_pubkey`, чтобы отправитель включал сервера в получатели ключа файла.
    pub fn server_ecdh_pub(&self) -> String {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let mut guard = self.server_ecdh.lock().expect("ecdh lock poisoned");
        if guard.is_none() {
            // rand 0.9 несовместим с rand_core 0.6, который ждёт elliptic-curve,
            // поэтому берём рендер из самого p256 (фича "ecdh" включает "arithmetic").
            *guard = Some(p256::SecretKey::random(&mut rand_core::OsRng));
        }
        let sk = guard.as_ref().unwrap();
        let pk = sk.public();
        crate::crypto::b64url_encode(pk.to_encoded_point(false).as_bytes())
    }

    // ---------- Админ-сессии ----------

    /// Создать новый токен сессии (32 байта криптостойкой случайности).
    /// В памяти токен хранится как `"<token>:<unix-время истечения>"`.
    pub fn create_session(&self) -> String {
        use rand::TryRngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut bytes).expect("ОС не даёт случайные байты");
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .push(format!("{token}:{}", now + SESSION_TTL_SECS));
        token
    }

    /// Проверить токен из cookie и «продлить» его срок жизни.
    pub fn check_session(&self, token: &str) -> bool {
        let mut list = self.sessions.lock().expect("sessions lock poisoned");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // вычистить просроченные
        list.retain(|item| item.split_once(':').map(|(_, e)| e.parse::<u64>().unwrap_or(0) > now).unwrap_or(false));
        for item in list.iter_mut() {
            if let Some((t, _)) = item.split_once(':') {
                if t == token {
                    *item = format!("{token}:{}", now + SESSION_TTL_SECS);
                    return true;
                }
            }
        }
        false
    }

    pub fn revoke_session(&self, token: &str) {
        let mut list = self.sessions.lock().expect("sessions lock poisoned");
        list.retain(|item| item.split_once(':').map(|(t, _)| t != token).unwrap_or(true));
    }

    /// Санитизация исходного имени файла из multipart-загрузки.
    pub fn sanitize_name(raw: &str) -> String {
        // keep only the file-name part (strip any path components)
        let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
        let cleaned: String = base
            .chars()
            .filter(|c| !c.is_control())
            .map(|c| match c {
                '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
                _ => c,
            })
            .collect();
        let trimmed = cleaned.trim_matches(|c| c == '.' || c == ' ');
        if trimmed.is_empty() {
            "file".to_string()
        } else if trimmed.len() > 200 {
            format!("{}_{}", &trimmed[..64], &trimmed[trimmed.len() - 32..])
        } else {
            trimmed.to_string()
        }
    }

    /// Resolve a user-supplied file name inside the storage directory.
    /// Returns `None` if the name tries to escape the directory or is not a plain file.
    pub fn resolve_file(dir: &Path, name: &str) -> Option<PathBuf> {
        if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
            return None;
        }
        let path = dir.join(name);
        if path.is_file() {
            Some(path)
        } else {
            None
        }
    }
}
