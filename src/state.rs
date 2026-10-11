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
}

impl AppState {
    pub fn new(templates: Templates, config_path: PathBuf, config: Config) -> Self {
        Self {
            storage: std::sync::Arc::new(RwLock::new(config.storage_dir.clone())),
            templates,
            config_path: std::sync::Arc::new(config_path),
            config: std::sync::Arc::new(RwLock::new(config)),
            sessions: std::sync::Arc::new(Mutex::new(Vec::new())),
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
