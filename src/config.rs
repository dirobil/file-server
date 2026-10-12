//! Конфигурация сервера: кроссплатформенный путь + атомарная запись в TOML/JSON.
//!
//! Файл хранится в «домашней директории приложения» — крейт `dirs`
//! подбирает правильное место под каждую ОС (см. `config_path()`), поэтому
//! один и тот же бинарник одинаково работает на Windows, Linux и macOS.
//!
//! Формат по умолчанию — **TOML** (человекочитаемый, с комментариями).
//! Крейт `toml` умеет и читать, и писать; дополнительно поддерживается
//! **JSON** (для машинного редактирования) — формат выбирается по расширению
//! файла и определяется автоматически при чтении по содержимому.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Версия схемы конфига — пригодится при миграциях.
pub const CONFIG_VERSION: u32 = 1;

/// Настройки админ-панели.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Пароль в виде PHC-хеша Argon2id (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`);
    /// сам пароль нигде не хранится.
    pub password_hash: String,
}

/// Настройки шифрования файлов на диске.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EncryptionConfig {
    /// Включено ли шифрование новых загружаемых файлов (AES-256-GCM).
    pub enabled: bool,
    /// Ключ в hex (64 символа). Пустой — ключ ещё не создавался.
    /// Сам ключ генерируется ОС; в открытом виде нигде, кроме этого файла (0600), не хранится.
    pub key_hex: String,
}

/// Настройки HTTPS (TLS) — нужны, чтобы браузер дал доступ к WebCrypto API
/// на адресе вида 192.168.0.16 (не localhost).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Поднимать ли дополнительный HTTPS-слушатель рядом с HTTP.
    pub enabled: bool,
    /// Адрес (IP или имя), для которого выпускается самоподписанный сертификат.
    pub addr: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self { enabled: false, addr: crate::tls::DEFAULT_TLS_ADDR.to_string() }
    }
}

/// Полная конфигурация сервера.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    /// Выбранная админом директория для хранения файлов (`None` — сервер не настроен).
    pub storage_dir: Option<PathBuf>,
    pub admin: AdminConfig,
    pub encryption: EncryptionConfig,
    pub tls: TlsConfig,
}

impl Config {
    /// Новый конфиг с версией схемы.
    pub fn with_storage(storage_dir: Option<PathBuf>) -> Self {
        Self {
            version: CONFIG_VERSION,
            storage_dir,
            admin: AdminConfig::default(),
            encryption: EncryptionConfig::default(),
            tls: TlsConfig::default(),
        }
    }

    /// Рабочий 32-байтный ключ, если включён и корректный hex задан.
    pub fn encryption_key(&self) -> Option<[u8; 32]> {
        if !self.encryption.enabled {
            return None;
        }
        crate::crypto::key_from_hex(&self.encryption.key_hex)
    }

    /// Есть ли уже установленный пароль администратора.
    pub fn has_admin_password(&self) -> bool {
        !self.admin.password_hash.is_empty()
    }

    /// Сохранить конфиг атомарно: во временный файл рядом, затем `rename`.
    /// Так конфиг не может «полукровиться» при падении процесса посреди записи.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("не удалось создать директорию {}: {e}", parent.display()))?;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("toml");
        let body = match ext {
            "json" => format!(
                "{}\n",
                serde_json::to_string_pretty(self).map_err(|e| e.to_string())?
            ),
            _ => render_toml(self)?,
        };

        let tmp = path.with_extension(format!("{}.tmp", ext));
        {
            let mut f =
                fs::File::create(&tmp).map_err(|e| format!("не удалось создать {}: {e}", tmp.display()))?;
            // На Unix выставим права 0600: в файле лежит хеш пароля.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
            }
            f.write_all(body.as_bytes())
                .map_err(|e| format!("ошибка записи {}: {e}", tmp.display()))?;
            f.sync_all().ok();
        }
        fs::rename(&tmp, path).map_err(|e| format!("не удалось заменить {}: {e}", path.display()))?;
        Ok(())
    }

    /// Прочитать конфиг. Если файла нет — `Ok(None)` (сервер ещё не настраивали).
    /// Формат определяется по содержимому: `{` — JSON, иначе TOML.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("не удалось прочитать {}: {e}", path.display())),
        };
        let cfg: Config = if text.trim_start().starts_with('{') {
            serde_json::from_str(&text).map_err(|e| format!("битый JSON в конфиге: {e}"))?
        } else {
            toml::from_str(&text).map_err(|e| format!("битый TOML в конфиге: {e}"))?
        };
        Ok(Some(cfg))
    }
}

/// Ручная сериализация в TOML: нам важно оставить комментарии прямо в файле конфига,
/// а генератор `toml::to_string` их не умеет. Экранирование строк делает
/// `toml_edit::Value::String` (без захода на сериализатор `toml::Value`,
/// который падал с «unsupported rust type»).
fn render_toml(cfg: &Config) -> Result<String, String> {
    fn quoted(s: &str) -> String {
        toml_edit::Value::from(s).to_string()
    }
    let mut out = String::new();
    out.push_str("# Конфигурация файлового сервера.\n");
    out.push_str("# Файл создаётся автоматически при первом сохранении настроек.\n\n");
    out.push_str(&format!("version = {}\n", cfg.version));
    match &cfg.storage_dir {
        Some(d) => out.push_str(&format!("storage_dir = {}\n", quoted(&d.display().to_string()))),
        None => out.push_str("# storage_dir не задан — обмен файлами выключен\n"),
    }
    out.push_str("\n[admin]\n");
    if cfg.admin.password_hash.is_empty() {
        out.push_str("password_hash = \"\" # пароль администратора ещё не установлен\n");
    } else {
        out.push_str(&format!(
            "password_hash = {}\n",
            quoted(&cfg.admin.password_hash)
        ));
    }
    out.push_str("\n[encryption]\n");
    out.push_str(&format!("enabled = {} # шифрование файлов на диске (AES-256-GCM)\n", cfg.encryption.enabled));
    if cfg.encryption.key_hex.is_empty() {
        out.push_str("key_hex = \"\" # ключ создаётся автоматически при включении шифрования\n");
    } else {
        out.push_str(&format!("key_hex = {}\n", quoted(&cfg.encryption.key_hex)));
    }
    out.push_str("\n[tls]\n");
    out.push_str(&format!("enabled = {} # HTTPS-слушатель (нужен для WebCrypto на IP-адресе)\n", cfg.tls.enabled));
    out.push_str(&format!("addr = {}\n", quoted(&cfg.tls.addr)));
    Ok(out)
}

/// Домашняя директория приложения — кроссплатформенно, через крейт `dirs`:
///   * Linux/macOS: `~/.config/file-server/` (или `$XDG_CONFIG_HOME`)
///   * Windows:     `%APPDATA%\file-server\`
pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("FILE_SERVER_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .map(|p| p.join("file-server"))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Путь к файлу конфига. По умолчанию — `config_dir()/file-server.toml`;
/// можно переопределить переменной окружения `FILE_SERVER_CONFIG`
/// (например, указать `file-server.json`, чтобы использовать формат JSON).
pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("FILE_SERVER_CONFIG") {
        return PathBuf::from(p);
    }
    config_dir().join("file-server.toml")
}
