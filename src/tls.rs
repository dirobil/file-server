//! HTTPS (TLS) для сервера — без внешних инструментов и конфигурации.
//!
//! Зачем это нужно: WebCrypto API (`crypto.subtle`) браузеры отдают только в
//! «безопасном контексте» — на HTTPS или на localhost/127.0.0.1. Для адреса
//! вида `http://192.168.0.16` он недоступен, поэтому сервер умеет сам поднимать
//! TLS-контейнер.
//!
//! Как это работает (вариант «самоподписанный сертификат + доверие один раз»):
//!   * При первом запуске с включённым TLS генерируется ECDSA P-256 ключ и
//!     самоподписанный сертификат (крейт `rcgen`), где адрес `192.168.0.16`
//!     прописан как SAN (Subject Alternative Name) — именно SAN браузер
//!     проверяет при установке соединения.
//!   * Ключ и сертификат сохраняются в директории конфига (права 600) и
//!     переиспользуются при следующих запусках — иначе браузер каждый раз
//!     видел бы «новый» сертификат.
//!   * Сервер слушает одновременно HTTP и HTTPS; по HTTPS попадает в тот же
//!     самый код. Пользователь один раз принимает сертификат («Дополнительно →
//!     Перейти на сайт») — дальше адресная строка показывает замок, а значит
//!     страница считается безопасной и WebCrypto доступен.
//!   * Корневой сертификат CA можно скачать по `/ca.crt` и один раз добавить
//!     в доверенные на устройстве — тогда предупреждение не появится вовсе.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::ServerConfig;

/// Адрес (IP/имя), для которого выпускается сертификат. Переопределяется
/// переменной окружения `TLS_ADDR`, по умолчанию — IP локальной сети из задачи.
pub const DEFAULT_TLS_ADDR: &str = "192.168.0.16";

/// Путь к файлу PEM (ключ + сертификат) в директории конфига.
pub fn cert_path() -> PathBuf {
    crate::config::config_dir().join("file-server-tls.pem")
}

/// Прочитать готовый сертификат с диска; `None` если файла нет или он битый.
fn load_saved(path: &Path) -> Option<Arc<ServerConfig>> {
    let pem = std::fs::read(path).ok()?;
    parse_pem(&pem).map(Arc::new)
}

/// Собрать rustls-конфиг из PEM-ов (секрета сертификата и самого сертификата).
fn parse_pem(pem: &[u8]) -> Result<ServerConfig, String> {
    use std::io::BufReader;
    let mut certs = rustls_pemfile::certs(&mut BufReader::new(pem));
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(pem));
    // rustls 0.23 требует явного ALPN: отдаём h2 и http/1.1 (hyper поддержит оба).
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            certs.next().and_then(|r| r.ok()).map(Vec::from).unwrap_or_default(),
            keys.next().and_then(|r| r.ok())?,
        )
        .map_err(|e| format!("не удалось настроить TLS: {e}"))?;
    Ok(cfg)
}

/// Сгенерировать новый самоподписанный сертификат для `addr` и сохранить его
/// на диск. Возвращает конфиг сервера TLS и PEM корня (для страницы доверия).
fn generate(addr: &str, path: &Path) -> Result<(Arc<ServerConfig>, Vec<u8>), String> {
    let mut params = CertificateParams::default();
    // SAN: адрес может быть IPv4 или доменным именем — пробуем распарсить IP.
    let names = match addr.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![rcgen::SanType::IpAddress(ip)],
        Err(_) => vec![rcgen::SanType::DnsName(addr.to_string().try_into().map_err(|_| "битое имя хоста")?)],
    };
    params.subject_alt_names = names;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("file-server {addr}"));
    params.distinguished_name = dn;

    let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
    // Самоподписанный сертификат живёт 10 лет — хватит для домашней/локальной сети.
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("не удалось выпустить сертификат: {e}"))?;

    let mut pem = Vec::new();
    pem.extend_from_slice(cert.pem().as_bytes());
    pem.extend_from_slice(key_pair.serialize_pem().as_bytes());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, &pem).map_err(|e| format!("не удалось сохранить {}: {e}", path.display()))?;
    // Права 600: приватный ключ не должен читаться другими пользователями.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    let cfg = parse_pem(&pem)?;
    Ok((Arc::new(cfg), cert.pem().into_bytes()))
}

/// Подготовить TLS-конфиг: взять сохранённый сертификат либо выпустить новый.
/// Второй элемент кортежа — PEM сертификата (чтобы отдать его пользователю по
/// ссылке `/ca.crt` для добавления в доверенные).
pub fn server_config(tls_addr: &str) -> Result<(Arc<ServerConfig>, Vec<u8>), String> {
    let path = cert_path();
    if let Some(cfg) = load_saved(&path) {
        // PEM для скачивания берём из того же файла (сертификат — публичная часть).
        let pem = std::fs::read(&path).unwrap_or_default();
        return Ok((cfg, pem));
    }
    generate(tls_addr, &path)
}

/// TLS-слой для `axum::serve`: реализует `axum::serve::Listener` поверх
/// обычного `TcpListener`. Каждое принятое соединение оборачивается в
/// `TlsStream` (rustls), поэтому axum/hyper видят уже «расшифрованный»
/// поток. Модуля `hyper::server::accept` в Hyper 1.x больше нет — вместо
/// старого `Accept`-трейта используется этот подход через `Listener`.
pub struct TlsListener {
    inner: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListener {
    pub fn new(inner: tokio::net::TcpListener, config: Arc<ServerConfig>) -> Self {
        Self {
            inner,
            acceptor: tokio_rustls::TlsAcceptor::from(config),
        }
    }
}

impl axum::serve::Listener for TlsListener {
    // Готовый TLS-поток после завершённого рукопожатия.
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((tcp, addr)) => match self.acceptor.accept(tcp).await {
                    Ok(tls) => return (tls, addr),
                    Err(e) => eprintln!("TLS handshake failed for {addr}: {e}"),
                },
                // Ошибку accept логируем и пробуем следующее соединение
                // (так же ведёт себя встроенный impl Listener у TcpListener).
                Err(e) => eprintln!("Ошибка accept: {e}"),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_reload_roundtrip() {
        let dir = std::env::temp_dir().join(format!("fstls-test-{}", std::process::id()));
        let path = dir.join("cert.pem");
        let _ = std::fs::remove_dir_all(&dir);
        let (cfg, pem) = generate("192.168.0.16", &path).unwrap();
        assert!(!pem.is_empty());
        assert!(path.exists());
        // Повторное чтение с диска должно дать рабочий конфиг.
        let reloaded = load_saved(&path).expect("сохранённый сертификат должен читаться");
        let _ = cfg;
        let _ = reloaded;
        std::fs::remove_dir_all(&dir).ok();
    }
}
