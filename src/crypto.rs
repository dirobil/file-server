//! Прозрачное шифрование файлов «на диске»: AES-256-GCM (аутентифицированное шифрование).
//!
//! Как это работает и почему пользователю «просто»:
//!   * Зашифрованный файл хранится в директории сервера рядом с метаданными `<имя>.meta.json`
//!     (исходное имя, MIME-тип, размер оригинала) — без них мы не смогли бы вернуть
//!     браузеру нормальное имя и тип при скачивании.
//!   * При скачивании сервер **сам расшифровывает** поток на лету: пользователь жмёт
//!     «Скачать» и получает обычный, читаемый файл. Никаких паролей и инструментов
//!     на стороне пользователя не нужно.
//!   * Ключ — 32 случайных байта, генерируются при первом включении шифрования и
//!     хранятся в конфиге сервера (файл конфига имеет права 0600).
//!   * Формат файла на диске: `magic(4) "FSenc1" | nonce(12) | ciphertext+tag(GCM)`.
//!     GCM одновременно шифрует и проверяет целостность: битый/подменённый файл
//!     не расшифруется (ошибка аутентификации), а не выдаст мусор.
//!
//! Ограничение: шифрование потоковое (по чанкам ~64 КБ), поэтому каждый чанк
//! шифруется отдельным nonce-счётчиком в рамках одного ключа — стандартная схема
//! для больших файлов; общий тег не используется, целостность каждого чанка
//! обеспечивает GCM-тег этого чанка.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// P-256 для ECDH — используется только при «сквозном» шифровании в браузере:
// сервер помогает доставить симметричный ключ, но сам его не видит.
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};

/// Магическая сигнатура зашифованных файлов (первые 6 байт на диске).
pub const MAGIC: &[u8; 6] = b"FSenc1";
/// Размер nonce AES-GCM.
const NONCE_LEN: usize = 12;

/// Метаданные зашифрованного файла — лежат в `<storage>/<имя>.meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    /// Оригинальное имя файла (такое же, как показываем пользователю).
    pub name: String,
    /// MIME-тип из multipart-загрузки (или octet-stream).
    pub content_type: String,
    /// Размер исходного (нешифрованного) файла в байтах.
    pub size: u64,
}

/// Сгенерировать новый ключ — 32 байта от OS CSPRNG.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut key)
        .expect("ОС не даёт случайные байты");
    key
}

/// Ключ в hex-представлении (для конфига).
pub fn key_to_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Разобрать ключ из hex; `None` если строка битая.
pub fn key_from_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(key)
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("ключ всегда 32 байта")
}

/// Зашифровать один чанк. `seq` — номер чанка; nonce детерминированный
/// (случайная база 8 байт + счётчик 4 байта), чтобы при дешифровке уметь
/// восстановить его по позиции в потоке.
pub fn encrypt_chunk(key: &[u8; 32], base: &[u8; 8], seq: u32, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..8].copy_from_slice(base);
    nonce[8..].copy_from_slice(&seq.to_le_bytes());
    cipher(key)
        .encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|_| "ошибка шифрования".to_string())
}

/// Расшифровать чанк по его номеру в потоке.
pub fn decrypt_chunk(key: &[u8; 32], base: &[u8; 8], seq: u32, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..8].copy_from_slice(base);
    nonce[8..].copy_from_slice(&seq.to_le_bytes());
    cipher(key)
        .decrypt(Nonce::from_slice(&nonce), data)
        .map_err(|_| "файл повреждён или ключ не подходит".to_string())
}

/// Полный путь к файлу метаданных для зашифрованного файла `name`.
pub fn meta_path(dir: &PathBuf, name: &str) -> PathBuf {
    dir.join(format!("{name}.meta.json"))
}

/// Есть ли у файла метаданные (т.е. загружен ли он уже по новой схеме).
pub fn has_meta(dir: &PathBuf, name: &str) -> bool {
    meta_path(dir, name).is_file()
}

// ==================== «Сквозное» шифрование в браузере (WebCrypto) ====================
//
// Когда пользователь включает тумблер «Шифрование в браузере», файл шифруется
// WebCrypto ещё ДО отправки (AES-GCM 256), а ключ файла передается только
// получателю через ECDH P-256 + HKDF (см. JS в main_page.html). Сервер при этом:
//   * не знает ключей и НЕ может расшифровать такой файл;
//   * хранит зашифрованный blob как есть + JSON-«конверт» `<имя>.ekey.json`
//     с публичными параметрами, нужными для скачивания (iv, список получателей);
//   * на `/ecdh_pubkey` отдаёт свой временный публичный ECDH-ключ, чтобы
//     браузер мог добавить сервера в список получателей — иначе файл нельзя
//     будет скачать после закрытия вкладки.
// Файлы, зашифрованные в браузере, помечаются magic `FSweb1` и НЕ переименовываются
// сервером (имя лежит внутри конверта) — поэтому ссылка на них всегда живая.

/// Магическая сигнатура файлов, зашифрованных на стороне браузера.
pub const MAGIC_WEB: &[u8; 6] = b"FSweb1";
/// Расширение файла-конверта с параметрами сквозного шифрования.
pub const EKEY_EXT: &str = ".ekey.json";

/// Параметры одного ECDH-получателя симметричного ключа файла.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    /// Имя кривой (запас на будущее), сейчас всегда "P-256".
    pub curve: String,
    /// Публичный ключ получателя, uncompressed SEC1 (65 байт), base64url.
    pub pubkey: String,
    /// Случайная соль HKDF (16 байт), base64url.
    pub salt: String,
    /// AES-GCM iv для обёртки ключа (12 байт), base64url.
    pub iv: String,
    /// Зашифрованный ключ файла + GCM-тег, base64url.
    pub wrapped_key: String,
}

/// Конверт сквозного шифрования — `<имя>.ekey.json` рядом с файлом.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebMeta {
    /// Оригинальное имя файла (сервер его не менял — но всё равно храним).
    pub name: String,
    pub content_type: String,
    /// Размер исходного файла.
    pub size: u64,
    /// AES-GCM iv для чанков основного потока (первый чанк), base64url.
    /// Последующие чанки сдвигают счётчик (big-endian инкремент последних 8 байт).
    pub iv: String,
    pub recipients: Vec<Recipient>,
}

pub fn ekey_path(dir: &PathBuf, name: &str) -> PathBuf {
    dir.join(format!("{name}{EKEY_EXT}"))
}

pub fn has_ekey(dir: &PathBuf, name: &str) -> bool {
    ekey_path(dir, name).is_file()
}

/// Баз64url без паддингов (то же кодирование, что `b64e` в JS на странице).
pub fn b64url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Разобрать баз64url; `None` если строка битая.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

/// Проверить, что указанный публичный ключ валиден (точка на кривой P-256),
/// и вернуть его SEC1-представление. Защита от мусора/битых данных в конверте.
pub fn validate_ecdh_public(sec1: &[u8]) -> Option<Vec<u8>> {
    let point = EncodedPoint::from_bytes(sec1).ok()?;
    let pk = PublicKey::from_encoded_point(&point);
    if pk.is_some().into() {
        Some(pk.unwrap().to_encoded_point(false).as_bytes().to_vec())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_roundtrip() {
        let key = generate_key();
        let base = [7u8; 8];
        let data = "привет, это секретный файл!".as_bytes().to_vec();
        let enc = encrypt_chunk(&key, &base, 0, &data).unwrap();
        assert_ne!(enc, data);
        let dec = decrypt_chunk(&key, &base, 0, &enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn wrong_key_fails_auth() {
        let key = generate_key();
        let other = generate_key();
        let base = [1u8; 8];
        let enc = encrypt_chunk(&key, &base, 3, b"data").unwrap();
        assert!(decrypt_chunk(&other, &base, 3, &enc).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let key = generate_key();
        let base = [2u8; 8];
        let mut enc = encrypt_chunk(&key, &base, 0, b"important").unwrap();
        enc[5] ^= 0xFF;
        assert!(decrypt_chunk(&key, &base, 0, &enc).is_err());
    }

    #[test]
    fn key_hex_roundtrip() {
        let key = generate_key();
        let hex = key_to_hex(&key);
        assert_eq!(hex.len(), 64);
        assert_eq!(key_from_hex(&hex).unwrap(), key);
        assert!(key_from_hex("not-hex").is_none());
        assert!(key_from_hex("ab").is_none());
    }

    #[test]
    fn b64url_roundtrip_matches_webcrypto_style() {
        let data = [0u8, 1, 250, 255, 42];
        let enc = b64url_encode(&data);
        assert!(!enc.contains('='));
        assert!(!enc.contains('+'));
        assert!(!enc.contains('/'));
        assert_eq!(b64url_decode(&enc).unwrap(), data.to_vec());
        assert!(b64url_decode("!!!bad!!!").is_none());
    }

    #[test]
    fn ecdh_public_validation() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::{PublicKey, SecretKey};
        let sk = SecretKey::random(&mut rand::rngs::OsRng);
        let pk = PublicKey::from(sk.as_affine());
        let sec1 = pk.to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(sec1.len(), 65);
        assert_eq!(validate_ecdh_public(&sec1).unwrap(), sec1);
        // мусор — не ключ
        assert!(validate_ecdh_public(&[0u8; 33]).is_none());
        assert!(validate_ecdh_public(&sec1[..10]).is_none());
    }
}
