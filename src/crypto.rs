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
}
