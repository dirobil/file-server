//! Авторизация администратора: хеширование пароля, cookie-сессии, middleware.
//!
//! Хеширование паролей — аргон2 (RustCrypto `argon2`, memory-hard KDF),
//! сравнение хешей — через встроенную constant-time проверку `PasswordHash::verify`
//! (крейт `subtle` в явном виде не нужен).

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRngCore;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::{header, request::Parts, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};

use crate::state::AppState;

/// Имя cookie админ-сессии.
pub const ADMIN_COOKIE: &str = "fs_admin";

/// Параметры Argon2id: компромисс между стойкостью и задержкой входа (~0.5 c на ядро).
fn hasher() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19456, 2, 1, None).expect("корректные параметры Argon2"),
    )
}

/// Хеш пароля в стандартном PHC-формате: `$argon2id$v=19$m=...,t=...,p=...$salt$hash`.
pub fn hash_password(password: &str) -> String {
    // SaltString::generate требует rand_core 0.6 (уже не экспортируется напрямую),
    // поэтому соль формируем из байт системного CSPRNG вручную (A–z, 0–9).
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("ОС не даёт случайные байты");
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let salt_b64: String = bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    let salt = SaltString::from_b64(&salt_b64).expect("соль собрана из допустимых символов");
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2: ошибка хеширования")
        .to_string()
}

/// Проверка пароля против сохранённого PHC-хеша (constant-time внутри `verify`).
pub fn verify_password(password: &str, stored: &str) -> bool {
    match PasswordHash::new(stored) {
        Ok(parsed) => hasher()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Значение Set-Cookie для админ-сессии. В production (`FS_HTTPS=1`) добавится `Secure`.
pub fn session_cookie(token: &str) -> String {
    let secure = if std::env::var("FS_HTTPS").is_ok() {
        "; Secure"
    } else {
        ""
    };
    format!("{ADMIN_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax{secure}; Max-Age=28800")
}

/// Cookie «выход»: пустое значение с мгновенным истечением.
pub fn clear_cookie() -> String {
    format!("{ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Извлечь значение cookie `fs_admin` из заголовка запроса.
pub fn extract_cookie(headers: &header::HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(ADMIN_COOKIE) {
            let value = rest.strip_prefix('=')?.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Middleware защиты админ-зон: без валидной сессии — страница «нет доступа» (403).
pub async fn require_admin(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let token = extract_cookie(req.headers());
    let authorized = token
        .as_deref()
        .map(|t| state.check_session(t))
        .unwrap_or(false);
    if !authorized {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            Html(state.templates.denied),
        )
            .into_response();
    }
    next.run(req).await
}

/// Извлечённый токен админ-сессии из cookie (для обработчиков login/logout).
pub struct AdminCookie(pub Option<String>);

impl<S> FromRequestParts<S> for AdminCookie
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(AdminCookie(extract_cookie(&parts.headers)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let stored = hash_password("secret-123");
        assert!(stored.starts_with("$argon2id$"));
        assert!(verify_password("secret-123", &stored));
        assert!(!verify_password("secret-124", &stored));
        assert!(!verify_password("", &stored));
        assert!(!verify_password("anything", "not-a-valid-hash"));
    }

    #[test]
    fn different_salts_different_hashes() {
        assert_ne!(hash_password("same"), hash_password("same"));
    }
}
