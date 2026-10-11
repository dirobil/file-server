//! Template loading helpers.
//!
//! All HTML markup now lives in the `static/` directory as plain files:
//!   - static/not_configured.html — заглушка «сервер не настроен»
//!   - static/main_page.html      — главная страница (загрузка + список файлов)
//!   - static/admin.html          — админская страница (выбор директории)
//!   - static/style.css           — общие стили (подключаются по ссылке /style.css)
//!
//! Dynamic parts are inserted by replacing `{{placeholder}}` markers.
//!
//! The files are embedded into the binary at compile time via `include_str!`,
//! so the server works from any working directory and ships as a single file.
//! The CSS is embedded the same way and served at `/style.css` from memory.

use std::collections::HashMap;

/// Return the compiled-in contents of a template from `static/`.
pub fn load_template(name: &str) -> &'static str {
    match name {
        "not_configured.html" => include_str!("../static/not_configured.html"),
        "main_page.html" => include_str!("../static/main_page.html"),
        "admin.html" => include_str!("../static/admin.html"),
        "login.html" => include_str!("../static/login.html"),
        "denied.html" => include_str!("../static/denied.html"),
        _ => panic!("unknown template: {name}"),
    }
}

/// The stylesheet, also embedded into the binary (served at `/style.css`).
pub const STYLE_CSS: &str = include_str!("../static/style.css");

/// Replace every `{{key}}` marker with its value.
/// Values must already be HTML-escaped by the caller when needed.
pub fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let map: HashMap<&str, &str> = vars.iter().copied().collect();
    let mut out = String::with_capacity(template.len() + 1024);
    let mut rest = template;
    while let Some(pos) = rest.find("{{") {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        match rest.find("}}") {
            Some(end) => {
                let key = &rest[2..end];
                out.push_str(map.get(key).copied().unwrap_or(""));
                rest = &rest[end + 2..];
            }
            None => {
                out.push_str(rest);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// Minimal percent-encoding for file names in URLs (keeps unreserved chars).
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
