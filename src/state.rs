use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// Shared application state: the (optional) storage directory configured by admin.
/// Cheap to clone because the directory lives behind an `Arc`.
#[derive(Clone, Default)]
pub struct AppState {
    pub storage: std::sync::Arc<RwLock<Option<PathBuf>>>,
}

impl AppState {
    /// Currently configured storage directory, if any.
    pub fn storage_dir(&self) -> Option<PathBuf> {
        self.storage.read().expect("state lock poisoned").clone()
    }

    /// Set (or clear with `None`) the storage directory.
    pub fn set_storage_dir(&self, dir: Option<PathBuf>) {
        *self.storage.write().expect("state lock poisoned") = dir;
    }

    /// Sanitize an original file name coming from a multipart upload.
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
