//! Path handling for untrusted input: repository paths, run artifacts.

use crate::error::{Error, Result};
use std::path::{Component, Path, PathBuf};

/// Join `rel` under `root`, refusing absolute paths, `..`, NUL bytes and
/// anything else that could escape `root`. Purely lexical: callers that write
/// must additionally ensure no directory on the way is a symlink
/// (see [`ensure_real_dir`]).
pub fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    if rel.contains('\0') {
        return Err(Error::Analysis(format!("refusing path containing NUL: {rel:?}")));
    }
    let p = Path::new(rel);
    let mut out = root.to_path_buf();
    for c in p.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::Analysis(format!("path escapes {}: {rel}", root.display())));
            }
        }
    }
    Ok(out)
}

/// A filename component derived from untrusted text (property ids, targets).
pub fn safe_file_name(s: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_len));
    let mut last_us = false;
    for ch in s.chars() {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-');
        if ok {
            out.push(ch);
            last_us = false;
        } else if !last_us {
            out.push('_');
            last_us = true;
        }
        if out.len() >= max_len {
            break;
        }
    }
    let trimmed = out.trim_start_matches(['.', '_']).to_owned();
    if trimmed.is_empty() { "unnamed".to_owned() } else { trimmed }
}

/// Repository-relative path with forward slashes.
pub fn to_repo_path(root: &Path, abs: &Path) -> String {
    let rel = abs.strip_prefix(root).unwrap_or(abs);
    rel.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Create `path` as a real directory, or verify an existing one is not a
/// symlink (a hostile repository could point `.proof-it` at `~/.ssh`).
pub fn ensure_real_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            Err(Error::Environment(format!("refusing to write: {} is not a regular directory (symlink?)", path.display())))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(path).map_err(|e| Error::io(path, e)),
        Err(e) => Err(Error::io(path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_escapes() {
        let root = Path::new("/r");
        assert!(safe_join(root, "../etc/passwd").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, "a/../../b").is_err());
        assert!(safe_join(root, "a\0b").is_err());
        assert_eq!(safe_join(root, "./a/b").ok(), Some(PathBuf::from("/r/a/b")));
    }

    #[test]
    fn file_names_are_sanitised() {
        assert_eq!(safe_file_name("../../etc/passwd", 80), "etc_passwd");
        assert_eq!(safe_file_name("AUTHZ-001::GET /x/:id", 80), "AUTHZ-001_GET_x_id");
        assert_eq!(safe_file_name("...", 80), "unnamed");
    }
}
