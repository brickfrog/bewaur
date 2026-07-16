use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub repositories: usize,
    pub bytes: u64,
}

/// Returns the cache directory, creating it if needed.
pub fn cache_dir() -> PathBuf {
    let dir = dirs_or_default();
    std::fs::create_dir_all(&dir).ok();
    dir
}

/// Returns the git clone cache subdirectory.
pub fn git_cache_dir() -> PathBuf {
    let dir = cache_dir().join("git");
    std::fs::create_dir_all(&dir).ok();
    dir
}

/// Inspect the normal AUR Git cache without following symlinks.
pub fn git_cache_stats() -> Result<CacheStats, String> {
    cache_stats_at(&git_cache_dir())
}

/// Remove one validated package-base repository, or every repository when
/// `package_base` is `None`. Callers should require an explicit `--all` before
/// selecting the latter behavior.
pub fn clean_git_cache(package_base: Option<&str>) -> Result<usize, String> {
    clean_git_cache_at(&git_cache_dir(), package_base)
}

fn cache_stats_at(root: &Path) -> Result<CacheStats, String> {
    let mut repositories = 0usize;
    let mut bytes = 0u64;

    let entries = std::fs::read_dir(root)
        .map_err(|e| format!("failed to read cache {}: {e}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read cache entry: {e}"))?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|e| format!("failed to inspect {}: {e}", entry.path().display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            repositories += 1;
            bytes = bytes.saturating_add(directory_size(&entry.path())?);
        } else {
            bytes = bytes.saturating_add(metadata.len());
        }
    }

    Ok(CacheStats {
        repositories,
        bytes,
    })
}

fn directory_size(path: &Path) -> Result<u64, String> {
    let mut bytes = 0u64;
    let entries =
        std::fs::read_dir(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read cache entry: {e}"))?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|e| format!("failed to inspect {}: {e}", entry.path().display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            bytes = bytes.saturating_add(directory_size(&entry.path())?);
        } else {
            bytes = bytes.saturating_add(metadata.len());
        }
    }
    Ok(bytes)
}

fn clean_git_cache_at(root: &Path, package_base: Option<&str>) -> Result<usize, String> {
    std::fs::create_dir_all(root)
        .map_err(|e| format!("failed to create cache {}: {e}", root.display()))?;
    let root_metadata = std::fs::symlink_metadata(root)
        .map_err(|e| format!("failed to inspect cache {}: {e}", root.display()))?;
    if root_metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing to clean symlinked cache root: {}",
            root.display()
        ));
    }

    if let Some(package_base) = package_base {
        crate::shared::aur_git::validate_package_name(package_base)?;
        let target = root.join(package_base);
        let metadata = match std::fs::symlink_metadata(&target) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => {
                return Err(format!("failed to inspect {}: {error}", target.display()));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing to remove symlinked cache entry: {package_base}"
            ));
        }
        if !metadata.is_dir() {
            return Err(format!("cache entry is not a directory: {package_base}"));
        }

        let canonical_root = root
            .canonicalize()
            .map_err(|e| format!("failed to resolve cache root: {e}"))?;
        let canonical_target = target
            .canonicalize()
            .map_err(|e| format!("failed to resolve cache entry: {e}"))?;
        if canonical_target.parent() != Some(canonical_root.as_path()) {
            return Err(format!("cache entry escaped cache root: {package_base}"));
        }

        std::fs::remove_dir_all(&target)
            .map_err(|e| format!("failed to remove {}: {e}", target.display()))?;
        return Ok(1);
    }

    let mut removed = 0usize;
    let entries = std::fs::read_dir(root)
        .map_err(|e| format!("failed to read cache {}: {e}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read cache entry: {e}"))?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("failed to inspect {}: {e}", path.display()))?;
        if metadata.file_type().is_symlink() || metadata.is_file() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("failed to remove {}: {e}", path.display()))?;
        } else if metadata.is_dir() {
            std::fs::remove_dir_all(&path)
                .map_err(|e| format!("failed to remove {}: {e}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn dirs_or_default() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("bewaur")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache").join("bewaur")
    } else {
        PathBuf::from("/tmp/bewaur-cache")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_cache() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bewaur-cache-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn stats_count_repositories_and_bytes_without_following_symlinks() {
        let root = temp_cache();
        std::fs::create_dir(root.join("alpha")).unwrap();
        std::fs::write(root.join("alpha/data"), b"1234").unwrap();
        std::fs::create_dir(root.join("beta")).unwrap();
        std::fs::write(root.join("beta/data"), b"12").unwrap();

        let stats = cache_stats_at(&root).unwrap();
        assert_eq!(stats.repositories, 2);
        assert_eq!(stats.bytes, 6);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn package_clean_rejects_path_traversal_and_absolute_paths() {
        let root = temp_cache();
        let outside = root.parent().unwrap().join("bewaur-must-not-delete");
        std::fs::create_dir_all(&outside).unwrap();

        assert!(clean_git_cache_at(&root, Some("../../bewaur-must-not-delete")).is_err());
        assert!(clean_git_cache_at(&root, outside.to_str()).is_err());
        assert!(clean_git_cache_at(&root, Some(".")).is_err());
        assert!(outside.exists());

        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn package_clean_removes_only_selected_repository() {
        let root = temp_cache();
        std::fs::create_dir(root.join("alpha")).unwrap();
        std::fs::create_dir(root.join("beta")).unwrap();

        assert_eq!(clean_git_cache_at(&root, Some("alpha")).unwrap(), 1);
        assert!(!root.join("alpha").exists());
        assert!(root.join("beta").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn clean_all_requires_caller_to_choose_none_explicitly() {
        let root = temp_cache();
        std::fs::create_dir(root.join("alpha")).unwrap();
        std::fs::create_dir(root.join("beta")).unwrap();

        assert_eq!(clean_git_cache_at(&root, None).unwrap(), 2);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn package_clean_refuses_symlinked_entry() {
        use std::os::unix::fs::symlink;

        let root = temp_cache();
        let outside = temp_cache();
        symlink(&outside, root.join("alpha")).unwrap();

        assert!(clean_git_cache_at(&root, Some("alpha")).is_err());
        assert!(outside.exists());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn package_clean_refuses_dangling_symlinked_entry() {
        use std::os::unix::fs::symlink;

        let root = temp_cache();
        symlink(root.join("missing"), root.join("alpha")).unwrap();

        assert!(clean_git_cache_at(&root, Some("alpha")).is_err());
        assert!(std::fs::symlink_metadata(root.join("alpha")).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
