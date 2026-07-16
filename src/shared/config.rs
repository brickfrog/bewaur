use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const CONFIG_SCHEMA_VERSION: u32 = 1;
const APPROVAL_DIGEST_PREFIX: &str = "sha256:v1:p1:";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub thresholds: ThresholdConfig,
    #[serde(default)]
    pub permanent_allow: PermanentAllowConfig,
    #[serde(default)]
    pub approvals: ApprovalConfig,
    #[serde(default)]
    pub ignored: IgnoredConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            thresholds: ThresholdConfig::default(),
            permanent_allow: PermanentAllowConfig::default(),
            approvals: ApprovalConfig::default(),
            ignored: IgnoredConfig::default(),
        }
    }
}

fn default_schema_version() -> u32 {
    CONFIG_SCHEMA_VERSION
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdConfig {
    #[serde(default = "default_block_at")]
    pub block_at: String,
    #[serde(default = "default_warn_at")]
    pub warn_at: String,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            block_at: default_block_at(),
            warn_at: default_warn_at(),
        }
    }
}

fn default_block_at() -> String {
    "critical".to_string()
}

fn default_warn_at() -> String {
    "medium".to_string()
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PermanentAllowConfig {
    #[serde(default)]
    pub packages: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    #[serde(default)]
    pub trees: Vec<TreeApproval>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TreeApproval {
    pub package_base: String,
    pub digest: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IgnoredConfig {
    #[serde(default)]
    pub signals: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
}

/// Load config from ~/.config/bewaur/config.toml, falling back to defaults.
pub fn load_config() -> Config {
    let path = config_path();
    if !path.is_absolute() {
        return Config::default();
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// Load config without hiding malformed or unreadable state.
///
/// Missing config still means defaults, but security gates use this variant so
/// an existing config that cannot be interpreted blocks the build instead of
/// silently changing approval or ignored-signal behavior.
pub fn load_config_strict() -> Result<Config, String> {
    let path = config_path();
    if !path.is_absolute() {
        return Err(format!(
            "Config path must be absolute; refusing {}",
            path.display()
        ));
    }
    load_config_strict_from_path(&path)
}

fn load_config_strict_from_path(path: &Path) -> Result<Config, String> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            if toml::from_str::<toml::Value>(&content)
                .ok()
                .and_then(|value| value.get("whitelist").cloned())
                .is_some()
            {
                return Err(format!(
                    "Legacy [whitelist] in {} is no longer accepted; review each entry and use 'bewaur allow <package-base> --forever', or remove the section",
                    path.display()
                ));
            }
            let config: Config = toml::from_str(&content)
                .map_err(|error| format!("Failed to parse config {}: {error}", path.display()))?;
            validate_config(&config)
                .map_err(|error| format!("Invalid config {}: {error}", path.display()))?;
            Ok(config)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(error) => Err(format!("Failed to read config {}: {error}", path.display())),
    }
}

fn save_config_to_path(config: &Config, path: &Path) -> Result<(), String> {
    validate_config(config)?;
    let parent = prepare_config_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "Refusing to replace symlinked config: {}",
                path.display()
            ));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(format!("Config is not a regular file: {}", path.display()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Failed to inspect config {}: {error}",
                path.display()
            ));
        }
    }

    let toml_str =
        toml::to_string_pretty(config).map_err(|e| format!("Failed to serialize config: {e}"))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("Config path is not valid UTF-8: {}", path.display()))?;
    let mut temporary = None;
    for attempt in 0..100u32 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("Failed to create temporary config: {error}")),
        }
    }
    let (temporary_path, mut file) =
        temporary.ok_or_else(|| "Failed to allocate a unique temporary config path".to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&temporary_path);
            return Err(format!("Failed to secure temporary config: {error}"));
        }
    }

    let result = (|| {
        file.write_all(toml_str.as_bytes())
            .map_err(|error| format!("Failed to write temporary config: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Failed to sync temporary config: {error}"))?;
        drop(file);
        fs::rename(&temporary_path, path)
            .map_err(|error| format!("Failed to atomically replace config: {error}"))?;
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("Failed to sync config directory: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn prepare_config_parent(path: &Path) -> Result<&Path, String> {
    if !path.is_absolute() {
        return Err(format!(
            "Config path must be absolute; refusing {}",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("Config path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "Failed to create config directory {}: {error}",
            parent.display()
        )
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        format!(
            "Failed to inspect config directory {}: {error}",
            parent.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "Config directory is not a real directory: {}",
            parent.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "Failed to secure config directory {}: {error}",
                parent.display()
            )
        })?;
    }
    Ok(parent)
}

fn update_config(mutation: impl FnOnce(&mut Config) -> Result<(), String>) -> Result<(), String> {
    let path = config_path();
    update_config_at_path(&path, mutation)
}

fn update_config_at_path(
    path: &Path,
    mutation: impl FnOnce(&mut Config) -> Result<(), String>,
) -> Result<(), String> {
    let parent = prepare_config_parent(path)?;
    let lock_path = parent.join(".config.toml.lock");
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(format!(
                "Config lock is not a regular file: {}",
                lock_path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Failed to inspect config lock {}: {error}",
                lock_path.display()
            ));
        }
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| format!("Failed to open config lock: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        lock.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Failed to secure config lock: {error}"))?;
    }
    lock.lock_exclusive()
        .map_err(|error| format!("Failed to lock config: {error}"))?;

    let result = (|| {
        let mut config = load_config_strict_from_path(path)?;
        mutation(&mut config)?;
        save_config_to_path(&config, path)
    })();
    let unlock_result = lock
        .unlock()
        .map_err(|error| format!("Failed to unlock config: {error}"));
    match (result, unlock_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Add an explicit name-wide, permanent bypass and persist it.
pub fn add_to_permanent_allow(package: &str) -> Result<(), String> {
    crate::shared::aur_git::validate_package_name(package)?;
    update_config(|config| {
        if !config
            .permanent_allow
            .packages
            .contains(&package.to_string())
        {
            config.permanent_allow.packages.push(package.to_string());
            config.permanent_allow.packages.sort();
        }
        Ok(())
    })
}

/// Store one exact-tree approval per package base, replacing an older digest.
pub fn approve_tree(package_base: &str, digest: &str) -> Result<(), String> {
    crate::shared::aur_git::validate_package_name(package_base)?;
    validate_digest(digest)?;
    update_config(|config| {
        config
            .approvals
            .trees
            .retain(|approval| approval.package_base != package_base);
        config.approvals.trees.push(TreeApproval {
            package_base: package_base.to_string(),
            digest: digest.to_string(),
        });
        config
            .approvals
            .trees
            .sort_by(|left, right| left.package_base.cmp(&right.package_base));
        Ok(())
    })
}

/// Remove an exact-tree approval. Returns whether an entry existed.
pub fn revoke_tree_approval(package_base: &str) -> Result<bool, String> {
    crate::shared::aur_git::validate_package_name(package_base)?;
    let mut removed = false;
    update_config(|config| {
        let before = config.approvals.trees.len();
        config
            .approvals
            .trees
            .retain(|approval| approval.package_base != package_base);
        removed = config.approvals.trees.len() != before;
        Ok(())
    })?;
    Ok(removed)
}

/// Remove a permanent name-wide allowance. Returns whether one existed.
pub fn revoke_permanent_allow(package_base: &str) -> Result<bool, String> {
    crate::shared::aur_git::validate_package_name(package_base)?;
    let mut removed = false;
    update_config(|config| {
        let before = config.permanent_allow.packages.len();
        config
            .permanent_allow
            .packages
            .retain(|candidate| candidate != package_base);
        removed = config.permanent_allow.packages.len() != before;
        Ok(())
    })?;
    Ok(removed)
}

/// Atomically remove both authorization classes for one package base.
pub fn revoke_all_approvals(package_base: &str) -> Result<(bool, bool), String> {
    crate::shared::aur_git::validate_package_name(package_base)?;
    let mut removed_tree = false;
    let mut removed_permanent = false;
    update_config(|config| {
        let tree_before = config.approvals.trees.len();
        config
            .approvals
            .trees
            .retain(|approval| approval.package_base != package_base);
        removed_tree = config.approvals.trees.len() != tree_before;

        let permanent_before = config.permanent_allow.packages.len();
        config
            .permanent_allow
            .packages
            .retain(|candidate| candidate != package_base);
        removed_permanent = config.permanent_allow.packages.len() != permanent_before;
        Ok(())
    })?;
    Ok((removed_tree, removed_permanent))
}

/// Check if a package has an explicit permanent bypass.
#[allow(dead_code)] // Used by bewaur-hook binary
pub fn is_permanently_allowed_in(config: &Config, package: &str) -> bool {
    config
        .permanent_allow
        .packages
        .iter()
        .any(|candidate| candidate == package)
}

/// Return the sole stored exact-tree digest for a package base, if present.
pub fn approved_tree_digest<'a>(config: &'a Config, package_base: &str) -> Option<&'a str> {
    config
        .approvals
        .trees
        .iter()
        .find(|approval| approval.package_base == package_base)
        .map(|approval| approval.digest.as_str())
}

/// Add a signal ID to the ignored list and persist to disk.
pub fn add_to_ignored(signal_id: &str) -> Result<(), String> {
    update_config(|config| {
        if !config.ignored.signals.contains(&signal_id.to_string()) {
            config.ignored.signals.push(signal_id.to_string());
            config.ignored.signals.sort();
        }
        Ok(())
    })
}

/// Remove a signal ID from the ignored list and persist to disk.
pub fn remove_from_ignored(signal_id: &str) -> Result<(), String> {
    update_config(|config| {
        config.ignored.signals.retain(|signal| signal != signal_id);
        Ok(())
    })
}

/// Check if a signal should be ignored (by individual ID or by category).
/// Ignoring "SA-FOO" also suppresses "IS-SA-FOO".
#[allow(dead_code)] // Used by coordinator and bewaur-hook
pub fn is_signal_ignored(
    config: &Config,
    signal_id: &str,
    signal_category: &crate::shared::scoring::SignalCategory,
) -> bool {
    // Check category-level ignore
    if !config.ignored.categories.is_empty() {
        let cat_str = format!("{:?}", signal_category);
        if config
            .ignored
            .categories
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&cat_str))
        {
            return true;
        }
    }

    if config.ignored.signals.is_empty() {
        return false;
    }
    // Exact match
    if config.ignored.signals.iter().any(|s| s == signal_id) {
        return true;
    }
    // IS-prefixed variant: if "SA-FOO" is ignored, "IS-SA-FOO" is also ignored
    if let Some(base) = signal_id.strip_prefix("IS-") {
        return config.ignored.signals.iter().any(|s| s == base);
    }
    false
}

/// Add a category to the ignored list and persist to disk.
pub fn add_category_to_ignored(category: &str) -> Result<(), String> {
    update_config(|config| {
        if !config
            .ignored
            .categories
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(category))
        {
            config.ignored.categories.push(category.to_string());
            config.ignored.categories.sort();
        }
        Ok(())
    })
}

/// Remove a category from the ignored list and persist to disk.
pub fn remove_category_from_ignored(category: &str) -> Result<(), String> {
    update_config(|config| {
        config
            .ignored
            .categories
            .retain(|candidate| !candidate.eq_ignore_ascii_case(category));
        Ok(())
    })
}

fn validate_config(config: &Config) -> Result<(), String> {
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema_version {}; expected {CONFIG_SCHEMA_VERSION}",
            config.schema_version
        ));
    }

    for package in &config.permanent_allow.packages {
        crate::shared::aur_git::validate_package_name(package)
            .map_err(|error| format!("invalid permanent package {package:?}: {error}"))?;
    }

    let mut seen = HashSet::new();
    for approval in &config.approvals.trees {
        crate::shared::aur_git::validate_package_name(&approval.package_base).map_err(|error| {
            format!(
                "invalid approved package base {:?}: {error}",
                approval.package_base
            )
        })?;
        validate_digest(&approval.digest)?;
        if !seen.insert(&approval.package_base) {
            return Err(format!(
                "multiple exact-tree approvals exist for package base {:?}",
                approval.package_base
            ));
        }
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), String> {
    let Some(hex) = digest.strip_prefix(APPROVAL_DIGEST_PREFIX) else {
        return Err(format!(
            "approval digest must start with {APPROVAL_DIGEST_PREFIX}"
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("approval digest must contain 64 lowercase hexadecimal characters".to_string());
    }
    Ok(())
}

pub fn config_path() -> std::path::PathBuf {
    // When running under sudo/doas (e.g. ALPM hook), resolve the invoking
    // user's home before considering inherited XDG/HOME state.
    let invoking_user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("DOAS_USER"))
        .ok();
    if invoking_user.as_deref().is_some_and(|user| user != "root") {
        return calling_user_home()
            .map(|home| home.join(".config").join("bewaur").join("config.toml"))
            .unwrap_or_else(|| std::path::PathBuf::from("/etc/bewaur/config.toml"));
    }

    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return std::path::PathBuf::from(xdg)
            .join("bewaur")
            .join("config.toml");
    }

    if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home)
            .join(".config")
            .join("bewaur")
            .join("config.toml")
    } else {
        std::path::PathBuf::from("/etc/bewaur/config.toml")
    }
}

/// Resolve the invoking user's home directory when running under sudo or doas.
fn calling_user_home() -> Option<std::path::PathBuf> {
    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("DOAS_USER"))
        .ok()?;

    if user == "root" {
        return None;
    }

    let output = std::process::Command::new("/usr/bin/getent")
        .args(["passwd", &user])
        .output()
        .ok()?;

    let line = String::from_utf8(output.stdout).ok()?;
    // getent passwd format: name:x:uid:gid:gecos:home:shell
    let home = line.split(':').nth(5)?;
    Some(std::path::PathBuf::from(home))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "bewaur-config-{name}-{}-{}",
                std::process::id(),
                NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn digest(byte: char) -> String {
        format!("sha256:v1:p1:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn config_rejects_ambiguous_or_malformed_tree_approvals() {
        let mut config = Config::default();
        config.approvals.trees.push(TreeApproval {
            package_base: "demo".to_string(),
            digest: digest('a'),
        });
        config.approvals.trees.push(TreeApproval {
            package_base: "demo".to_string(),
            digest: digest('b'),
        });
        assert!(
            validate_config(&config)
                .unwrap_err()
                .contains("multiple exact-tree approvals")
        );

        config.approvals.trees.truncate(1);
        config.approvals.trees[0].digest = "sha256:v1:p1:not-a-digest".to_string();
        assert!(
            validate_config(&config)
                .unwrap_err()
                .contains("64 lowercase hexadecimal")
        );
    }

    #[test]
    fn config_save_atomically_replaces_a_regular_file() {
        let root = TestDir::new("atomic");
        let path = root.0.join("nested/config.toml");
        let mut config = Config::default();
        config.permanent_allow.packages.push("demo".to_string());
        config.approvals.trees.push(TreeApproval {
            package_base: "demo".to_string(),
            digest: digest('a'),
        });

        save_config_to_path(&config, &path).unwrap();
        let first: Config = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(first.permanent_allow.packages, vec!["demo"]);

        config.permanent_allow.packages.clear();
        config.approvals.trees[0].digest = digest('b');
        save_config_to_path(&config, &path).unwrap();
        let second: Config = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(second.permanent_allow.packages.is_empty());
        assert_eq!(second.approvals.trees[0].digest, digest('b'));
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn concurrent_config_transactions_preserve_every_update() {
        let root = TestDir::new("concurrent");
        let path = std::sync::Arc::new(root.0.join("nested/config.toml"));
        let mut threads = Vec::new();
        for index in 0..8 {
            let path = std::sync::Arc::clone(&path);
            threads.push(std::thread::spawn(move || {
                let package = format!("demo-{index}");
                update_config_at_path(&path, |config| {
                    config.permanent_allow.packages.push(package);
                    config.permanent_allow.packages.sort();
                    Ok(())
                })
            }));
        }
        for thread in threads {
            thread.join().unwrap().unwrap();
        }

        let config = load_config_strict_from_path(&path).unwrap();
        assert_eq!(config.permanent_allow.packages.len(), 8);
        for index in 0..8 {
            assert!(
                config
                    .permanent_allow
                    .packages
                    .contains(&format!("demo-{index}"))
            );
        }
    }

    #[test]
    fn strict_config_rejects_unknown_fields_and_relative_storage() {
        let root = TestDir::new("strict-fields");
        let path = root.0.join("config.toml");
        fs::write(&path, "schema_version = 1\nmisspelled_approvals = []\n").unwrap();
        let error = load_config_strict_from_path(&path).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");

        let relative = Path::new("relative/config.toml");
        let error = save_config_to_path(&Config::default(), relative).unwrap_err();
        assert!(error.contains("must be absolute"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn config_save_refuses_to_replace_a_symlink() {
        use std::os::unix::fs::symlink;

        let root = TestDir::new("symlink");
        let target = root.0.join("target.toml");
        let path = root.0.join("config.toml");
        fs::write(&target, "keep me").unwrap();
        symlink(&target, &path).unwrap();

        let error = save_config_to_path(&Config::default(), &path).unwrap_err();
        assert!(
            error.contains("Refusing to replace symlinked config"),
            "{error}"
        );
        assert_eq!(fs::read_to_string(target).unwrap(), "keep me");
    }
}
