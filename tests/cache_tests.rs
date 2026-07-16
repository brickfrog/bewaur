//! End-to-end coverage for explicit, path-confined cache maintenance.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestCache {
    root: PathBuf,
    cache_home: PathBuf,
}

impl TestCache {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bewaur-cache-cli-{name}-{}-{nonce}",
            std::process::id()
        ));
        let cache_home = root.join("cache");
        fs::create_dir_all(cache_home.join("bewaur/git")).unwrap();
        Self { root, cache_home }
    }

    fn repository(&self, package_base: &str, bytes: &[u8]) {
        let directory = self.cache_home.join("bewaur/git").join(package_base);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("data"), bytes).unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bewaur"));
        command
            .env("HOME", self.root.join("home"))
            .env("XDG_CACHE_HOME", &self.cache_home);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command()
            .args(args)
            .output()
            .expect("failed to execute bewaur cache command")
    }

    fn git_cache(&self) -> PathBuf {
        self.cache_home.join("bewaur/git")
    }
}

impl Drop for TestCache {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn cache_stats_reports_repository_count_and_exact_bytes() {
    let cache = TestCache::new("stats");
    cache.repository("alpha", b"1234");
    cache.repository("beta", b"12");

    let output = cache.run(&["cache", "stats"]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("2 repositories"), "{stdout}");
    assert!(stdout.contains("6 bytes"), "{stdout}");
}

#[test]
fn cache_clean_removes_only_the_selected_package_base() {
    let cache = TestCache::new("selected");
    cache.repository("alpha", b"one");
    cache.repository("beta", b"two");

    let output = cache.run(&["cache", "clean", "alpha"]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!cache.git_cache().join("alpha").exists());
    assert!(cache.git_cache().join("beta").exists());
}

#[test]
fn cache_clean_rejects_traversal_without_touching_outside_data() {
    let cache = TestCache::new("traversal");
    cache.repository("alpha", b"one");
    let outside = cache.root.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("keep"), b"safe").unwrap();

    let output = cache.run(&["cache", "clean", "../../outside"]);

    assert!(!output.status.success());
    assert!(outside.join("keep").exists());
    assert!(cache.git_cache().join("alpha").exists());
}

#[test]
fn cache_clean_requires_an_explicit_target_or_all() {
    let cache = TestCache::new("explicit");
    cache.repository("alpha", b"one");

    let output = cache.run(&["cache", "clean"]);

    assert!(!output.status.success());
    assert!(cache.git_cache().join("alpha").exists());
}

#[test]
fn cache_clean_all_requires_flag_and_removes_every_repository() {
    let cache = TestCache::new("all");
    cache.repository("alpha", b"one");
    cache.repository("beta", b"two");

    let output = cache.run(&["cache", "clean", "--all"]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_dir(cache.git_cache()).unwrap().count(), 0);
}
