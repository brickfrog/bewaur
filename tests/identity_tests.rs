//! Regression coverage for the fork's renamed runtime identity.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn cli_reports_bewaur_name_and_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_bewaur"))
        .arg("--version")
        .output()
        .expect("failed to run bewaur --version");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("bewaur {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn cli_help_uses_bewaur_command_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_bewaur"))
        .arg("--help")
        .output()
        .expect("failed to run bewaur --help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Usage: bewaur <COMMAND>"), "{stdout}");
}

#[test]
fn cargo_builds_only_the_renamed_binary_targets() {
    assert_eq!(
        Path::new(env!("CARGO_BIN_EXE_bewaur"))
            .file_name()
            .and_then(|name| name.to_str()),
        Some("bewaur")
    );
    assert_eq!(
        Path::new(env!("CARGO_BIN_EXE_bewaur-hook"))
            .file_name()
            .and_then(|name| name.to_str()),
        Some("bewaur-hook")
    );

    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("name = \"traur\""));
}

#[test]
fn renamed_hook_binary_starts_with_empty_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_bewaur-hook"))
        .stdin(Stdio::null())
        .output()
        .expect("failed to run bewaur-hook");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn cli_writes_only_the_renamed_config_directory() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("bewaur-identity-{}-{nonce}", std::process::id()));

    let output = Command::new(env!("CARGO_BIN_EXE_bewaur"))
        .args(["allow", "identity-test-package"])
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env_remove("SUDO_USER")
        .env_remove("DOAS_USER")
        .output()
        .expect("failed to run bewaur allow");

    assert!(output.status.success());
    assert!(root.join("config/bewaur/config.toml").is_file());
    assert!(!root.join("config/traur").exists());

    fs::remove_dir_all(root).unwrap();
}
