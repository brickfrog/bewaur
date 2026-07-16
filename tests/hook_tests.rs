const PORTABLE_HOOK: &str = include_str!("../hook/bewaur.hook");
const NETWORK_HOOK: &str = include_str!("../hook/bewaur-network.hook");
const SOURCE_PKGBUILD: &str = include_str!("../pkg/PKGBUILD");

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn portable_hook_uses_only_upstream_alpm_keys() {
    assert!(!PORTABLE_HOOK.contains("NetworkAccess"));
    assert!(PORTABLE_HOOK.contains("Exec = /usr/bin/bewaur-hook"));
    assert!(PORTABLE_HOOK.contains("Depends = bewaur"));
    assert!(PORTABLE_HOOK.contains("NeedsTargets"));
    assert!(PORTABLE_HOOK.contains("AbortOnFail"));
}

#[test]
fn network_isolated_pacman_hook_explicitly_opts_in() {
    assert!(NETWORK_HOOK.contains("NetworkAccess = allowed"));
    assert!(NETWORK_HOOK.contains("Exec = /usr/bin/bewaur-hook"));
    assert!(NETWORK_HOOK.contains("Depends = bewaur"));
    assert!(NETWORK_HOOK.contains("NeedsTargets"));
    assert!(NETWORK_HOOK.contains("AbortOnFail"));
}

#[test]
fn packages_select_the_network_hook_by_capability() {
    assert!(SOURCE_PKGBUILD.contains("pacman --disable-sandbox-network --version"));
    assert!(SOURCE_PKGBUILD.contains("bewaur-network.hook"));
    assert!(SOURCE_PKGBUILD.contains("bewaur.hook"));
    assert!(SOURCE_PKGBUILD.contains("target/release/bewaur"));
    assert!(SOURCE_PKGBUILD.contains("target/release/bewaur-hook"));
    assert!(SOURCE_PKGBUILD.contains("conflicts=('traur' 'traur-bin')"));
    assert!(SOURCE_PKGBUILD.contains("/usr/share/libalpm/hooks/bewaur.hook"));
    assert!(!SOURCE_PKGBUILD.contains("target/release/traur"));
    assert!(!SOURCE_PKGBUILD.contains("/usr/bin/traur"));
    assert!(!SOURCE_PKGBUILD.contains("/usr/share/libalpm/hooks/traur.hook"));
    assert!(!SOURCE_PKGBUILD.contains("/usr/share/traur"));
}

#[cfg(unix)]
#[test]
fn hook_without_a_controlling_tty_still_reaches_a_fail_closed_decision() {
    unsafe extern "C" {
        fn setsid() -> i32;
    }

    let mut command = Command::new(env!("CARGO_BIN_EXE_bewaur-hook"));
    command
        .env("PATH", "/nonexistent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // SAFETY: `setsid` is async-signal-safe and is the only operation run in
    // the child between fork and exec. It guarantees /dev/tty cannot be opened.
    unsafe {
        command.pre_exec(|| {
            if setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }

    let mut child = command.spawn().expect("failed to run detached hook");
    let package = "x".repeat(5_000);
    writeln!(child.stdin.take().unwrap(), "{package}").unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(
        !output.status.success(),
        "a missing tty must not bypass metadata validation: {stderr}"
    );
    assert!(
        stderr.contains("exceeds the AUR RPC URL length limit"),
        "the hook did not reach metadata validation: {stderr}"
    );
    assert!(
        stderr.contains("AUR metadata could not be fetched — blocking transaction"),
        "the hook did not make a fail-closed decision: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn hook_without_a_tty_blocks_on_malformed_security_config() {
    unsafe extern "C" {
        fn setsid() -> i32;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("bewaur-hook-config-{}-{nonce}", std::process::id()));
    let config_dir = root.join("config/bewaur");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(config_dir.join("config.toml"), "not valid TOML = [").unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_bewaur-hook"));
    command
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env_remove("SUDO_USER")
        .env_remove("DOAS_USER")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }

    let mut child = command.spawn().unwrap();
    writeln!(child.stdin.take().unwrap(), "demo").unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("invalid or unreadable security config — blocking transaction"),
        "{stderr}"
    );
    assert!(stderr.contains("Failed to parse config"), "{stderr}");

    fs::remove_dir_all(root).unwrap();
}
