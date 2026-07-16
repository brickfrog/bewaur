const PORTABLE_HOOK: &str = include_str!("../hook/bewaur.hook");
const NETWORK_HOOK: &str = include_str!("../hook/bewaur-network.hook");
const SOURCE_PKGBUILD: &str = include_str!("../pkg/PKGBUILD");

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
