const PORTABLE_HOOK: &str = include_str!("../hook/traur.hook");
const NETWORK_HOOK: &str = include_str!("../hook/traur-network.hook");
const SOURCE_PKGBUILD: &str = include_str!("../pkg/PKGBUILD");
const BINARY_PKGBUILD: &str = include_str!("../pkg/PKGBUILD-bin");

#[test]
fn portable_hook_uses_only_upstream_alpm_keys() {
    assert!(!PORTABLE_HOOK.contains("NetworkAccess"));
    assert!(PORTABLE_HOOK.contains("NeedsTargets"));
    assert!(PORTABLE_HOOK.contains("AbortOnFail"));
}

#[test]
fn network_isolated_pacman_hook_explicitly_opts_in() {
    assert!(NETWORK_HOOK.contains("NetworkAccess = allowed"));
    assert!(NETWORK_HOOK.contains("NeedsTargets"));
    assert!(NETWORK_HOOK.contains("AbortOnFail"));
}

#[test]
fn packages_select_the_network_hook_by_capability() {
    for pkgbuild in [SOURCE_PKGBUILD, BINARY_PKGBUILD] {
        assert!(pkgbuild.contains("pacman --disable-sandbox-network --version"));
        assert!(pkgbuild.contains("traur-network.hook"));
        assert!(pkgbuild.contains("traur.hook"));
    }
}
