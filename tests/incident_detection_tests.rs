use bewaur::coordinator::scan_pkgbuild;
use bewaur::features::Feature;
use bewaur::features::install_script_analysis::InstallScriptAnalysis;
use bewaur::features::pkgbuild_analysis::PkgbuildAnalysis;
use bewaur::shared::models::PackageContext;
use bewaur::shared::scoring::{Signal, Tier, compute_score};

fn context(pkgbuild: Option<&str>, install_script: Option<&str>) -> PackageContext {
    PackageContext {
        name: "incident-test".into(),
        metadata: None,
        pkgbuild_content: pkgbuild.map(str::to_string),
        install_script_content: install_script.map(str::to_string),
        prior_pkgbuild_content: None,
        git_log: vec![],
        maintainer_packages: vec![],
        github_stars: None,
        github_not_found: false,
        aur_comments: vec![],
    }
}

fn has(signals: &[Signal], id: &str) -> bool {
    signals.iter().any(|signal| signal.id == id)
}

#[test]
fn pkgbuild_static_detection_covers_named_js_package_installs() {
    for command in [
        "npm install atomic-lockfile",
        "pnpm add @scope/pkg@1.2.3",
        "yarn add lockfile-js",
        "bun add js-digest",
        "env NODE_ENV=production npm install --ignore-scripts nextfile-js",
        "/usr/bin/npm i example-package",
        "/usr/bin/env bun add example-package",
        "command -- bun add example-package",
    ] {
        let pkgbuild = format!("build() {{\n  {command}\n}}");
        let signals = PkgbuildAnalysis.analyze(&context(Some(&pkgbuild), None));
        assert!(
            has(&signals, "P-NAMED-JS-PACKAGE-INSTALL"),
            "named install was missed: {command}; signals: {:?}",
            signals.iter().map(|signal| &signal.id).collect::<Vec<_>>()
        );
        assert!(
            signals
                .iter()
                .find(|signal| signal.id == "P-NAMED-JS-PACKAGE-INSTALL")
                .is_some_and(|signal| !signal.is_override_gate),
            "static package-manager behavior must remain supporting evidence"
        );
    }
}

#[test]
fn pkgbuild_static_detection_excludes_bare_and_local_installs() {
    for command in [
        "npm install",
        "npm ci",
        "npm install .",
        "npm install ./vendor/pkg",
        "pnpm add ../pkg",
        "yarn add file:../pkg",
        "bun add \"$srcdir/pkg\"",
        "npm install --omit dev",
    ] {
        let pkgbuild = format!("build() {{\n  {command}\n}}");
        let signals = PkgbuildAnalysis.analyze(&context(Some(&pkgbuild), None));
        assert!(
            !has(&signals, "P-NAMED-JS-PACKAGE-INSTALL"),
            "bare/local install must not signal: {command}"
        );
    }
}

#[test]
fn shared_parser_excludes_heredocs_and_resolves_static_manager_variables() {
    let heredoc = "build() {\n  cat <<E\"O\"F\n  npm install documentation-only\nEOF\n}";
    let signals = PkgbuildAnalysis.analyze(&context(Some(heredoc), None));
    assert!(!has(&signals, "P-NAMED-JS-PACKAGE-INSTALL"));

    let variables =
        "manager=bun\ndependency=js-digest\nbuild() { \"$manager\" add \"$dependency\"; }";
    let signals = PkgbuildAnalysis.analyze(&context(Some(variables), None));
    assert!(has(&signals, "P-NAMED-JS-PACKAGE-INSTALL"));
    assert!(has(&signals, "P-JUNE-2026-JS-IOC"));
}

#[test]
fn exact_june_campaign_is_sketchy_without_takeover_metadata() {
    let result = scan_pkgbuild(
        "incident-test",
        "pkgname=incident-test\nbuild() { bun add js-digest; }",
    );
    assert_eq!(result.tier, Tier::Sketchy);
    assert!(has(&result.signals, "P-JUNE-2026-JS-IOC"));
    assert!(result.override_gate_fired.is_none());
}

#[test]
fn install_script_named_package_fetch_is_high_severity_but_not_a_gate() {
    let signals = InstallScriptAnalysis.analyze(&context(None, Some("bun add js-digest")));
    let signal = signals
        .iter()
        .find(|signal| signal.id == "P-INSTALL-NAMED-JS-PACKAGE")
        .expect("named package install in .install must be detected");

    assert_eq!(signal.points, 90);
    assert!(!signal.is_override_gate);
    let result = compute_score("incident-test", &signals);
    assert_eq!(
        result.tier,
        Tier::Sketchy,
        "a named root-run install must be strict-gate blocking without being an unconditional override"
    );
}

#[test]
fn install_script_detects_symbolic_and_numeric_suid_sgid_modes() {
    for command in [
        "chmod u+s /usr/bin/helper",
        "chmod g+s /usr/bin/helper",
        "chmod -v ug+s /usr/bin/helper",
        "chmod 4755 /usr/bin/helper",
        "chmod 04755 /usr/bin/helper",
        "chmod -v 2750 /usr/bin/helper",
        "chmod 6755 /usr/bin/helper",
    ] {
        let signals = InstallScriptAnalysis.analyze(&context(None, Some(command)));
        let signal = signals
            .iter()
            .find(|signal| signal.id == "P-INSTALL-SUID-SGID")
            .unwrap_or_else(|| panic!("privileged chmod was missed: {command}"));
        assert_eq!(signal.points, 90);
        assert_eq!(compute_score("incident-test", &signals).tier, Tier::Sketchy);
    }
}

#[test]
fn install_script_does_not_confuse_normal_or_sticky_modes_with_suid_sgid() {
    for command in [
        "chmod 0755 /usr/bin/helper",
        "chmod 1755 /var/tmp/app",
        "chmod a-s /usr/bin/helper",
        "chmod +x /usr/bin/helper",
    ] {
        let signals = InstallScriptAnalysis.analyze(&context(None, Some(command)));
        assert!(
            !has(&signals, "P-INSTALL-SUID-SGID"),
            "ordinary chmod must not signal: {command}"
        );
    }

    let heredoc = "cat <<'EOF'\nchmod 4755 /usr/bin/documentation-example\nEOF";
    let signals = InstallScriptAnalysis.analyze(&context(None, Some(heredoc)));
    assert!(!has(&signals, "P-INSTALL-SUID-SGID"));
}

#[test]
fn wallet_pattern_requires_whole_token_boundaries() {
    let long_hex = format!("4A{}", "a".repeat(126));
    let signals = PkgbuildAnalysis.analyze(&context(Some(&format!("payload='{long_hex}'")), None));
    assert!(
        !has(&signals, "P-CRYPTO-WALLET"),
        "a wallet-shaped substring inside a longer token must not signal"
    );

    for wallet in [
        "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
        "0x52908400098527886E0F7030069857D2E4169EE7",
    ] {
        let signals = PkgbuildAnalysis.analyze(&context(Some(&format!("wallet='{wallet}'")), None));
        assert!(
            has(&signals, "P-CRYPTO-WALLET"),
            "real wallet address should still signal: {wallet}"
        );
    }
}
