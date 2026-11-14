pub mod patterns;

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::sync::LazyLock;

static SOURCE_ARRAYS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?ms)^source(?:_[a-zA-Z0-9_]+)?\s*=\s*\((.*?)\)").unwrap());

pub struct SourceUrlAnalysis;

impl Feature for SourceUrlAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.pkgbuild_content else {
            return Vec::new();
        };

        // Inspect every literal standard source-array assignment. This is
        // deliberately conservative: a benign earlier assignment must not hide
        // a later effective value, and makepkg consumes architecture-specific
        // variants such as source_x86_64.
        let source_content = SOURCE_ARRAYS_RE
            .captures_iter(content)
            .map(|caps| caps[1].to_string())
            .collect::<Vec<_>>()
            .join("\n");
        if source_content.is_empty() {
            return Vec::new();
        }

        let compiled = patterns::compiled_patterns();
        let mut signals = Vec::new();

        for pat in compiled {
            if pat.regex.is_match(&source_content) {
                let matched_line = source_content
                    .lines()
                    .find(|line| pat.regex.is_match(line))
                    .map(|line| line.trim().to_string());
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

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(source_url: &str) -> Vec<String> {
        let content = format!("pkgname=test\nsource=('{source_url}')\n");
        analyze_content(&content)
    }

    fn analyze_content(content: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: "test-pkg".into(),
            metadata: None,
            pkgbuild_content: Some(content.to_string()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        SourceUrlAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    #[test]
    fn raw_ip_url() {
        let ids = analyze("http://192.168.1.100/payload.tar.gz");
        assert!(has(&ids, "P-RAW-IP-URL"));
    }

    #[test]
    fn url_shortener() {
        let ids = analyze("https://bit.ly/malware");
        assert!(has(&ids, "P-URL-SHORTENER"));
    }

    #[test]
    fn discord_webhook() {
        let ids = analyze("https://discord.com/api/webhooks/123/ABC");
        assert!(has(&ids, "P-DISCORD-WEBHOOK"));
    }

    #[test]
    fn pastebin() {
        let ids = analyze("https://pastebin.com/raw/abc123");
        assert!(has(&ids, "P-PASTEBIN"));
    }

    #[test]
    fn dynamic_dns() {
        let ids = analyze("https://evil.duckdns.org/payload.tar.gz");
        assert!(has(&ids, "P-DYNAMIC-DNS"));
    }

    #[test]
    fn telegram_bot() {
        let ids = analyze("https://api.telegram.org/bot123:ABC/sendMessage");
        assert!(has(&ids, "P-TELEGRAM-BOT"));
    }

    #[test]
    fn tunnel_service() {
        let ids = analyze("https://abc123.ngrok.io/payload.tar.gz");
        assert!(has(&ids, "P-TUNNEL-SERVICE"));
    }

    #[test]
    fn http_source() {
        let ids = analyze("http://example.com/tool.tar.gz");
        assert!(has(&ids, "P-HTTP-SOURCE"));
    }

    #[test]
    fn filehost_source() {
        let ids = analyze("https://transfer.sh/abc123/payload.tar.gz");
        assert!(has(&ids, "P-FILEHOST-SOURCE"));
    }

    #[test]
    fn onion_source() {
        let ids = analyze("http://abc123def456.onion/tool.tar.gz");
        assert!(has(&ids, "P-ONION-SOURCE"));
    }

    #[test]
    fn mega_source() {
        let ids = analyze("https://mega.nz/file/abc123");
        assert!(has(&ids, "P-MEGA-SOURCE"));
    }

    #[test]
    fn github_no_signals() {
        let ids = analyze("https://github.com/user/repo/archive/v1.0.tar.gz");
        assert!(
            ids.is_empty(),
            "GitHub URL should trigger no signals, got: {ids:?}"
        );
    }

    #[test]
    fn later_source_assignment_cannot_hide_effective_url() {
        let ids = analyze_content(
            "source=('https://github.com/example/clean.tar.gz')\n\
             source=('http://192.0.2.1/payload.tar.gz')\n",
        );
        assert!(has(&ids, "P-RAW-IP-URL"), "got: {ids:?}");
        assert!(has(&ids, "P-HTTP-SOURCE"), "got: {ids:?}");
    }

    #[test]
    fn architecture_specific_source_arrays_are_analyzed() {
        let ids = analyze_content("source_x86_64=('http://192.0.2.1/payload.tar.gz')\n");
        assert!(has(&ids, "P-RAW-IP-URL"), "got: {ids:?}");
        assert!(has(&ids, "P-HTTP-SOURCE"), "got: {ids:?}");
    }

    #[test]
    fn ignores_comments() {
        let content = "# source from https://pastebin.com/abc\nsource=('https://github.com/user/repo.tar.gz')\n";
        let ids = analyze_content(content);
        assert!(
            !has(&ids, "P-PASTEBIN"),
            "Should not detect pastebin URL in comment"
        );
    }
}
