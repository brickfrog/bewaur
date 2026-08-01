use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::sync::LazyLock;

static HAS_CHECKSUMS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(md5|sha1|sha224|sha256|sha384|sha512|b2)sums(_[a-zA-Z0-9_]+)?\s*=").unwrap()
});

static WEAK_CHECKSUMS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(md5|sha1)sums=").unwrap());

static STRONG_CHECKSUMS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^(sha(256|384|512)|b2)sums=").unwrap());

static CHECKSUM_ARRAY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?ms)^(md5|sha\d+|b2)sums=\((.*?)\)").unwrap());

static ENTRY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"'([^']*)'").unwrap());

pub struct ChecksumAnalysis;

impl Feature for ChecksumAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.pkgbuild_content else {
            return Vec::new();
        };

        let mut signals = Vec::new();
        let is_vcs = ctx.name.ends_with("-git")
            || ctx.name.ends_with("-svn")
            || ctx.name.ends_with("-hg")
            || ctx.name.ends_with("-bzr");

        // Check for any checksum arrays
        if !HAS_CHECKSUMS_RE.is_match(content) && !is_vcs {
            signals.push(Signal {
                id: "P-NO-CHECKSUMS".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 30,
                description: "No checksum array found in PKGBUILD".to_string(),
                is_override_gate: false,
                matched_line: None,
                min_tier: None,
            });
        }

        // Check if all checksums are SKIP (only flag for non-VCS)
        if !is_vcs && has_all_skip_checksums(content) {
            signals.push(Signal {
                id: "P-SKIP-ALL".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 25,
                description: "All checksums are SKIP (no integrity verification)".to_string(),
                is_override_gate: false,
                matched_line: None,
                min_tier: None,
            });
        }

        // Check for weak checksums (md5 or sha1) without stronger alternative
        if WEAK_CHECKSUMS_RE.is_match(content) && !STRONG_CHECKSUMS_RE.is_match(content) {
            signals.push(Signal {
                id: "P-WEAK-CHECKSUMS".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 10,
                description: "Using weak checksums (md5/sha1) without stronger alternative"
                    .to_string(),
                is_override_gate: false,
                matched_line: None,
                min_tier: None,
            });
        }

        // Check source count vs checksum count mismatch (including arch-specific arrays)
        'outer: for suffix in find_array_suffixes(content) {
            let source_name = format!("source{suffix}");
            let src_count = count_array_entries(content, &source_name);
            if src_count > 0 {
                for algo in &["md5sums", "sha256sums", "sha512sums", "b2sums"] {
                    let checksum_name = format!("{algo}{suffix}");
                    let cksum_count = count_array_entries(content, &checksum_name);
                    if cksum_count > 0 && cksum_count != src_count {
                        signals.push(Signal {
                            id: "P-CHECKSUM-MISMATCH".to_string(),
                            category: SignalCategory::Pkgbuild,
                            points: 25,
                            description: format!(
                                "checksum count mismatch: {source_name} has {src_count} entries but {checksum_name} has {cksum_count}"
                            ),
                            is_override_gate: false,
                            matched_line: None,
                            min_tier: None,
                        });
                        break 'outer;
                    }
                }
            }
        }

        signals
    }
}

/// Check if the package has checksum arrays where ALL entries are 'SKIP'.
fn has_all_skip_checksums(content: &str) -> bool {
    let mut found_any = false;

    for caps in CHECKSUM_ARRAY_RE.captures_iter(content) {
        let body = &caps[2];
        let entries: Vec<&str> = ENTRY_RE
            .captures_iter(body)
            .map(|c| c.get(1).unwrap().as_str())
            .collect();

        if entries.is_empty() {
            continue;
        }

        found_any = true;

        // If any array has a non-SKIP entry, the package has real checksums
        if entries.iter().any(|e| *e != "SKIP") {
            return false;
        }
    }

    found_any
}

/// Find all source array suffixes (e.g. "", "_x86_64", "_i686").
fn find_array_suffixes(content: &str) -> Vec<String> {
    let re = Regex::new(r"(?m)^source(_[a-zA-Z0-9_]+)?\s*=\s*\(").unwrap();
    re.captures_iter(content)
        .map(|c| c.get(1).map_or(String::new(), |m| m.as_str().to_string()))
        .collect()
}

static DYNAMIC_BASH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\(|`|\$\{[^}]*\[@\]|\$\{[^}]*\[\*\]").unwrap());

/// Count entries in a bash array like source=(...) or sha256sums=(...)
/// Returns 0 for arrays with dynamic bash constructs (command substitution,
/// array expansion) since static token counting would be unreliable.
fn count_array_entries(content: &str, array_name: &str) -> usize {
    let pattern = format!(r"(?m)^\s*{}\s*=\s*\(", regex::escape(array_name));
    let re = Regex::new(&pattern).unwrap();
    let Some(opening) = re.find(content) else {
        return 0;
    };
    let Some(body) = extract_array_body(content, opening.end()) else {
        return 0;
    };
    if DYNAMIC_BASH_RE.is_match(body) {
        return 0;
    }
    count_static_shell_words(body).unwrap_or(0)
}

/// Return the array body, respecting quotes and nested parentheses rather than
/// stopping at a `)` contained in a URL or quoted filename.
fn extract_array_body(content: &str, body_start: usize) -> Option<&str> {
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 1usize;

    for (offset, ch) in content[body_start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else if ch == '\\' && delimiter == '"' {
                escaped = true;
            }
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&content[body_start..body_start + offset]);
                }
            }
            _ => {}
        }
    }

    None
}

/// Count Bash words while preserving quote concatenation. For example,
/// `"filename"::"https://example"` is one source entry, not three tokens.
fn count_static_shell_words(body: &str) -> Option<usize> {
    let mut count = 0usize;
    let mut in_word = false;
    let mut quote = None;
    let mut escaped = false;
    let mut in_comment = false;

    for ch in body.chars() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
            }
            continue;
        }
        if escaped {
            escaped = false;
            in_word = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else if ch == '\\' && delimiter == '"' {
                escaped = true;
            }
            in_word = true;
            continue;
        }

        match ch {
            '\\' => {
                escaped = true;
                in_word = true;
            }
            '\'' | '"' => {
                quote = Some(ch);
                in_word = true;
            }
            '#' if !in_word => in_comment = true,
            c if c.is_whitespace() => {
                if in_word {
                    count += 1;
                    in_word = false;
                }
            }
            _ => in_word = true,
        }
    }

    if quote.is_some() || escaped {
        return None;
    }
    if in_word {
        count += 1;
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(name: &str, content: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: name.into(),
            metadata: None,
            pkgbuild_content: Some(content.into()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        ChecksumAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    #[test]
    fn no_checksums() {
        let ids = analyze(
            "test-pkg",
            "pkgname=test\nsource=('https://example.com/a.tar.gz')\n",
        );
        assert!(has(&ids, "P-NO-CHECKSUMS"));
    }

    #[test]
    fn skip_all() {
        let ids = analyze(
            "test-pkg",
            "pkgname=test\nsource=('https://example.com/a.tar.gz')\nsha256sums=('SKIP')\n",
        );
        assert!(has(&ids, "P-SKIP-ALL"));
    }

    #[test]
    fn weak_checksums() {
        let ids = analyze(
            "test-pkg",
            "pkgname=test\nsource=('https://example.com/a.tar.gz')\nsha1sums=('da39a3ee5e6b4b0d3255bfef95601890afd80709')\n",
        );
        assert!(has(&ids, "P-WEAK-CHECKSUMS"));
    }

    #[test]
    fn checksum_mismatch() {
        let ids = analyze(
            "test-pkg",
            "pkgname=test\nsource=('a.tar.gz' 'b.tar.gz')\nsha256sums=('abc123')\n",
        );
        assert!(has(&ids, "P-CHECKSUM-MISMATCH"));
    }

    #[test]
    fn vcs_skip_not_flagged() {
        let ids = analyze(
            "tool-git",
            "pkgname=tool-git\nsource=('git+https://github.com/user/tool.git')\nsha256sums=('SKIP')\n",
        );
        assert!(
            !has(&ids, "P-SKIP-ALL"),
            "VCS package should not flag SKIP checksums"
        );
        assert!(
            !has(&ids, "P-NO-CHECKSUMS"),
            "VCS package should not flag missing checksums"
        );
    }

    #[test]
    fn strong_checksum_no_weak_flag() {
        let ids = analyze(
            "test-pkg",
            "pkgname=test\nsource=('a.tar.gz')\nsha256sums=('abc123')\n",
        );
        assert!(!has(&ids, "P-WEAK-CHECKSUMS"));
    }

    // --- Arch-specific array false positive regression ---

    #[test]
    fn checksum_mismatch_points_and_wording() {
        let ctx = PackageContext {
            name: "test-pkg".into(),
            metadata: None,
            pkgbuild_content: Some(
                "source=('a.tar.gz' 'b.tar.gz')\nsha256sums=('abc123')\n".into(),
            ),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let signals = ChecksumAnalysis.analyze(&ctx);
        let mismatch = signals
            .iter()
            .find(|s| s.id == "P-CHECKSUM-MISMATCH")
            .unwrap();
        assert_eq!(mismatch.points, 25);
        assert!(mismatch.description.contains("checksum count mismatch"));
    }

    #[test]
    fn checksum_arch_specific_no_mismatch() {
        let ids = analyze(
            "test-pkg",
            "source=('a.tar.gz' 'b.patch')\nsource_x86_64=('c.tar.gz')\nsha256sums=('hash1' 'hash2')\nsha256sums_x86_64=('hash3')\n",
        );
        assert!(
            !has(&ids, "P-CHECKSUM-MISMATCH"),
            "Arch-specific arrays should not cause mismatch, got: {ids:?}"
        );
    }

    #[test]
    fn renamed_source_url_is_one_array_entry() {
        let ids = analyze(
            "flutter-bin",
            r#"source=("$_pkgsrc.$_pkgext"::"$_url_dl/flutter.tar.xz")
md5sums=('0123456789abcdef0123456789abcdef')"#,
        );
        assert!(
            !has(&ids, "P-CHECKSUM-MISMATCH"),
            "filename::URL quote concatenation is one source entry, got: {ids:?}"
        );
    }

    #[test]
    fn parentheses_inside_source_url_do_not_end_array() {
        let ids = analyze(
            "test-pkg",
            "source=('https://example.test/file(1).tar' 'fix.patch')\nsha256sums=('h1' 'h2')",
        );
        assert!(!has(&ids, "P-CHECKSUM-MISMATCH"), "got: {ids:?}");
    }

    #[test]
    fn checksum_arch_specific_real_mismatch() {
        let ids = analyze(
            "test-pkg",
            "source=('a.tar.gz' 'b.patch')\nsha256sums=('hash1')\n",
        );
        assert!(has(&ids, "P-CHECKSUM-MISMATCH"));
    }

    #[test]
    fn arch_only_checksums_no_false_no_checksums() {
        // Package with only arch-specific checksum arrays should NOT fire P-NO-CHECKSUMS
        let ids = analyze(
            "test-bin",
            "source_x86_64=('a.tar.gz')\nsha256sums_x86_64=('hash1')\n",
        );
        assert!(
            !has(&ids, "P-NO-CHECKSUMS"),
            "arch-specific checksums should count, got: {ids:?}"
        );
    }

    #[test]
    fn dynamic_source_array_no_mismatch() {
        // source uses bash array expansion — static counting is unreliable, skip mismatch
        let ids = analyze(
            "test-pkg",
            "source=(\"$_iso\"\n  \"${_fonts[@]/#/file://}\"\n  file://license.rtf)\nsha256sums=('hash1' 'hash2' 'hash3')\n",
        );
        assert!(
            !has(&ids, "P-CHECKSUM-MISMATCH"),
            "dynamic source array should not trigger mismatch, got: {ids:?}"
        );
    }

    #[test]
    fn dynamic_checksum_array_no_mismatch() {
        // sha256sums uses command substitution — static counting is unreliable, skip mismatch
        let ids = analyze(
            "test-pkg",
            "source=('a.tar.gz' 'b.tar.gz')\nsha256sums=($(awk \"BEGIN{for(c=0;c<2;c++) printf \\\"SKIP\\n\\\"}\"))\n",
        );
        assert!(
            !has(&ids, "P-CHECKSUM-MISMATCH"),
            "dynamic checksum array should not trigger mismatch, got: {ids:?}"
        );
    }

    #[test]
    fn mismatch_emits_only_one_signal() {
        // Multiple arch suffixes with mismatches should only emit one P-CHECKSUM-MISMATCH
        let ctx = PackageContext {
            name: "test-bin".into(),
            metadata: None,
            pkgbuild_content: Some("source_x86_64=('a' 'b' 'c')\nsha256sums_x86_64=('h1')\nsource_aarch64=('d' 'e' 'f')\nsha256sums_aarch64=('h2')\n".into()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let signals = ChecksumAnalysis.analyze(&ctx);
        let mismatch_count = signals
            .iter()
            .filter(|s| s.id == "P-CHECKSUM-MISMATCH")
            .count();
        assert_eq!(
            mismatch_count, 1,
            "should emit exactly one mismatch signal, got {mismatch_count}"
        );
    }
}
