use crate::features::Feature;
use crate::shared::aur_identity::identity_key;
use crate::shared::js_package_manager;
use crate::shared::models::PackageContext;
use crate::shared::patterns;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

static CHECKSUM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(md5|sha1|sha224|sha256|sha384|sha512|b2)sums(_[a-z0-9_]+)?=").unwrap()
});

static SOURCE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^source(_[a-z0-9_]+)?\s*=\s*\(([^)]*)\)").unwrap());

static URL_DOMAIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://([^/\s'"]+)"#).unwrap());

/// Loaded once: high-severity pkgbuild patterns (points >= 60) for diff detection.
static HIGH_SEVERITY_PATTERNS: LazyLock<Vec<patterns::CompiledPattern>> = LazyLock::new(|| {
    patterns::load_patterns("pkgbuild_analysis")
        .into_iter()
        .filter(|p| p.points >= 60)
        .collect()
});

const ESTABLISHED_AGE_SECONDS: u64 = 90 * 86_400;
const RECENT_UPDATE_SECONDS: u64 = 90 * 86_400;
const RPC_GIT_ALIGNMENT_SECONDS: u64 = 7 * 86_400;

pub struct PkgbuildDiffAnalysis;

impl Feature for PkgbuildDiffAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let (Some(new_content), Some(old_content)) =
            (&ctx.pkgbuild_content, &ctx.prior_pkgbuild_content)
        else {
            return Vec::new();
        };

        let mut signals = Vec::new();

        check_new_suspicious(new_content, old_content, &mut signals);
        check_new_js_package_manager_behavior(ctx, new_content, old_content, &mut signals);
        check_checksum_removed(new_content, old_content, &mut signals);
        check_source_domain_changed(new_content, old_content, &mut signals);
        check_major_rewrite(new_content, old_content, &mut signals);

        signals
    }
}

fn check_new_js_package_manager_behavior(
    ctx: &PackageContext,
    new: &str,
    old: &str,
    signals: &mut Vec<Signal>,
) {
    let old_dependencies = js_package_manager::extract_manager_dependencies(old);
    let new_dependencies = js_package_manager::extract_manager_dependencies(new);
    let mut added_dependencies: Vec<_> = new_dependencies
        .difference(&old_dependencies)
        .cloned()
        .collect();
    added_dependencies.sort();

    if !added_dependencies.is_empty() {
        signals.push(Signal {
            id: "T-DIFF-NEW-JS-MANAGER-DEP".to_string(),
            category: SignalCategory::Temporal,
            points: 35,
            description: format!(
                "Current update adds JavaScript package-manager dependency: {}",
                added_dependencies.join(", ")
            ),
            is_override_gate: false,
            matched_line: find_line_with_any(new, &added_dependencies),
            min_tier: None,
        });
    }

    let old_analysis = js_package_manager::analyze(old);
    let new_analysis = js_package_manager::analyze(new);
    let old_installs: HashSet<(String, String)> = old_analysis
        .named_installs
        .into_iter()
        .map(|install| (install.manager, install.package))
        .collect();
    let added_installs: Vec<_> = new_analysis
        .named_installs
        .iter()
        .filter(|install| {
            !old_installs.contains(&(install.manager.clone(), install.package.clone()))
        })
        .collect();

    if let Some(first_install) = added_installs.first() {
        signals.push(Signal {
            id: "T-DIFF-NEW-NAMED-JS-INSTALL".to_string(),
            category: SignalCategory::Temporal,
            points: 55,
            description: format!(
                "Current update adds named package-manager install: {}",
                added_installs
                    .iter()
                    .map(|install| format!("{} {}", install.manager, install.package))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            is_override_gate: false,
            matched_line: Some(first_install.matched_line.clone()),
            min_tier: None,
        });
    }

    let old_iocs: HashSet<String> = old_analysis
        .known_june_iocs
        .into_iter()
        .map(|ioc| ioc.package)
        .collect();
    let added_iocs: Vec<_> = new_analysis
        .known_june_iocs
        .iter()
        .filter(|ioc| !old_iocs.contains(&ioc.package))
        .collect();

    if let Some(first_ioc) = added_iocs.first() {
        signals.push(Signal {
            id: "T-DIFF-NEW-JUNE-2026-IOC".to_string(),
            category: SignalCategory::Temporal,
            points: 80,
            description: format!(
                "Current update adds known June 2026 incident dependency: {}",
                added_iocs
                    .iter()
                    .map(|ioc| ioc.package.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            is_override_gate: false,
            matched_line: Some(first_ioc.matched_line.clone()),
            min_tier: None,
        });
    }

    let Some(takeover) = recent_takeover_evidence(ctx) else {
        return;
    };

    if let Some(first_install) = added_installs.first() {
        signals.push(Signal {
            id: "B-TAKEOVER-NAMED-JS-INSTALL".to_string(),
            category: SignalCategory::Behavioral,
            points: 95,
            description: format!(
                "Recently updated established adopted package has a new git author ({}) and adds a named package-manager install",
                takeover.latest_author
            ),
            is_override_gate: false,
            matched_line: Some(first_install.matched_line.clone()),
            min_tier: None,
        });
    }

    if let Some(first_ioc) = added_iocs.first()
        && takeover.author_matches_maintainer
    {
        signals.push(Signal {
            id: "B-RECENT-TAKEOVER-JUNE-2026-IOC".to_string(),
            category: SignalCategory::Behavioral,
            points: 98,
            description: format!(
                "Recent maintainer-authored takeover update adds known June 2026 incident dependency: {}",
                first_ioc.package
            ),
            is_override_gate: true,
            matched_line: Some(first_ioc.matched_line.clone()),
            min_tier: None,
        });
    }
}

struct RecentTakeoverEvidence<'a> {
    latest_author: &'a str,
    author_matches_maintainer: bool,
}

/// High-confidence evidence tied to the current update. Historical submitter
/// changes are insufficient: RPC and git timestamps must both be recent and
/// aligned, and the latest author must be absent from the available prior log.
///
/// The AUR clone is intentionally bounded to 20 commits, so this predicate is
/// supporting evidence only. An override additionally requires a known incident
/// IOC and a normalized latest-author/current-maintainer identity match.
fn recent_takeover_evidence(ctx: &PackageContext) -> Option<RecentTakeoverEvidence<'_>> {
    let metadata = ctx.metadata.as_ref()?;
    let submitter = metadata.submitter.as_deref()?;
    let maintainer = metadata.maintainer.as_deref()?;
    let submitter_identity = identity_key(submitter);
    let maintainer_identity = identity_key(maintainer);
    if submitter_identity.is_empty()
        || maintainer_identity.is_empty()
        || submitter_identity == maintainer_identity
        || ctx.git_log.len() < 2
    {
        return None;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if metadata.first_submitted == 0
        || now.saturating_sub(metadata.first_submitted) <= ESTABLISHED_AGE_SECONDS
        || metadata.last_modified == 0
        || metadata.last_modified > now + 86_400
        || now.saturating_sub(metadata.last_modified) > RECENT_UPDATE_SECONDS
    {
        return None;
    }

    let latest = &ctx.git_log[0];
    let author_identity = identity_key(&latest.author);
    if latest.author.trim().is_empty()
        || author_identity.is_empty()
        || latest.timestamp == 0
        || latest.timestamp > now + 86_400
        || now.saturating_sub(latest.timestamp) > RECENT_UPDATE_SECONDS
        || latest.timestamp.abs_diff(metadata.last_modified) > RPC_GIT_ALIGNMENT_SECONDS
        || ctx.git_log[1..]
            .iter()
            .any(|commit| commit.timestamp >= latest.timestamp)
        || ctx.git_log[1..]
            .iter()
            .any(|commit| identity_key(&commit.author) == author_identity)
    {
        return None;
    }

    Some(RecentTakeoverEvidence {
        latest_author: &latest.author,
        author_matches_maintainer: !author_identity.is_empty()
            && author_identity == maintainer_identity,
    })
}

fn find_line_with_any(content: &str, needles: &[String]) -> Option<String> {
    content
        .lines()
        .find(|line| {
            !line.trim_start().starts_with('#')
                && needles.iter().any(|needle| line.contains(needle))
        })
        .map(|line| line.trim().to_string())
}

/// Flag high-severity patterns newly introduced in the current version.
fn check_new_suspicious(new: &str, old: &str, signals: &mut Vec<Signal>) {
    for pattern in HIGH_SEVERITY_PATTERNS.iter() {
        if pattern.regex.is_match(new) && !pattern.regex.is_match(old) {
            let matched_line = new
                .lines()
                .find(|line| pattern.regex.is_match(line))
                .map(|l| l.trim().to_string());
            signals.push(Signal {
                id: "T-DIFF-NEW-SUSPICIOUS".to_string(),
                category: SignalCategory::Temporal,
                points: 40,
                description: format!(
                    "Newly introduced suspicious pattern: {} ({})",
                    pattern.id, pattern.description
                ),
                is_override_gate: false,
                matched_line,
                min_tier: None,
            });
            return; // one signal is enough
        }
    }
}

/// Flag if checksums were removed or all changed to SKIP.
fn check_checksum_removed(new: &str, old: &str, signals: &mut Vec<Signal>) {
    let old_has_checksums = CHECKSUM_RE.is_match(old);
    let new_has_checksums = CHECKSUM_RE.is_match(new);

    if old_has_checksums && !new_has_checksums {
        signals.push(Signal {
            id: "T-DIFF-CHECKSUM-REMOVED".to_string(),
            category: SignalCategory::Temporal,
            points: 35,
            description: "Checksum array removed in latest update".to_string(),
            is_override_gate: false,
            matched_line: None,
            min_tier: None,
        });
        return;
    }

    // Check if checksums all changed to SKIP
    if old_has_checksums && new_has_checksums {
        let old_has_skip_only = has_only_skip_checksums(old);
        let new_has_skip_only = has_only_skip_checksums(new);
        if !old_has_skip_only && new_has_skip_only {
            signals.push(Signal {
                id: "T-DIFF-CHECKSUM-REMOVED".to_string(),
                category: SignalCategory::Temporal,
                points: 35,
                description: "All checksums changed to SKIP in latest update".to_string(),
                is_override_gate: false,
                matched_line: None,
                min_tier: None,
            });
        }
    }
}

/// Check if all checksum entries are 'SKIP'.
fn has_only_skip_checksums(content: &str) -> bool {
    // Find checksum arrays and check if they only contain SKIP
    for cap in CHECKSUM_RE.find_iter(content) {
        let rest = &content[cap.end()..];
        // Find the matching parenthesized array
        if let Some(paren_start) = rest.find('(') {
            let after_paren = &rest[paren_start + 1..];
            if let Some(paren_end) = after_paren.find(')') {
                let array_content = &after_paren[..paren_end];
                let entries: Vec<&str> = array_content
                    .split_whitespace()
                    .map(|s| s.trim_matches('\'').trim_matches('\"'))
                    .filter(|s| !s.is_empty())
                    .collect();
                if !entries.is_empty() && entries.iter().all(|e| *e == "SKIP") {
                    continue;
                }
                return false;
            }
        }
    }
    true
}

/// Flag if source domains changed between versions.
fn check_source_domain_changed(new: &str, old: &str, signals: &mut Vec<Signal>) {
    let old_domains = extract_source_domains(old);
    let new_domains = extract_source_domains(new);

    if old_domains.is_empty() || new_domains.is_empty() {
        return;
    }

    // Flag if new introduces domains not in old
    let added: Vec<&String> = new_domains.difference(&old_domains).collect();
    if !added.is_empty() {
        signals.push(Signal {
            id: "T-DIFF-SOURCE-DOMAIN-CHANGED".to_string(),
            category: SignalCategory::Temporal,
            points: 30,
            description: format!(
                "Source URLs changed to new domain(s): {}",
                added
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            is_override_gate: false,
            matched_line: None,
            min_tier: None,
        });
    }
}

/// Extract domains from source=() arrays.
fn extract_source_domains(content: &str) -> HashSet<String> {
    let mut domains = HashSet::new();
    for cap in SOURCE_RE.captures_iter(content) {
        let array_content = &cap[2];
        for url_match in URL_DOMAIN_RE.captures_iter(array_content) {
            let domain = url_match[1].to_lowercase();
            // Strip common variable-containing prefixes
            if !domain.contains('$') {
                domains.insert(domain);
            }
        }
    }
    domains
}

/// Flag if >50% of lines changed (unusual for a version bump).
fn check_major_rewrite(new: &str, old: &str, signals: &mut Vec<Signal>) {
    let old_lines: HashSet<&str> = old
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    let new_lines: HashSet<&str> = new
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    if old_lines.is_empty() {
        return;
    }

    let common = old_lines.intersection(&new_lines).count();
    let total = old_lines.len().max(new_lines.len());
    let changed_pct = ((total - common) as f64 / total as f64 * 100.0) as u32;

    if changed_pct > 50 {
        signals.push(Signal {
            id: "T-DIFF-MAJOR-REWRITE".to_string(),
            category: SignalCategory::Temporal,
            points: 15,
            description: format!(
                "{}% of PKGBUILD lines changed (unusual for version bump)",
                changed_pct
            ),
            is_override_gate: false,
            matched_line: None,
            min_tier: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::models::{AurPackage, GitCommit};
    use crate::shared::scoring::{Tier, compute_score};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    fn analyze(new: &str, old: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: Some(new.to_string()),
            install_script_content: None,
            prior_pkgbuild_content: Some(old.to_string()),
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        PkgbuildDiffAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn takeover_context(new: &str, old: &str) -> PackageContext {
        let timestamp = now();
        PackageContext {
            name: "established-package".into(),
            metadata: Some(AurPackage {
                name: "established-package".into(),
                package_base: None,
                url: None,
                num_votes: 10,
                popularity: 1.0,
                out_of_date: None,
                maintainer: Some("new-maintainer".into()),
                submitter: Some("original-maintainer".into()),
                first_submitted: timestamp - 365 * 86_400,
                last_modified: timestamp - 60,
                license: None,
            }),
            pkgbuild_content: Some(new.into()),
            install_script_content: None,
            prior_pkgbuild_content: Some(old.into()),
            git_log: vec![
                GitCommit {
                    author: "New Maintainer".into(),
                    timestamp: timestamp - 60,
                    diff: None,
                },
                GitCommit {
                    author: "original-author".into(),
                    timestamp: timestamp - 180 * 86_400,
                    diff: None,
                },
            ],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        }
    }

    fn signals(ctx: &PackageContext) -> Vec<Signal> {
        PkgbuildDiffAnalysis.analyze(ctx)
    }

    #[test]
    fn no_prior_pkgbuild() {
        let ctx = PackageContext {
            name: "test".into(),
            metadata: None,
            pkgbuild_content: Some("pkgname=test".into()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        assert!(PkgbuildDiffAnalysis.analyze(&ctx).is_empty());
    }

    #[test]
    fn checksum_removed() {
        let old = "pkgname=test\nsha256sums=('abc123')";
        let new = "pkgname=test\n";
        assert!(has(&analyze(new, old), "T-DIFF-CHECKSUM-REMOVED"));
    }

    #[test]
    fn checksum_changed_to_skip() {
        let old = "pkgname=test\nsha256sums=('abc123def456')";
        let new = "pkgname=test\nsha256sums=('SKIP')";
        assert!(has(&analyze(new, old), "T-DIFF-CHECKSUM-REMOVED"));
    }

    #[test]
    fn checksum_unchanged_no_signal() {
        let old = "pkgname=test\nsha256sums=('abc123')";
        let new = "pkgname=test\nsha256sums=('def456')";
        assert!(!has(&analyze(new, old), "T-DIFF-CHECKSUM-REMOVED"));
    }

    #[test]
    fn source_domain_changed() {
        let old = "pkgname=test\nsource=('https://github.com/owner/repo/v1.tar.gz')";
        let new = "pkgname=test\nsource=('https://evil.com/repo/v1.tar.gz')";
        assert!(has(&analyze(new, old), "T-DIFF-SOURCE-DOMAIN-CHANGED"));
    }

    #[test]
    fn source_domain_same_no_signal() {
        let old = "pkgname=test\nsource=('https://github.com/owner/repo/v1.tar.gz')";
        let new = "pkgname=test\nsource=('https://github.com/owner/repo/v2.tar.gz')";
        assert!(!has(&analyze(new, old), "T-DIFF-SOURCE-DOMAIN-CHANGED"));
    }

    #[test]
    fn new_manager_dependency_is_supporting_only() {
        let old = "pkgname=test\nmakedepends=('git')";
        let new = "pkgname=test\nmakedepends=('git' 'npm')";
        let ctx = takeover_context(new, old);
        let found = signals(&ctx);
        assert!(found.iter().any(|s| s.id == "T-DIFF-NEW-JS-MANAGER-DEP"));
        assert!(found.iter().all(|s| !s.is_override_gate));
    }

    #[test]
    fn generic_takeover_install_is_high_risk_but_not_an_override() {
        let old = "pkgname=test\nbuild() { :; }";
        let new = "pkgname=test\nbuild() { npm install ordinary-build-tool; }";
        let ctx = takeover_context(new, old);
        let found = signals(&ctx);
        assert!(found.iter().any(|s| s.id == "B-TAKEOVER-NAMED-JS-INSTALL"));
        assert!(found.iter().all(|s| !s.is_override_gate));
    }

    #[test]
    fn recent_takeover_plus_new_known_ioc_gates_malicious() {
        let old = "pkgname=test\nbuild() { :; }";
        let new = "pkgname=test\nbuild() { bun add js-digest; }";
        let ctx = takeover_context(new, old);
        let found = signals(&ctx);
        let result = compute_score(&ctx.name, &found);
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(
            result.override_gate_fired.as_deref(),
            Some("B-RECENT-TAKEOVER-JUNE-2026-IOC")
        );
    }

    #[test]
    fn author_not_correlated_to_maintainer_cannot_fire_ioc_override() {
        let old = "pkgname=test\nbuild() { :; }";
        let new = "pkgname=test\nbuild() { bun add js-digest; }";
        let mut ctx = takeover_context(new, old);
        ctx.git_log[0].author = "unrelated-display-name".into();
        let found = signals(&ctx);
        assert!(found.iter().any(|s| s.id == "B-TAKEOVER-NAMED-JS-INSTALL"));
        assert!(found.iter().all(|s| !s.is_override_gate));
    }

    #[test]
    fn stale_adoption_cannot_fire_takeover_signals() {
        let old = "pkgname=test\nbuild() { :; }";
        let new = "pkgname=test\nbuild() { bun add js-digest; }";
        let mut ctx = takeover_context(new, old);
        let stale = now() - 365 * 86_400;
        ctx.metadata.as_mut().unwrap().last_modified = stale;
        ctx.git_log[0].timestamp = stale;
        let found = signals(&ctx);
        assert!(found.iter().all(|s| !s.id.starts_with("B-TAKEOVER")));
        assert!(found.iter().all(|s| !s.is_override_gate));
    }

    #[test]
    fn returning_author_in_available_history_cannot_fire_takeover_signals() {
        let old = "pkgname=test\nbuild() { :; }";
        let new = "pkgname=test\nbuild() { bun add js-digest; }";
        let mut ctx = takeover_context(new, old);
        ctx.git_log[1].author = ctx.git_log[0].author.clone();
        let found = signals(&ctx);
        assert!(found.iter().all(|s| !s.id.starts_with("B-TAKEOVER")));
        assert!(found.iter().all(|s| !s.is_override_gate));
    }

    #[test]
    fn returning_author_identity_variation_cannot_fire_takeover_signals() {
        let old = "pkgname=test\nbuild() { :; }";
        let new = "pkgname=test\nbuild() { bun add js-digest; }";
        let mut ctx = takeover_context(new, old);
        ctx.git_log[1].author = "new-maintainer".into();
        let found = signals(&ctx);
        assert!(found.iter().all(|s| !s.id.starts_with("B-TAKEOVER")));
        assert!(found.iter().all(|s| !s.is_override_gate));
    }

    #[test]
    fn submitter_identity_variation_is_not_a_takeover() {
        let old = "pkgname=test\nbuild() { :; }";
        let new = "pkgname=test\nbuild() { bun add js-digest; }";
        let mut ctx = takeover_context(new, old);
        ctx.metadata.as_mut().unwrap().submitter = Some("New Maintainer".into());
        let found = signals(&ctx);
        assert!(found.iter().all(|s| !s.id.starts_with("B-TAKEOVER")));
        assert!(found.iter().all(|s| !s.is_override_gate));
    }

    #[test]
    fn longstanding_named_install_has_no_new_behavior_signal() {
        let old = "pkgname=test\nbuild() { npm install legitimate-build-tool; }";
        let new = "pkgname=test\npkgver=2\nbuild() { npm install legitimate-build-tool; }";
        let ctx = takeover_context(new, old);
        let found = signals(&ctx);
        assert!(found.iter().all(|s| s.id != "T-DIFF-NEW-NAMED-JS-INSTALL"));
        assert!(found.iter().all(|s| !s.is_override_gate));
    }

    #[test]
    fn major_rewrite_detected() {
        let old = (1..=20)
            .map(|i| format!("line{i}=old"))
            .collect::<Vec<_>>()
            .join("\n");
        let new = (1..=20)
            .map(|i| format!("line{i}=new"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(has(&analyze(&new, &old), "T-DIFF-MAJOR-REWRITE"));
    }

    #[test]
    fn minor_change_no_rewrite_signal() {
        let mut lines: Vec<String> = (1..=20).map(|i| format!("line{i}=value")).collect();
        let old = lines.join("\n");
        lines[0] = "line1=changed".to_string();
        let new = lines.join("\n");
        assert!(!has(&analyze(&new, &old), "T-DIFF-MAJOR-REWRITE"));
    }
}
