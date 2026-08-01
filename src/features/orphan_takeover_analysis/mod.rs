use crate::features::Feature;
use crate::shared::aur_identity::same_identity;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory, TierFloor};

/// Matches the `M-VOTES-LOW` threshold in `metadata_analysis`.
const LOW_VOTE_THRESHOLD: u32 = 5;

pub struct OrphanTakeoverAnalysis;

impl Feature for OrphanTakeoverAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        let Some(ref meta) = ctx.metadata else {
            return signals;
        };

        let Some(ref submitter) = meta.submitter else {
            return signals;
        };

        let Some(ref maintainer) = meta.maintainer else {
            return signals;
        };

        // Exact comparison is correct here: both values are AUR account names
        // from the same RPC namespace. Normalizing them would only merge two
        // genuinely distinct accounts into a false negative.
        if submitter == maintainer {
            return signals;
        }

        // Submitter differs from current maintainer — package was adopted
        signals.push(Signal {
            id: "B-SUBMITTER-CHANGED".to_string(),
            category: SignalCategory::Behavioral,
            points: 15,
            description: format!(
                "Package maintainer ({maintainer}) differs from original submitter ({submitter})"
            ),
            is_override_gate: false,
            matched_line: None,
            min_tier: None,
        });

        // Adoption by an account with no track record, of a package with no
        // community validation. Either corroborator alone is unremarkable; what
        // makes the pair meaningful is that the handover already happened.
        //
        // This is the shape the June/July 2026 campaign actually presented:
        // an established package quietly adopted by a fresh single-package
        // account, with the malicious push arriving separately. It is scored
        // for the tier floor rather than the points, because the composite
        // below needs a *visible* author change and the bounded 20-commit clone
        // often does not contain one.
        let unvalidated_package = meta.num_votes < LOW_VOTE_THRESHOLD;
        // An empty list means the maintainer's packages were never fetched, not
        // that they own exactly one. Compare to 1 exactly, never `<= 1`.
        let unproven_maintainer = ctx.maintainer_packages.len() == 1;

        if unvalidated_package || unproven_maintainer {
            let reason = match (unvalidated_package, unproven_maintainer) {
                (true, true) => format!(
                    "only {} votes and the adopting maintainer has a single package",
                    meta.num_votes
                ),
                (true, false) => format!("only {} votes", meta.num_votes),
                (false, true) => "the adopting maintainer has a single package".to_string(),
                (false, false) => unreachable!("guarded by the branch above"),
            };
            signals.push(Signal {
                id: "B-UNPROVEN-ADOPTION".to_string(),
                category: SignalCategory::Behavioral,
                // Zero points on purpose. Both corroborators are already scored
                // by their own signals (`M-VOTES-LOW`/`M-VOTES-ZERO` and
                // `B-MAINTAINER-SINGLE`/`B-MAINTAINER-NEW`), so adding points
                // here would double-count them and could push a package into a
                // tier that prompts or blocks. The finding this signal carries
                // is the tier floor: it withholds TRUSTED and nothing more.
                points: 0,
                description: format!("Adopted package with {reason}"),
                is_override_gate: false,
                matched_line: None,
                min_tier: Some(TierFloor::Ok),
            });
        }

        // Composite: orphan takeover pattern
        // Requires: adopted + git author change + established package (>90 days)
        if ctx.git_log.len() >= 2 && is_established(meta.first_submitted) {
            let latest_author = ctx.git_log[0].author.as_str();
            // Git author is a `%an` display name, so the same person can appear
            // as "Alice B" and "alice-b" across commits. Compare normalized, or
            // a punctuation change reads as a takeover.
            let author_is_new = !ctx.git_log[1..]
                .iter()
                .any(|c| same_identity(&c.author, latest_author));

            if author_is_new {
                signals.push(Signal {
                    id: "B-ORPHAN-TAKEOVER".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 50,
                    description: format!(
                        "Adopted package with new git author ({latest_author}) — orphan takeover pattern"
                    ),
                    is_override_gate: false,
                    matched_line: None,
                    // Behavioral signals cap at 0.25 * 100 = 25 risk, so this
                    // composite can never leave TRUSTED on score alone. The
                    // floor is what makes the detection actually count.
                    min_tier: Some(TierFloor::Ok),
                });
            }
        }

        signals
    }
}

/// Package is established if first_submitted is more than 90 days ago.
fn is_established(first_submitted: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    now.saturating_sub(first_submitted) > 90 * 86400
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::models::{AurPackage, GitCommit};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn make_pkg(maintainer: &str, submitter: Option<&str>, first_submitted: u64) -> AurPackage {
        AurPackage {
            name: "test-pkg".into(),
            package_base: None,
            url: None,
            num_votes: 10,
            popularity: 1.0,
            out_of_date: None,
            maintainer: Some(maintainer.into()),
            submitter: submitter.map(|s| s.into()),
            first_submitted,
            last_modified: now(),
            license: None,
        }
    }

    fn make_commit(author: &str, ts: u64) -> GitCommit {
        GitCommit {
            author: author.into(),
            timestamp: ts,
            diff: None,
        }
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    fn signal_ids(ctx: &PackageContext) -> Vec<String> {
        OrphanTakeoverAnalysis
            .analyze(ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    /// An established, adopted package whose git log carries `authors`
    /// (newest first).
    fn adoption_context(authors: &[&str]) -> PackageContext {
        let ts = now();
        PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("attacker", Some("original"), ts - 365 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: authors
                .iter()
                .enumerate()
                .map(|(i, a)| make_commit(a, ts - (i as u64 * 30 + 1) * 86400))
                .collect(),
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        }
    }

    fn signal_by_id(ctx: &PackageContext, id: &str) -> Option<Signal> {
        OrphanTakeoverAnalysis
            .analyze(ctx)
            .into_iter()
            .find(|s| s.id == id)
    }

    #[test]
    fn plain_adoption_carries_no_floor() {
        // Single commit: the composite cannot fire, so nothing is floored.
        let ctx = adoption_context(&["attacker"]);
        let submitter_changed =
            signal_by_id(&ctx, "B-SUBMITTER-CHANGED").expect("adoption should be flagged");
        assert!(
            submitter_changed.min_tier.is_none(),
            "legitimate adoption is common; it must not cap the tier"
        );
    }

    #[test]
    fn low_votes_corroborate_an_unproven_adoption() {
        let mut ctx = adoption_context(&["someone"]);
        ctx.metadata.as_mut().unwrap().num_votes = 4;
        let signal = signal_by_id(&ctx, "B-UNPROVEN-ADOPTION").expect("should fire");
        assert_eq!(signal.min_tier, Some(TierFloor::Ok));
        assert!(signal.description.contains("4 votes"), "{}", signal.description);
    }

    #[test]
    fn single_package_maintainer_corroborates_an_unproven_adoption() {
        let mut ctx = adoption_context(&["someone"]);
        let pkg = ctx.metadata.clone().unwrap();
        ctx.maintainer_packages = vec![pkg];
        let signal = signal_by_id(&ctx, "B-UNPROVEN-ADOPTION").expect("should fire");
        assert_eq!(signal.min_tier, Some(TierFloor::Ok));
        assert!(
            signal.description.contains("single package"),
            "{}",
            signal.description
        );
    }

    #[test]
    fn well_voted_adoption_by_multi_package_maintainer_is_not_unproven() {
        let mut ctx = adoption_context(&["someone"]);
        let pkg = ctx.metadata.clone().unwrap();
        ctx.metadata.as_mut().unwrap().num_votes = 800;
        ctx.maintainer_packages = vec![pkg.clone(), pkg];
        assert!(signal_by_id(&ctx, "B-UNPROVEN-ADOPTION").is_none());
    }

    #[test]
    fn unfetched_maintainer_packages_are_not_a_single_package_account() {
        let mut ctx = adoption_context(&["someone"]);
        ctx.metadata.as_mut().unwrap().num_votes = 800;
        assert!(ctx.maintainer_packages.is_empty());
        assert!(
            signal_by_id(&ctx, "B-UNPROVEN-ADOPTION").is_none(),
            "an empty list means not fetched, not one package"
        );
    }

    #[test]
    fn unproven_adoption_needs_an_actual_adoption() {
        // Same submitter and maintainer: the feature returns before any of this.
        let mut ctx = adoption_context(&["someone"]);
        ctx.metadata.as_mut().unwrap().maintainer = Some("original".into());
        ctx.metadata.as_mut().unwrap().num_votes = 0;
        assert!(signal_by_id(&ctx, "B-UNPROVEN-ADOPTION").is_none());
    }

    #[test]
    fn orphan_takeover_floors_at_ok() {
        let ctx = adoption_context(&["attacker", "original"]);
        let takeover = signal_by_id(&ctx, "B-ORPHAN-TAKEOVER").expect("composite should fire");
        assert_eq!(takeover.min_tier, Some(TierFloor::Ok));
    }

    #[test]
    fn git_author_display_name_variation_is_not_a_new_author() {
        // Same human, punctuation changed between commits.
        let ctx = adoption_context(&["Alice B", "alice-b"]);
        let ids = signal_ids(&ctx);
        assert!(has(&ids, "B-SUBMITTER-CHANGED"));
        assert!(
            !has(&ids, "B-ORPHAN-TAKEOVER"),
            "a display-name variant must not read as a takeover"
        );
    }

    #[test]
    fn distinct_non_ascii_authors_still_read_as_a_takeover() {
        // Both normalize to "", so the raw fallback is what keeps them apart.
        let ctx = adoption_context(&["日本", "中文"]);
        assert!(has(&signal_ids(&ctx), "B-ORPHAN-TAKEOVER"));
    }

    #[test]
    fn identical_non_ascii_authors_are_not_a_takeover() {
        let ctx = adoption_context(&["日本", "日本"]);
        assert!(!has(&signal_ids(&ctx), "B-ORPHAN-TAKEOVER"));
    }

    #[test]
    fn same_submitter_maintainer() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("alice", Some("alice"), ts - 180 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        assert!(signal_ids(&ctx).is_empty());
    }

    #[test]
    fn no_submitter_field() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("alice", None, ts - 180 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        assert!(signal_ids(&ctx).is_empty());
    }

    #[test]
    fn submitter_changed() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("bob", Some("alice"), ts - 180 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let ids = signal_ids(&ctx);
        assert!(has(&ids, "B-SUBMITTER-CHANGED"));
        assert!(!has(&ids, "B-ORPHAN-TAKEOVER"));
    }

    #[test]
    fn orphan_takeover_composite() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("attacker", Some("original"), ts - 365 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![
                make_commit("attacker", ts - 3600),
                make_commit("original", ts - 180 * 86400),
            ],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let ids = signal_ids(&ctx);
        assert!(has(&ids, "B-SUBMITTER-CHANGED"));
        assert!(has(&ids, "B-ORPHAN-TAKEOVER"));
    }

    #[test]
    fn new_package_no_composite() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("bob", Some("alice"), ts - 30 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![
                make_commit("bob", ts - 3600),
                make_commit("alice", ts - 30 * 86400),
            ],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let ids = signal_ids(&ctx);
        assert!(has(&ids, "B-SUBMITTER-CHANGED"));
        assert!(!has(&ids, "B-ORPHAN-TAKEOVER"), "New package should not trigger composite signal");
    }

    #[test]
    fn same_git_author_no_composite() {
        let ts = now();
        let ctx = PackageContext {
            name: "pkg".into(),
            metadata: Some(make_pkg("bob", Some("alice"), ts - 365 * 86400)),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![
                make_commit("shared-author", ts - 3600),
                make_commit("shared-author", ts - 180 * 86400),
            ],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        let ids = signal_ids(&ctx);
        assert!(has(&ids, "B-SUBMITTER-CHANGED"));
        assert!(!has(&ids, "B-ORPHAN-TAKEOVER"), "Same git author should not trigger composite");
    }
}
