use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory, TierFloor};
use std::collections::HashSet;
use std::sync::LazyLock;

/// Vendored snapshot; see the header of the data file for provenance.
static JUNE_2026_COMPROMISED: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../data/june-2026-compromised.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
});

/// Flags package names and bases on the public list of AUR packages
/// compromised in the June 2026 incident.
pub struct KnownCompromised;

pub fn is_listed(name: &str) -> bool {
    JUNE_2026_COMPROMISED.contains(name.to_ascii_lowercase().as_str())
}

impl Feature for KnownCompromised {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let base = ctx
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.package_base.as_deref());
        let Some(listed) = [Some(ctx.name.as_str()), base]
            .into_iter()
            .flatten()
            .find(|name| is_listed(name))
        else {
            return Vec::new();
        };

        vec![Signal {
            id: "B-JUNE-2026-COMPROMISED".to_string(),
            category: SignalCategory::Behavioral,
            points: 50,
            description: format!(
                "'{listed}' is on the public list of AUR packages compromised in the June 2026 incident; review the exact tree before building"
            ),
            is_override_gate: false,
            matched_line: None,
            // Many listed packages were later cleaned up, so this withholds
            // TRUSTED and OK (forcing review at the strict gate) without
            // claiming MALICIOUS.
            min_tier: Some(TierFloor::Sketchy),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(name: &str, base: Option<&str>) -> PackageContext {
        PackageContext {
            name: name.into(),
            metadata: base.map(|base| crate::shared::models::AurPackage {
                name: name.into(),
                package_base: Some(base.into()),
                url: None,
                num_votes: 0,
                popularity: 0.0,
                out_of_date: None,
                maintainer: None,
                submitter: None,
                first_submitted: 0,
                last_modified: 0,
                license: None,
            }),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        }
    }

    #[test]
    fn snapshot_is_loaded_and_comments_are_ignored() {
        assert!(JUNE_2026_COMPROMISED.len() > 1000);
        assert!(
            !JUNE_2026_COMPROMISED
                .iter()
                .any(|name| name.starts_with('#'))
        );
    }

    #[test]
    fn listed_name_or_base_raises_a_sketchy_floor() {
        let signals = KnownCompromised.analyze(&context("aws-cli-git", None));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].min_tier, Some(TierFloor::Sketchy));
        assert!(!signals[0].is_override_gate);

        let split = KnownCompromised.analyze(&context("some-split-output", Some("aws-cli-git")));
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn unlisted_names_are_silent() {
        assert!(
            KnownCompromised
                .analyze(&context("bewaur", None))
                .is_empty()
        );
        assert!(
            KnownCompromised
                .analyze(&context("yay-bin", None))
                .is_empty()
        );
    }
}
