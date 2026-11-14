//! Tier assertions for packages carrying AUR metadata.
//!
//! Every other fixture path in the suite builds a context with `metadata: None`
//! (the pre-build gate and `scan_pkgbuild` both do), so adoption and maintainer
//! signals never fire there and no test covered the tier they produce. These do.
//!
//! Motivation: Arch halted AUR adoptions on 2026-07-31 after an influx of
//! malicious package adoptions. Scanning the compromised set showed the adoption
//! signals firing correctly while the packages still rated TRUSTED, because
//! behavioral signals cap at `0.25 * 100 = 25` risk and can never leave the
//! TRUSTED band on score alone.

use bewaur::coordinator::run_analysis_with_config;
use bewaur::shared::config::Config;
use bewaur::shared::models::{AurPackage, GitCommit, PackageContext};
use bewaur::shared::scoring::{Tier, TierFloor};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A PKGBUILD with nothing wrong with it. The real compromised trees had
/// already been reverted by Arch staff by the time they were scanned, so the
/// adoption metadata is the only evidence available — which is exactly the
/// case this test needs to pin.
const BENIGN_PKGBUILD: &str = r#"
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.org/demo"
source=("$pkgname-$pkgver.tar.gz::https://example.org/demo-$pkgver.tar.gz")
sha256sums=('7fd179ccf503ee6c985fdf2eb044c003e975c8e26f6c361ef199a91341e43874')

package() {
  cd "$srcdir/$pkgname-$pkgver"
  install -Dm644 README "${pkgdir}/usr/share/doc/${pkgname}/README"
}
"#;

struct Fixture {
    maintainer: &'static str,
    submitter: &'static str,
    age_days: u64,
    num_votes: u32,
    popularity: f64,
    authors: Vec<(&'static str, u64)>,
}

fn context(f: Fixture) -> PackageContext {
    let ts = now();
    PackageContext {
        name: "demo".into(),
        metadata: Some(AurPackage {
            name: "demo".into(),
            package_base: None,
            url: Some("https://example.org/demo".into()),
            num_votes: f.num_votes,
            popularity: f.popularity,
            out_of_date: None,
            maintainer: Some(f.maintainer.into()),
            submitter: Some(f.submitter.into()),
            first_submitted: ts - f.age_days * 86400,
            last_modified: ts - 3600,
            license: None,
        }),
        pkgbuild_content: Some(BENIGN_PKGBUILD.into()),
        install_script_content: None,
        prior_pkgbuild_content: None,
        git_log: f
            .authors
            .iter()
            .map(|(author, days_ago)| GitCommit {
                author: (*author).into(),
                timestamp: ts - days_ago * 86400,
                diff: None,
            })
            .collect(),
        maintainer_packages: vec![],
        github_stars: Some(500),
        github_not_found: false,
        aur_comments: vec![],
    }
}

#[test]
fn sanitized_compromised_shape_cannot_be_trusted() {
    let ctx = context(Fixture {
        maintainer: "attacker",
        submitter: "original",
        age_days: 900,
        num_votes: 4,
        popularity: 0.0,
        authors: vec![("attacker", 1), ("original", 400)],
    });
    let result = run_analysis_with_config(&ctx, &Config::default());

    assert!(
        result.tier >= Tier::Ok,
        "adopted package with a new git author must not rate TRUSTED (got {:?} at {})",
        result.tier,
        result.score
    );

    // The score alone already reaches Ok here, so the floor is redundant in the
    // default configuration — see `orphan_takeover_floor_is_defense_in_depth`
    // for the case where it does the work. `B-ORPHAN-TAKEOVER` cannot fire
    // without `T-AUTHOR-CHANGE` also firing (both need >= 2 commits and a
    // latest author absent from the priors), and 0.25*65 + 0.15*25 = 20.0 risk
    // lands at trust 80, one point below the TRUSTED band.
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.id == "B-ORPHAN-TAKEOVER" && s.min_tier == Some(TierFloor::Ok)),
        "the composite must still carry its floor as a backstop"
    );

    // The score stays an honest risk number; the tier is what gets clamped.
    assert!(
        result.score > 60,
        "score should remain high (got {})",
        result.score
    );
}

#[test]
fn orphan_takeover_floor_is_defense_in_depth() {
    // With the temporal category suppressed, `T-AUTHOR-CHANGE`'s points are
    // gone and the weighted score climbs back into the TRUSTED band. The floor
    // is the only thing keeping an adopted, newly-authored package out of it.
    let ctx = context(Fixture {
        maintainer: "attacker",
        submitter: "original",
        age_days: 900,
        num_votes: 800,
        popularity: 12.0,
        authors: vec![("attacker", 1), ("original", 400)],
    });
    let mut config = Config::default();
    config.ignored.categories = vec!["Temporal".into()];

    let result = run_analysis_with_config(&ctx, &config);
    assert!(
        result.score >= 81,
        "score alone should say TRUSTED here (got {})",
        result.score
    );
    assert_eq!(result.tier, Tier::Ok, "the floor must override the score");
    assert_eq!(
        result.tier_floor.as_ref().map(|f| f.signal.as_str()),
        Some("B-ORPHAN-TAKEOVER"),
    );
}

#[test]
fn legitimate_long_settled_adoption_stays_trusted() {
    // Adopted years ago, and every commit since is by the same person.
    let ctx = context(Fixture {
        maintainer: "newmaintainer",
        submitter: "founder",
        age_days: 2000,
        num_votes: 800,
        popularity: 12.0,
        authors: vec![("newmaintainer", 30), ("newmaintainer", 400)],
    });
    let result = run_analysis_with_config(&ctx, &Config::default());
    assert_eq!(
        result.tier,
        Tier::Trusted,
        "a settled handoff must not be penalized (score {})",
        result.score
    );
    assert!(result.tier_floor.is_none());
}

#[test]
fn clean_never_adopted_package_is_trusted() {
    let ctx = context(Fixture {
        maintainer: "founder",
        submitter: "founder",
        age_days: 2000,
        num_votes: 800,
        popularity: 12.0,
        authors: vec![("founder", 30), ("founder", 400)],
    });
    let result = run_analysis_with_config(&ctx, &Config::default());
    assert_eq!(result.tier, Tier::Trusted);
    assert!(result.tier_floor.is_none());
}

#[test]
fn ignored_category_cannot_defeat_a_tier_floor() {
    let ctx = context(Fixture {
        maintainer: "attacker",
        submitter: "original",
        age_days: 900,
        num_votes: 4,
        popularity: 0.0,
        authors: vec![("attacker", 1), ("original", 400)],
    });
    let mut config = Config::default();
    config.ignored.categories = vec!["Behavioral".into()];

    let result = run_analysis_with_config(&ctx, &config);

    assert!(
        result.tier >= Tier::Ok,
        "ignoring a category suppresses points, never the tier decision"
    );
    assert_eq!(
        result.tier_floor.as_ref().map(|f| f.signal.as_str()),
        Some("B-ORPHAN-TAKEOVER"),
    );
    assert!(
        !result.signals.iter().any(|s| s.id == "B-ORPHAN-TAKEOVER"),
        "the signal itself should still be hidden from the report"
    );
}

#[test]
fn ignoring_the_floor_signal_by_id_also_cannot_defeat_it() {
    let ctx = context(Fixture {
        maintainer: "attacker",
        submitter: "original",
        age_days: 900,
        num_votes: 4,
        popularity: 0.0,
        authors: vec![("attacker", 1), ("original", 400)],
    });
    // Ignore every floor-bearing signal by id; the tier must still hold.
    let mut config = Config::default();
    config.ignored.signals = vec!["B-ORPHAN-TAKEOVER".into(), "B-UNPROVEN-ADOPTION".into()];

    let result = run_analysis_with_config(&ctx, &config);
    assert!(result.score >= 81, "score alone would say TRUSTED here");
    assert_eq!(result.tier, Tier::Ok);
    assert!(result.tier_floor.is_some());
}

#[test]
fn quietly_adopted_low_vote_package_cannot_be_trusted() {
    // The shape that actually rated TRUSTED at 93/100 during the July 2026
    // incident: an established package adopted by a different account, with a
    // git log that shows no author change at all because the malicious push had
    // already been reverted. `B-ORPHAN-TAKEOVER` cannot fire here — only the
    // adoption itself plus the absence of community validation.
    let ctx = context(Fixture {
        maintainer: "zsolthorvath",
        submitter: "bbaa",
        age_days: 900,
        num_votes: 4,
        popularity: 1.0,
        authors: vec![("bbaa", 90), ("bbaa", 200)],
    });
    let result = run_analysis_with_config(&ctx, &Config::default());

    assert!(
        !result.signals.iter().any(|s| s.id == "B-ORPHAN-TAKEOVER"),
        "no visible author change, so the composite must not fire"
    );
    assert!(
        result.score >= 81,
        "score alone still says TRUSTED (got {}) — the floor is the mechanism",
        result.score
    );
    assert_eq!(result.tier, Tier::Ok);
    assert_eq!(
        result.tier_floor.as_ref().map(|f| f.signal.as_str()),
        Some("B-UNPROVEN-ADOPTION"),
    );
}

#[test]
fn adoption_by_an_established_maintainer_is_not_unproven() {
    // Well-voted package, adopter owns many packages: no corroborator, so no
    // floor. This is the ordinary legitimate handoff and it must stay clean.
    let mut ctx = context(Fixture {
        maintainer: "trusted-dev",
        submitter: "founder",
        age_days: 2000,
        num_votes: 800,
        popularity: 12.0,
        authors: vec![("trusted-dev", 30), ("trusted-dev", 400)],
    });
    // Three packages under this maintainer: not a single-package account.
    let base = ctx.metadata.clone().unwrap();
    ctx.maintainer_packages = vec![base.clone(), base.clone(), base];

    let result = run_analysis_with_config(&ctx, &Config::default());
    assert!(
        !result.signals.iter().any(|s| s.id == "B-UNPROVEN-ADOPTION"),
        "an established adopter of a popular package is not unproven"
    );
    assert_eq!(result.tier, Tier::Trusted);
}

#[test]
fn unfetched_maintainer_packages_do_not_corroborate() {
    // An empty `maintainer_packages` means "never fetched", not "one package".
    // Treating it as a corroborator would floor every adopted package whenever
    // the maintainer prefetch failed.
    let ctx = context(Fixture {
        maintainer: "newmaintainer",
        submitter: "founder",
        age_days: 2000,
        num_votes: 800,
        popularity: 12.0,
        authors: vec![("newmaintainer", 30), ("newmaintainer", 400)],
    });
    assert!(ctx.maintainer_packages.is_empty());

    let result = run_analysis_with_config(&ctx, &Config::default());
    assert!(
        !result.signals.iter().any(|s| s.id == "B-UNPROVEN-ADOPTION"),
        "an unfetched maintainer list must not read as a single-package account"
    );
    assert_eq!(result.tier, Tier::Trusted);
}
