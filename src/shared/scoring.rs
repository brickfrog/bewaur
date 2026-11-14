use serde::Serialize;

/// A signal emitted by a feature during analysis.
///
/// Every field is written explicitly at each construction site — there is
/// deliberately no `Default` impl, because eliding `is_override_gate` or
/// `min_tier` would let a scoring-critical decision be set by omission.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub id: String,
    pub category: SignalCategory,
    pub points: u32,
    pub description: String,
    pub is_override_gate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_line: Option<String>,
    /// The least-severe tier this signal will permit for the package, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_tier: Option<TierFloor>,
}

/// The four weighted signal categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignalCategory {
    Metadata,
    Pkgbuild,
    Behavioral,
    Temporal,
}

/// Trust tier derived from the final score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Tier {
    Trusted,
    Ok,
    Sketchy,
    Suspicious,
    Malicious,
}

/// The least-severe tier a signal will permit for the package.
///
/// Deliberately cannot express `Malicious`: that verdict belongs only to the
/// vetted override gates. Variant order matches [`Tier`] (best to worst), so
/// the strongest floor in a set is its `max`.
///
/// `Ok` is emitted by `B-ORPHAN-TAKEOVER` and `B-UNPROVEN-ADOPTION`; `Sketchy`
/// by `B-JUNE-2026-COMPROMISED`. `Suspicious` is reserved for future signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[allow(dead_code)]
pub enum TierFloor {
    Ok,
    Sketchy,
    Suspicious,
}

impl From<TierFloor> for Tier {
    fn from(floor: TierFloor) -> Self {
        match floor {
            TierFloor::Ok => Tier::Ok,
            TierFloor::Sketchy => Tier::Sketchy,
            TierFloor::Suspicious => Tier::Suspicious,
        }
    }
}

/// Why the reported tier is more severe than the score alone implies.
#[derive(Debug, Clone, Serialize)]
pub struct TierFloorReason {
    pub tier: Tier,
    pub signal: String,
}

/// Complete result of scanning a package.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub package: String,
    pub score: u32,
    pub tier: Tier,
    pub signals: Vec<Signal>,
    pub override_gate_fired: Option<String>,
    /// Set only when a tier floor actually raised the reported tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_floor: Option<TierFloorReason>,
}

/// Category weights for the composite score.
const WEIGHT_METADATA: f64 = 0.15;
const WEIGHT_PKGBUILD: f64 = 0.45;
const WEIGHT_BEHAVIORAL: f64 = 0.25;
const WEIGHT_TEMPORAL: f64 = 0.15;

/// Findings that must survive user suppression.
///
/// Computed over every signal a feature emitted, before the coordinator drops
/// rows the user has ignored. Ignoring a signal is a scoring preference, never
/// a detection kill switch.
#[derive(Debug, Default, Clone)]
pub struct HardFindings {
    pub override_gate: Option<(String, u32)>,
    pub floor: Option<(TierFloor, String)>,
}

/// Collect the override gate and tier floor from an unfiltered signal set.
pub fn hard_findings(signals: &[Signal]) -> HardFindings {
    let override_gate = signals
        .iter()
        .filter(|s| s.is_override_gate)
        .max_by_key(|s| s.points)
        .map(|s| (s.id.clone(), s.points));

    // Strongest floor wins. Ties break on points, then on the lexicographically
    // smallest id, so the reported reason does not depend on the order features
    // happen to be registered in `features::all_features()`.
    let floor = signals
        .iter()
        .filter_map(|s| s.min_tier.map(|floor| (floor, s)))
        .max_by(|(a, sa), (b, sb)| {
            a.cmp(b)
                .then(sa.points.cmp(&sb.points))
                .then(sb.id.cmp(&sa.id))
        })
        .map(|(floor, s)| (floor, s.id.clone()));

    HardFindings {
        override_gate,
        floor,
    }
}

/// Compute the final score and tier from a list of signals.
///
/// Correct only when `signals` is the unfiltered set. Callers that suppress
/// signals must use [`compute_score_with`] so that gates and floors are still
/// derived from everything the features emitted. The coordinator does exactly
/// that, which leaves this as the public convenience entry point.
#[allow(dead_code)]
pub fn compute_score(package_name: &str, signals: &[Signal]) -> ScanResult {
    compute_score_with(package_name, signals, hard_findings(signals))
}

/// Compute the final score from `scored_signals`, applying hard findings that
/// were collected separately (see [`hard_findings`]).
///
/// Callers that suppress signals for display must still pass the hard findings
/// derived from the unfiltered set, so a config edit cannot disable a gate.
pub fn compute_score_with(
    package_name: &str,
    scored_signals: &[Signal],
    hard: HardFindings,
) -> ScanResult {
    let weighted_score = compute_weighted(scored_signals);

    let (risk, gate_tier, override_gate_fired) = match hard.override_gate {
        // Use the higher of the override gate score and the weighted score.
        Some((id, points)) => (
            points.max(weighted_score).min(100),
            Some(Tier::Malicious),
            Some(id),
        ),
        None => (weighted_score, None, None),
    };

    let trust = 100 - risk;
    let scored_tier = score_to_tier(trust);
    let base_tier = gate_tier.unwrap_or(scored_tier);

    // A floor may only raise severity. `Tier` orders best-to-worst, so this is
    // a `max` and can never soften an override gate's MALICIOUS verdict.
    let (tier, tier_floor) = match hard.floor {
        Some((floor, signal)) => {
            let floor_tier = Tier::from(floor);
            let raised = base_tier.max(floor_tier);
            let reason =
                (raised == floor_tier && floor_tier > scored_tier).then_some(TierFloorReason {
                    tier: floor_tier,
                    signal,
                });
            (raised, reason)
        }
        None => (base_tier, None),
    };

    ScanResult {
        package: package_name.to_string(),
        score: trust,
        tier,
        signals: scored_signals.to_vec(),
        override_gate_fired,
        tier_floor,
    }
}

/// Compute the weighted composite score from signals (without override gate logic).
fn compute_weighted(signals: &[Signal]) -> u32 {
    let mut meta_total: u32 = 0;
    let mut pkgbuild_total: u32 = 0;
    let mut behavioral_total: u32 = 0;
    let mut temporal_total: u32 = 0;

    for signal in signals {
        match signal.category {
            SignalCategory::Metadata => meta_total += signal.points,
            SignalCategory::Pkgbuild => pkgbuild_total += signal.points,
            SignalCategory::Behavioral => behavioral_total += signal.points,
            SignalCategory::Temporal => temporal_total += signal.points,
        }
    }

    meta_total = meta_total.min(100);
    pkgbuild_total = pkgbuild_total.min(100);
    behavioral_total = behavioral_total.min(100);
    temporal_total = temporal_total.min(100);

    let weighted = (WEIGHT_METADATA * meta_total as f64)
        + (WEIGHT_PKGBUILD * pkgbuild_total as f64)
        + (WEIGHT_BEHAVIORAL * behavioral_total as f64)
        + (WEIGHT_TEMPORAL * temporal_total as f64);

    (weighted.round() as u32).min(100)
}

fn score_to_tier(trust: u32) -> Tier {
    match trust {
        0..=20 => Tier::Malicious,
        21..=40 => Tier::Suspicious,
        41..=60 => Tier::Sketchy,
        61..=80 => Tier::Ok,
        _ => Tier::Trusted,
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Trusted => write!(f, "TRUSTED"),
            Tier::Ok => write!(f, "OK"),
            Tier::Sketchy => write!(f, "SKETCHY"),
            Tier::Suspicious => write!(f, "SUSPICIOUS"),
            Tier::Malicious => write!(f, "MALICIOUS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(id: &str, category: SignalCategory, points: u32, override_gate: bool) -> Signal {
        Signal {
            id: id.to_string(),
            category,
            points,
            description: String::new(),
            is_override_gate: override_gate,
            matched_line: None,
            min_tier: None,
        }
    }

    fn floored(id: &str, points: u32, floor: TierFloor) -> Signal {
        Signal {
            min_tier: Some(floor),
            ..signal(id, SignalCategory::Behavioral, points, false)
        }
    }

    #[test]
    fn tier_floor_raises_a_trusted_score() {
        // Zero points: the score stays perfect, only the tier moves.
        let result = compute_score("pkg", &[floored("B-FLOOR", 0, TierFloor::Sketchy)]);
        assert_eq!(result.score, 100);
        assert_eq!(result.tier, Tier::Sketchy);
        let reason = result.tier_floor.expect("floor should be reported");
        assert_eq!(reason.tier, Tier::Sketchy);
        assert_eq!(reason.signal, "B-FLOOR");
    }

    #[test]
    fn tier_floor_never_softens_a_worse_score() {
        // Pkgbuild 100 -> 45 risk -> trust 55 -> Sketchy, already worse than Ok.
        let signals = vec![
            signal("P-BAD", SignalCategory::Pkgbuild, 100, false),
            floored("B-FLOOR", 0, TierFloor::Ok),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.tier, Tier::Sketchy);
        assert_eq!(result.score, 55);
        assert!(
            result.tier_floor.is_none(),
            "floor did not bind, so it must not be reported"
        );
    }

    #[test]
    fn strongest_floor_wins() {
        let signals = vec![
            floored("B-WEAK", 10, TierFloor::Ok),
            floored("B-STRONG", 10, TierFloor::Suspicious),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.tier, Tier::Suspicious);
        assert_eq!(result.tier_floor.unwrap().signal, "B-STRONG");
    }

    #[test]
    fn override_gate_outranks_every_floor() {
        let signals = vec![
            signal("P-REVSHELL-DEVTCP", SignalCategory::Pkgbuild, 95, true),
            floored("B-FLOOR", 10, TierFloor::Ok),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(
            result.override_gate_fired.as_deref(),
            Some("P-REVSHELL-DEVTCP")
        );
        assert!(result.tier_floor.is_none());
    }

    #[test]
    fn floor_never_changes_the_score() {
        let base = vec![signal("B-X", SignalCategory::Behavioral, 40, false)];
        let with_floor = vec![
            signal("B-X", SignalCategory::Behavioral, 40, false),
            floored("B-FLOOR", 0, TierFloor::Suspicious),
        ];
        assert_eq!(
            compute_score("pkg", &base).score,
            compute_score("pkg", &with_floor).score,
        );
    }

    #[test]
    fn hard_findings_survive_signal_suppression() {
        let all = vec![
            signal("P-REVSHELL-DEVTCP", SignalCategory::Pkgbuild, 95, true),
            floored("B-FLOOR", 10, TierFloor::Sketchy),
        ];
        let hard = hard_findings(&all);
        // Simulate the coordinator dropping every signal the user ignored.
        let result = compute_score_with("pkg", &[], hard);
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(
            result.override_gate_fired.as_deref(),
            Some("P-REVSHELL-DEVTCP")
        );
        assert!(result.signals.is_empty());
    }

    #[test]
    fn no_signals_scores_full_trust() {
        let result = compute_score("pkg", &[]);
        assert_eq!(result.score, 100);
        assert_eq!(result.tier, Tier::Trusted);
        assert!(result.override_gate_fired.is_none());
    }

    #[test]
    fn override_gate_picks_highest() {
        let signals = vec![
            signal("P-CURL-PIPE", SignalCategory::Pkgbuild, 90, true),
            signal("P-REVSHELL-DEVTCP", SignalCategory::Pkgbuild, 95, true),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(
            result.override_gate_fired.as_deref(),
            Some("P-REVSHELL-DEVTCP")
        );
        assert!(result.score <= 5, "Trust {} should be <= 5", result.score);
    }

    #[test]
    fn override_gate_uses_weighted_when_higher() {
        // Override gate (85) + lots of other signals that push weighted above 85
        let signals = vec![
            signal("P-REVSHELL-PYTHON", SignalCategory::Pkgbuild, 85, true),
            signal("P-EVAL-BASE64", SignalCategory::Pkgbuild, 85, false),
            signal("B-NAME-IMPERSONATE", SignalCategory::Behavioral, 65, false),
            signal("M-VOTES-ZERO", SignalCategory::Metadata, 30, false),
            signal("T-MALICIOUS-DIFF", SignalCategory::Temporal, 55, false),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.tier, Tier::Malicious);
        // Weighted risk: 0.45*100 + 0.25*65 + 0.15*30 + 0.15*55 = 74
        // Override gate risk: 85. Max(85, 74) = 85. Trust = 100 - 85 = 15
        assert!(result.score <= 15, "Trust {} should be <= 15", result.score);
    }

    #[test]
    fn category_caps_at_100() {
        let signals = vec![
            signal("P-A", SignalCategory::Pkgbuild, 80, false),
            signal("P-B", SignalCategory::Pkgbuild, 80, false),
        ];
        let result = compute_score("pkg", &signals);
        // Pkgbuild: min(160, 100) = 100 -> 0.45 * 100 = 45 risk -> 55 trust
        assert_eq!(result.score, 55);
        assert_eq!(result.tier, Tier::Sketchy);
    }

    #[test]
    fn tier_boundaries() {
        assert_eq!(score_to_tier(0), Tier::Malicious);
        assert_eq!(score_to_tier(20), Tier::Malicious);
        assert_eq!(score_to_tier(21), Tier::Suspicious);
        assert_eq!(score_to_tier(40), Tier::Suspicious);
        assert_eq!(score_to_tier(41), Tier::Sketchy);
        assert_eq!(score_to_tier(60), Tier::Sketchy);
        assert_eq!(score_to_tier(61), Tier::Ok);
        assert_eq!(score_to_tier(80), Tier::Ok);
        assert_eq!(score_to_tier(81), Tier::Trusted);
        assert_eq!(score_to_tier(100), Tier::Trusted);
    }

    #[test]
    fn min_trust_is_zero() {
        let signals = vec![
            signal("P", SignalCategory::Pkgbuild, 200, false),
            signal("M", SignalCategory::Metadata, 200, false),
            signal("B", SignalCategory::Behavioral, 200, false),
            signal("T", SignalCategory::Temporal, 200, false),
        ];
        let result = compute_score("pkg", &signals);
        assert_eq!(result.score, 0);
    }
}
