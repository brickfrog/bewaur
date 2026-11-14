# Orphan Takeover Analysis

Detects packages where the current maintainer is not the original submitter, a pattern used in the acroread AUR attack (2018).

## What it detects

- **Submitter changed** (B-SUBMITTER-CHANGED, +15): Current AUR maintainer differs from the original submitter. Low points because legitimate adoption is common. Carries no tier floor for the same reason.
- **Unproven adoption** (B-UNPROVEN-ADOPTION, +0, floor `Ok`): Adoption plus at
  least one of: fewer than 5 votes, or an adopting maintainer who owns exactly
  one package. Scores **zero points on purpose** — both corroborators are already
  counted by `M-VOTES-LOW`/`M-VOTES-ZERO` and `B-MAINTAINER-SINGLE`/
  `B-MAINTAINER-NEW`, so adding points would double-count them and could push a
  package into a tier that prompts or blocks. Its entire effect is the tier
  floor: it withholds TRUSTED and nothing more.
- **Orphan takeover** (B-ORPHAN-TAKEOVER, +50, floor `Ok`): Composite signal requiring ALL of: submitter != maintainer, latest git author differs from prior authors, and the package is established (>90 days old). High-confidence indicator of malicious takeover.

## Identity comparison

`submitter` vs `maintainer` is compared **exactly** — both are AUR account names
from the same RPC namespace, so normalizing them would merge distinct accounts
into a false negative.

Git authors are compared with `aur_identity::same_identity`, because `%an` is an
arbitrary display name and the same person appears as both `Alice B` and
`alice-b`. Without normalization a punctuation change reads as a takeover.

## Tier floor

`B-ORPHAN-TAKEOVER` carries a `TierFloor::Ok`, so an adopted package with a new
git author can never be reported as TRUSTED.

Note that `B-ORPHAN-TAKEOVER`'s floor is a **backstop rather than the deciding
factor**: `T-AUTHOR-CHANGE` (+25 Temporal) necessarily co-fires whenever the
composite does, and `0.25*65 + 0.15*25 = 20.0` risk already lands at trust 80 —
one point below TRUSTED. That floor becomes load-bearing only when other
categories are suppressed via `bewaur ignore`, or if the weights ever change.

`B-UNPROVEN-ADOPTION` is the one that does real work. The July 2026 incident
packages that rated TRUSTED (`i915-sriov-dkms` at 93, `warp-terminal-git` at 89,
`astro-box` at 82) had **no visible author change** — the malicious pushes had
already been reverted by Arch staff, leaving only the adoption in the metadata.
The composite could not fire for them; the corroborated-adoption floor is what
withholds TRUSTED. `tests/takeover_tier_tests.rs` pins all three shapes.

A plain adoption with no corroborator (well-voted package, adopter with a track
record) is still TRUSTED by design.

### Why `maintainer_packages.len() == 1`, never `<= 1`

An empty list means the maintainer prefetch never ran or failed, not that the
account owns one package. Treating empty as a corroborator would floor every
adopted package whenever the prefetch failed.

## Signals emitted

All signals use `SignalCategory::Behavioral` (weight 0.25).

## Dependencies

- `PackageContext.metadata` — `submitter` and `maintainer` fields from AUR RPC
- `PackageContext.git_log` — git commit authors for composite signal

## Known false positives

- `B-SUBMITTER-CHANGED` (~30%): Many packages are legitimately adopted by new maintainers. Low points (15) reflect this.
- `B-ORPHAN-TAKEOVER` (~5%): Rare false positive — requires the specific combination of adoption + new git author + established package.
