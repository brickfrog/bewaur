# Tests

## Strategy

- **Unit tests** (`src/features/*/mod.rs`): Each feature has `#[cfg(test)] mod tests` that tests every signal it emits in isolation. Tests construct a `PackageContext` directly, call `feature.analyze()`, and assert on signal IDs.
- **Integration tests** (`tests/feature_tests.rs`): Full-pipeline tests using `scan_pkgbuild()` that verify coordinator + scoring + tier assignment across multiple features.
- **Hook packaging tests** (`tests/hook_tests.rs`): Verify that the standard ALPM
  hook remains portable while the network-isolated pacman variant explicitly opts
  in to networking, and that local packaging installs the renamed binaries and
  conflicts with the old package. A detached-session regression also proves that
  losing `/dev/tty` reaches the scanner and fails closed instead of skipping the
  transaction check.
- **Identity tests** (`tests/identity_tests.rs`): Exercise the compiled CLI name,
  version, help output, and absence of old binary targets.
- **Pre-build gate tests** (`tests/gate_tests.rs`): Exercise the compiled Paru
  gate, including strict exit policy, stderr-only reports, inert build-tree
  loading, stale `.SRCINFO` install/source coverage, literal sourced helpers,
  invalid-UTF-8 executable bytes, install command-vs-data positions, inert local
  patch/doc handling, complete-tree digest invalidation, reviewed-tree approval
  reporting, exact/permanent revocation, explicit total-bypass policy, and
  operational failures.
- **Incident detection tests** (`tests/incident_detection_tests.rs`): Cover the
  June 2026 package-manager campaign, named `.install` fetches, and SUID/SGID
  regressions through the real feature analyzers and scorer.
- **Cache command tests** (`tests/cache_tests.rs`): Exercise compiled CLI stats,
  selected-package pruning, traversal rejection, and explicit `--all` policy in
  an isolated XDG cache.
- **Artifact tests** (`tests/artifact_tests.rs`): Build synthetic ALPM package
  archives and exercise the compiled non-extracting inspector, including clean,
  warning, and blocking outcomes; metadata identity; JSON ordering; traversal
  and link-pivot refusal; GNU/PAX and compression failures; corrupt streams; and
  transaction-time install-script analysis.

- **Corpus harness** (`tests/corpus_cases.rs`): Offline policy checks over
  `tests/corpus/`. Benign cases are real AUR packages (imported from upstream
  traur, MIT) that must stay at or below `max_tier` (normally `ok`, because the
  strict gate blocks SKETCHY). Malicious cases are incident-derived samples
  with a `min_tier` and `required` bewaur signal IDs. Contexts are built from
  file contents only; nothing is sourced. `CASE` keys: `max_tier`, `min_tier`,
  `required`, `forbidden`, `helpers`, `install`, `expect_error`, `note`,
  `revision`. A case directory with a `.SRCINFO` is loaded through the real
  gate loader (`local_build::load_build_tree`); `expect_error` asserts that the
  loader refuses the tree. Run with
  `cargo test --test corpus_cases -- --nocapture` for the per-case report.

## Fixtures

- `fixtures/malicious/` — PKGBUILDs based on known attacks (CHAOS RAT, Xeactor patterns, synthetic examples)
- `fixtures/benign/` — PKGBUILDs from popular, trusted packages

## Running

```bash
cargo test
```

## Adding test cases

For a new **pattern**: Add a unit test in the relevant feature's `#[cfg(test)] mod tests` (e.g., `src/features/pkgbuild_analysis/mod.rs`).

For a new **integration scenario**: Add a fixture PKGBUILD in `fixtures/malicious/` or `fixtures/benign/`, then add a test in `tests/feature_tests.rs` that verifies tier/scoring behavior.
