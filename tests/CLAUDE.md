# Tests

## Strategy

- **Unit tests** (`src/features/*/mod.rs`): Each feature has `#[cfg(test)] mod tests` that tests every signal it emits in isolation. Tests construct a `PackageContext` directly, call `feature.analyze()`, and assert on signal IDs.
- **Integration tests** (`tests/feature_tests.rs`): Full-pipeline tests using `scan_pkgbuild()` that verify coordinator + scoring + tier assignment across multiple features.
- **Hook packaging tests** (`tests/hook_tests.rs`): Verify that the standard ALPM
  hook remains portable while the network-isolated pacman variant explicitly opts
  in to networking, and that local packaging installs the renamed binaries and
  conflicts with the old package.
- **Identity tests** (`tests/identity_tests.rs`): Exercise the compiled CLI name,
  version, help output, and absence of old binary targets.

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
