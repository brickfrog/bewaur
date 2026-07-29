# Changelog

## Unreleased

### Changed
- **Project identity**: the personal fork is renamed from `traur` to `bewaur`.
  The CLI, hook binary, ALPM hook, config directory, cache directory, package,
  output prefixes, and HTTP user agents all use the new name. Existing
  `~/.config/traur` and `~/.cache/traur` state is intentionally not migrated.

### Fixed
- **Arch package linking**: use the system zstd library through pkg-config so
  makepkg's GCC LTO flags cannot leave bundled zstd objects unresolved when
  Rust links with lld. Declare the matching build/runtime dependencies and bump
  the local package release.
- **Complete, current scans**: network and hook scans now require a clean cache
  entry at the exact freshly fetched AUR `master` commit, reject stale or dirty
  repositories, and use the same path-confined `.SRCINFO`, install-script, and
  executable-helper loader as the pre-build gate.
- **Noninteractive hook policy**: an unavailable `/dev/tty` no longer skips the
  ALPM scan. Clean packages still pass unattended transactions, while flagged
  packages and operational scan errors block when no user can answer a prompt.
- **Hook fail-closed**: the ALPM hook now blocks the transaction when scans fail (git timeout, network error, etc.) instead of silently allowing unscanned packages through. Git clone/pull operations have a 30-second timeout to prevent indefinite hangs.
- **CachyOS hook networking**: package builds now select a `NetworkAccess = allowed`
  hook on pacman variants that isolate ALPM hooks from the network, while retaining
  a separate portable hook for standard Arch pacman.
- **Batch metadata errors**: AUR RPC transport and response failures are no longer
  treated as packages missing from the AUR, which previously skipped trust scoring.
- **Current AUR behavior**: restore comment extraction for the current HTML markup,
  make bulk-scan operational errors nonzero, and correct checksum/source counting
  plus checksum, comment, heredoc, and wallet-address false positives.
- **Shell bypasses**: reconstruct quoted command words such as `cu""rl | ba''sh`
  with wrapper, heredoc, and redirection-aware parsing instead of raw-text guesses.
- **Gate parser bypasses**: preserve textual variable-assignment order, inspect
  repeated and architecture-specific source arrays, require active compilation
  commands before suppressing binary-download findings, and include inert-looking
  helpers executed through process substitutions or code-loading interpreter
  options.
- **Terminal-safe evidence**: visibly escape attacker-controlled control and
  bidirectional formatting characters in human-readable scan output while
  preserving structured JSON data.

### Added
- **Built-artifact inspection**: add a bounded, non-extracting
  `inspect-artifact` command that validates ALPM archive structure and identity,
  scans transaction-time `.INSTALL` code, reports privileged payload and
  persistence surfaces, binds results to SHA-256, and supports ordered text or
  JSON reports for split-package outputs. Document a clean-chroot, root-owned
  staging, inspect, and explicit `pacman -U` workflow.
- **Exact local-tree approvals**: add versioned, policy-revisioned approval
  fingerprints over every entry in a fully loaded build tree, including VCS
  metadata and the build-root mode. Approved
  trees are still scanned and reported, but may override the final pre-build
  tier block until any path, content byte, mode, directory, or symlink changes.
- **Explicit authorization management**: add `approve`, `approvals`, and
  `revoke`; reserve `allow <pkgbase> --forever` for a conspicuous permanent
  name-wide bypass. Config updates are strictly validated, serialized under an
  exclusive lock, written atomically with private permissions, and legacy
  `[whitelist]` sections fail closed.
- **Paru pre-build gate**: `bewaur gate --build-dir .` inertly scans the exact,
  path-confined build tree before `makepkg`, blocks `SKETCHY` and above, and fails
  closed on operational or statically recognizable metadata-mutation errors.
- **June 2026 incident defenses**: detect named npm/pnpm/yarn/bun installs, exact
  incident dependencies, newly added manager behavior, correlated recent package
  takeovers, and active SUID/SGID mode changes in PKGBUILDs and install scripts.
- **Cache maintenance**: add safe `cache stats`, targeted `cache clean <base>`,
  and explicit `cache clean --all` commands without following symlink entries.
- **`-bin` source verification** (`bin_source_verification`): cross-references a `-bin` package's declared upstream URL against its `source=()` download domains. Detects fork impersonation when a package claims one GitHub org as upstream but downloads binaries from a different org. Emits `B-BIN-GITHUB-ORG-MISMATCH` (+50) and `B-BIN-DOMAIN-MISMATCH` (+30) behavioral signals.
- **Orphan takeover detection** (`orphan_takeover_analysis`): New feature that deserializes the `Submitter` field from AUR RPC and compares it against the current `Maintainer`. Emits `B-SUBMITTER-CHANGED` (+15, Behavioral) when they differ, and `B-ORPHAN-TAKEOVER` (+50, Behavioral) when combined with a git author change on an established package (>90 days). Detects the acroread-style attack vector where an attacker adopts an orphaned package and injects malicious code.
- `AurPackage` now deserializes `submitter` and `last_modified` from AUR RPC v5 responses.
