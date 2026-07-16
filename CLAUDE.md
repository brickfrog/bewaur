# bewaur - Pre-install Risk and Trust Scoring for AUR Packages

Scores AUR packages before you install them. ALPM hook for pre-install scanning.

## Architecture

Feature-based with coordinator pattern:

```
PackageContext (metadata + pkgbuild + git)
  -> Coordinator runs all Features
  -> Each Feature returns Vec<Signal>
  -> Scorer applies weights + override gates -> final score + tier
```

**Features** (`src/features/`): Self-contained analysis modules, each implementing the `Feature` trait. Each detects specific security signals.

**Shared** (`src/shared/`): Reusable components (AUR API client, GitHub API client, AUR comments scraper, git ops, scoring engine, pattern loader, cache, config, output).

**Coordinator** (`src/coordinator.rs`): Orchestrates features, collects signals, computes final score.

## Scoring

Trust score 0-100 (higher = more trusted) from 4 weighted categories:
```
risk = 0.15*metadata + 0.45*pkgbuild + 0.25*behavioral + 0.15*temporal
trust = 100 - risk
```

Tiers: TRUSTED (81-100), OK (61-80), SKETCHY (41-60), SUSPICIOUS (21-40), MALICIOUS (0-20).

Override gates: 47 signals across download-and-execute, reverse shells, GTFOBins binary abuse, and variable-concatenated exec escalate directly to MALICIOUS.

## Build

```bash
cargo build --release
```

Binaries: `target/release/bewaur` (CLI) and `target/release/bewaur-hook` (ALPM hook).

## Install local package

```bash
pkgver=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
git archive --format=tar.gz --prefix="bewaur-${pkgver}/" \
  --output="pkg/bewaur-${pkgver}.tar.gz" HEAD
(cd pkg && makepkg -Ccfsi)
```

The local package conflicts with the old `traur` packages so only one ALPM hook
is active. Git operations use SSH (`git@github.com:brickfrog/bewaur.git`), not
HTTPS remotes. HTTPS is acceptable only for web and download metadata.

## Adding a new feature

1. Create `src/features/your_feature/` with `mod.rs` and `CLAUDE.md`
2. Implement the `Feature` trait (return `Vec<Signal>` from `analyze()`)
3. Register in `src/features/mod.rs` (`all_features()`)
4. If pattern-based, add rules to `data/patterns.toml`

## Adding new detection patterns

Edit `data/patterns.toml`. Each pattern has: `id`, `pattern` (regex), `points`, `description`, `override_gate` (bool). Patterns are grouped by feature section name.

## Packaging

`pkg/PKGBUILD` consumes the `pkg/bewaur-<version>.tar.gz` archive generated from
the committed checkout. This is a local-only workflow: there is no AUR sync or
prebuilt binary-release package.

## Key files

| File | Purpose |
|------|---------|
| `src/coordinator.rs` | Orchestrates features and scoring |
| `src/features/mod.rs` | Feature trait + registry |
| `src/shared/scoring.rs` | Score computation, tiers, override gates. Signal has `matched_line: Option<String>` for verbose output |
| `src/shared/aur_rpc.rs` | AUR RPC v5 API client |
| `src/shared/aur_git.rs` | Git clone/pull/diff operations |
| `src/shared/bulk.rs` | Batch metadata fetch, maintainer prefetch, clone-with-retry |
| `src/features/orphan_takeover_analysis/` | Submitter != maintainer detection, orphan takeover composite signal |
| `src/features/shell_analysis/` | Beyond-regex static analysis (var concat, indirect exec, char-by-char, data blobs, binary download) |
| `src/features/gtfobins_analysis/` | GTFOBins-derived patterns (117 patterns for legitimate binary abuse) |
| `src/features/bin_source_verification/` | -bin package source domain vs upstream URL mismatch detection |
| `src/features/pkgbuild_diff_analysis/` | PKGBUILD diff checking: new suspicious patterns, removed checksums, domain changes, major rewrites |
| `src/features/github_stars/` | GitHub stars checking: zero/low stars, repo not found |
| `src/features/aur_comments_analysis/` | AUR comments scanning for security-related keywords |
| `src/shared/github.rs` | GitHub API client (star count, repo existence) |
| `src/shared/aur_comments.rs` | AUR package page comment scraper |
| `src/shared/local_build.rs` | Inert, path-confined Paru build-tree loader for the pre-build gate |
| `src/shared/signal_registry.rs` | Central registry of all signal definitions (pattern + hardcoded) |
| `src/shared/config.rs` | User config: whitelist, ignored signals/categories |
| `data/patterns.toml` | Regex pattern database (239 patterns). Total signals: 279 (pattern + hardcoded) |
| `src/bench.rs` | Batch benchmark (parallel scan, retry, stats) |
| `hook/bewaur.hook` | ALPM hook definition |
| `hook/bewaur-network.hook` | Network opt-in hook for pacman builds that isolate hooks |
| `hook/bewaur-hook.rs` | Hook binary (filters AUR pkgs, runs scans) |

## Pre-build gate

`bewaur gate --build-dir .` is intended for Paru's `PreBuildCommand`. It reads
the exact local PKGBUILD, `.SRCINFO`, referenced install scripts, and bounded
local executable helpers without sourcing shell code. Literal PKGBUILD
`install=` assignments and literal source arrays are checked independently of
`.SRCINFO`; recognizable indirect install mutations fail closed, while arbitrary
dynamic shell/source reconstruction is intentionally not claimed. Helper bytes
are decoded lossily, and inert patches/docs/config are not concatenated as
shell. Unlike the interactive scan command and ALPM hook, the gate blocks
`SKETCHY` and every higher-risk tier, plus all operational errors. A validated
package-base whitelist entry is an explicit total bypass of tree reads and trust
findings.
