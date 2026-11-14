# Shared Components

Reusable modules consumed by features and the coordinator. Code goes here if it's used by 2+ features or by the coordinator.

## Modules

| Module | Purpose | Used by |
|--------|---------|---------|
| `models.rs` | `PackageContext` (with `github_stars`, `github_not_found`, `aur_comments`), `AurPackage`, `GitCommit` | All features |
| `aur_rpc.rs` | AUR RPC v5 API client (reqwest, blocking; encoded queries and bounded HTTP diagnostics) | coordinator, metadata, maintainer, name features |
| `aur_git.rs` | Strict AUR Git refresh to an explicitly fetched `master`, dirty/stale cache rejection, and diff/log operations | coordinator, pkgbuild, install_script, git_history features |
| `scoring.rs` | `Signal`, `SignalCategory`, `Tier`, `TierFloor`, `ScanResult`, `hard_findings()`, `compute_score_with()` | coordinator |
| `aur_identity.rs` | Normalized identity comparison across the AUR-account and git-author-display-name namespaces, with a raw fallback when normalization empties a key | orphan_takeover, pkgbuild_diff features |
| `patterns.rs` | Load TOML pattern rules, compile to regex | pkgbuild, install_script, source_url, gtfobins features |
| `cache.rs` | XDG cache paths plus non-symlink-following stats and validated, explicit Git-cache pruning | aur_git, aur_rpc, CLI |
| `config.rs` | Versioned strict config with exact/permanent authorization, exclusive update locking, atomic replacement, and private permissions | coordinator, gate, hook, CLI |
| `output.rs` | Terminal-control-safe colored text plus JSON formatting for ScanResult | coordinator (via main.rs) |
| `bulk.rs` | Count/URL-bounded metadata fetch with explicit omitted-name results, bounded-concurrency maintainer prefetch with retry (a failed lookup is a scan error, never an empty list), clone-with-retry | bench, cmd_scan_all_installed, ALPM hook, coordinator |
| `github.rs` | GitHub API client (star count, repo existence). Supports `GITHUB_TOKEN` env var for higher rate limits | coordinator, github_stars feature |
| `aur_comments.rs` | AUR package page HTML scraper for comment extraction | coordinator, aur_comments_analysis feature |
| `js_package_manager.rs` | Non-executing active-shell parsing with iterative executable-heredoc traversal for named JS installs, June incident IOCs, dependency arrays, and privileged chmod/install modes with their targets (bundled `-Dm4755` included) | pkgbuild, install_script, pkgbuild_diff, gtfobins features |
| `local_build.rs` | Inert `.SRCINFO`/PKGBUILD/install loader, bounded lossy helper discovery including process substitutions, code-loading interpreter options, and interpreter stdin files, canonical path confinement, conservative literal-variable resolution, checksum-pinned downloaded-artifact detection, and versioned full-tree fingerprints | pre-build gate, network-backed scans, exact approvals |
| `shell_syntax.rs` | Non-executing, parameter-expansion-aware shell comment and command-word lexer; prose-safe quote-fragment joining; multi-stage pipeline and command/process-substitution composition detection | pattern, GTFOBins and shell analysis |
| `signal_registry.rs` | Central registry of all signal definitions (pattern + hardcoded) | cmd_signals, cmd_ignore |

## When to put code here vs in a feature

- **Here**: Generic utilities, API clients, data types, scoring logic
- **Feature**: Analysis logic specific to one concern (even if it calls shared code)
