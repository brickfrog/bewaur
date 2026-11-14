mod artifact;
mod bench;
mod coordinator;
mod features;
mod shared;

use clap::{Parser, Subcommand};
use std::process;

#[derive(Parser)]
#[command(
    name = "bewaur",
    version,
    about = "Pre-install risk and trust scoring for AUR packages"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a package (or all installed AUR packages if none specified)
    Scan {
        /// Package name to scan (or --pkgbuild for local)
        package: Option<String>,

        /// Scan a local PKGBUILD file offline (only the PKGBUILD itself; use
        /// `gate --build-dir` to include install scripts and helpers)
        #[arg(long, value_name = "FILE")]
        pkgbuild: Option<String>,

        /// Scan all installed AUR packages (default when no package given)
        #[arg(long)]
        all_installed: bool,

        /// Number of concurrent scan threads (for bulk scanning)
        #[arg(long, default_value_t = 4)]
        jobs: usize,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Show the exact line that triggered each signal
        #[arg(short = 'v', long)]
        verbose: bool,

        /// Only show flagged packages (SKETCHY and above)
        #[arg(short = 'f', long)]
        flagged_only: bool,

        /// Send a desktop notification when the installed-package scan flags
        /// packages or fails (for unattended runs from a systemd timer)
        #[arg(long)]
        notify: bool,
    },
    /// Fail-closed scan of the exact local tree before an AUR helper builds it
    Gate {
        /// Paru build directory containing PKGBUILD and .SRCINFO
        #[arg(long, value_name = "DIR")]
        build_dir: std::path::PathBuf,
    },
    /// Approve the exact inert inputs in one fully loaded AUR build tree
    Approve {
        /// Build directory containing PKGBUILD, .SRCINFO, and local inputs
        #[arg(long, value_name = "DIR")]
        build_dir: std::path::PathBuf,

        /// Persist only if the current digest matches a previously reviewed one
        #[arg(long, value_name = "DIGEST")]
        reviewed: Option<String>,
    },
    /// Inspect or prune cached AUR Git repositories
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// Inspect built ALPM package archives without extracting or executing them
    InspectArtifact {
        /// One or more .pkg.tar, .zst, .gz, .xz, or .bz2 package archives
        #[arg(required = true, value_name = "ARCHIVE")]
        archives: Vec<std::path::PathBuf>,

        /// Require every artifact to identify this package base
        #[arg(long, value_name = "PKGBASE")]
        expected_pkgbase: Option<String>,

        /// Emit one machine-readable outcome per artifact
        #[arg(long)]
        json: bool,
    },
    /// Permanently allow a package base by name, across all future tree changes
    Allow {
        /// Package base to allow permanently
        package: String,

        /// Confirm this dangerous name-wide bypass instead of exact-tree approval
        #[arg(long)]
        forever: bool,
    },
    /// List exact-tree approvals and permanent package-base allowances
    Approvals {
        /// Show authorization state for only one package base
        package: Option<String>,
    },
    /// Remove an exact-tree approval, or an explicitly selected permanent one
    Revoke {
        /// Package base whose authorization should be removed
        package: String,

        /// Remove the permanent name-wide allowance instead of the exact tree
        #[arg(long, conflicts_with = "all")]
        forever: bool,

        /// Remove both exact-tree and permanent authorization
        #[arg(long)]
        all: bool,
    },
    /// Benchmark scanning the N most recently modified AUR packages
    Bench {
        /// Number of packages to scan
        #[arg(long, default_value_t = 1000)]
        count: usize,

        /// Number of concurrent scan threads
        #[arg(long, default_value_t = 8)]
        jobs: usize,
    },
    /// List all available signals
    Signals {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Ignore a signal or category (exclude from scoring and output)
    Ignore {
        /// Signal ID to ignore (e.g. P-PYTHON-INLINE)
        signal_id: Option<String>,

        /// Ignore all signals in a category (Metadata, Pkgbuild, Behavioral, Temporal)
        #[arg(long)]
        category: Option<String>,
    },
    /// Unignore a previously ignored signal or category
    Unignore {
        /// Signal ID to restore
        signal_id: Option<String>,

        /// Restore all signals in a category
        #[arg(long)]
        category: Option<String>,
    },
}

#[derive(Subcommand)]
enum CacheCommands {
    /// Show the number and exact size of cached AUR Git repositories
    Stats,
    /// Remove one cached package base, or every entry with an explicit --all
    Clean {
        /// Package base whose cached repository should be removed
        #[arg(
            value_name = "PACKAGE_BASE",
            required_unless_present = "all",
            conflicts_with = "all"
        )]
        package: Option<String>,

        /// Remove every entry from the AUR Git cache
        #[arg(long)]
        all: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Scan {
            package,
            pkgbuild,
            all_installed,
            jobs,
            json,
            verbose,
            flagged_only,
            notify,
        } => cmd_scan(
            package,
            pkgbuild,
            all_installed,
            jobs,
            json,
            verbose,
            flagged_only,
            notify,
        ),
        Commands::Gate { build_dir } => cmd_gate(&build_dir),
        Commands::Approve {
            build_dir,
            reviewed,
        } => cmd_approve(&build_dir, reviewed.as_deref()),
        Commands::Cache { command } => cmd_cache(command),
        Commands::InspectArtifact {
            archives,
            expected_pkgbase,
            json,
        } => cmd_inspect_artifact(&archives, expected_pkgbase.as_deref(), json),
        Commands::Allow { package, forever } => cmd_allow(&package, forever),
        Commands::Approvals { package } => cmd_approvals(package.as_deref()),
        Commands::Revoke {
            package,
            forever,
            all,
        } => cmd_revoke(&package, forever, all),
        Commands::Bench { count, jobs } => bench::run(count, jobs),
        Commands::Signals { json } => cmd_signals(json),
        Commands::Ignore {
            signal_id,
            category,
        } => cmd_ignore(signal_id.as_deref(), category.as_deref()),
        Commands::Unignore {
            signal_id,
            category,
        } => cmd_unignore(signal_id.as_deref(), category.as_deref()),
    };

    process::exit(exit_code);
}

fn cmd_cache(command: CacheCommands) -> i32 {
    match command {
        CacheCommands::Stats => match shared::cache::git_cache_stats() {
            Ok(stats) => {
                println!(
                    "Git cache: {} repositories, {} bytes",
                    stats.repositories, stats.bytes
                );
                0
            }
            Err(error) => {
                eprintln!("bewaur cache: {error}");
                1
            }
        },
        CacheCommands::Clean { package, all } => {
            let package_base = if all { None } else { package.as_deref() };
            match shared::cache::clean_git_cache(package_base) {
                Ok(removed) => {
                    println!("Removed {removed} cached repositories.");
                    0
                }
                Err(error) => {
                    eprintln!("bewaur cache: {error}");
                    1
                }
            }
        }
    }
}

fn cmd_gate(build_dir: &std::path::Path) -> i32 {
    use shared::config::{approved_tree_digest, is_permanently_allowed_in};
    use shared::scoring::Tier;

    let expected_pkgbase = match std::env::var("PKGBASE") {
        Ok(pkgbase) if !pkgbase.is_empty() => pkgbase,
        Ok(_) => {
            eprintln!(
                "bewaur gate: PKGBASE is empty; invoke this command through Paru PreBuildCommand"
            );
            return 1;
        }
        Err(error) => {
            eprintln!(
                "bewaur gate: PKGBASE is unavailable ({error}); invoke this command through Paru PreBuildCommand"
            );
            return 1;
        }
    };

    let manifest = match shared::local_build::load_build_manifest(build_dir, &expected_pkgbase) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("bewaur gate: {error}");
            return 1;
        }
    };

    let config = match shared::config::load_config_strict() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("bewaur gate: {error}");
            return 1;
        }
    };

    if is_permanently_allowed_in(&config, manifest.pkgbase()) {
        eprintln!(
            "bewaur gate: package base {} has a permanent name-wide allowance; allowing build",
            manifest.pkgbase()
        );
        return 0;
    }

    let initial_tree = match shared::local_build::load_build_tree_from_manifest(manifest) {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("bewaur gate: {error}");
            return 1;
        }
    };

    // Bracket a freshly loaded scanner snapshot with full-tree fingerprints.
    // A normal concurrent edit therefore blocks instead of pairing one tree's
    // report with another tree's approval.
    let (tree, result, current_digest) = match inspect_stable_tree(
        initial_tree,
        || shared::local_build::load_build_tree(build_dir, &expected_pkgbase),
        |tree| {
            coordinator::scan_local_build_with_config(
                &tree.pkgbase,
                &tree.pkgbuild_content,
                tree.install_script_content.as_deref(),
                tree.local_source_content.as_deref(),
                &tree.executed_artifacts,
                &config,
            )
        },
    ) {
        Ok(stable) => stable,
        Err(error) => {
            eprintln!("bewaur gate: {error}");
            return 1;
        }
    };
    shared::output::print_text(&result, true);

    let stored_tree_digest = approved_tree_digest(&config, &tree.pkgbase);
    let exact_tree_approved = stored_tree_digest == Some(current_digest.as_str());
    if stored_tree_digest.is_some() && !exact_tree_approved {
        eprintln!(
            "bewaur gate: build inputs for {} changed since approval; applying the current scan policy",
            tree.pkgbase
        );
    }

    if result.tier >= Tier::Sketchy && exact_tree_approved {
        eprintln!(
            "bewaur gate: exact build tree for {} is approved; allowing the reviewed inputs",
            tree.pkgbase
        );
        0
    } else if result.tier >= Tier::Sketchy {
        eprintln!(
            "bewaur gate: {} package blocked before build; review the exact tree and run 'bewaur approve --build-dir .' to approve only these inputs",
            result.tier
        );
        1
    } else {
        0
    }
}

fn inspect_stable_tree<T>(
    initial_tree: shared::local_build::LocalBuildTree,
    reload: impl FnOnce() -> Result<shared::local_build::LocalBuildTree, String>,
    inspect: impl FnOnce(&shared::local_build::LocalBuildTree) -> T,
) -> Result<(shared::local_build::LocalBuildTree, T, String), String> {
    let initial_digest = shared::local_build::fingerprint_build_tree(&initial_tree)
        .map_err(|error| format!("cannot fingerprint build tree: {error}"))?;
    let tree = reload()?;
    let result = inspect(&tree);
    let current_digest = shared::local_build::fingerprint_build_tree(&tree)
        .map_err(|error| format!("cannot fingerprint build tree: {error}"))?;
    if initial_digest != current_digest {
        return Err("build tree changed while it was being scanned or reviewed".to_string());
    }
    Ok((tree, result, current_digest))
}

fn cmd_scan(
    package: Option<String>,
    pkgbuild: Option<String>,
    _all_installed: bool,
    jobs: usize,
    json: bool,
    verbose: bool,
    flagged_only: bool,
    notify: bool,
) -> i32 {
    if let Some(path) = pkgbuild {
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading {path}: {e}");
                return 1;
            }
        };
        let name = std::path::Path::new(&path)
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("local");
        let result = coordinator::scan_pkgbuild(name, &content);
        if json {
            shared::output::print_json(&result);
        } else {
            shared::output::print_text(&result, verbose);
        }
        return if result.tier >= shared::scoring::Tier::Suspicious {
            1
        } else {
            0
        };
    }

    if let Some(pkg) = package {
        return cmd_scan_single(&pkg, json, verbose);
    }

    // No package, no pkgbuild -> scan all installed AUR packages
    cmd_scan_all_installed(jobs, json, verbose, flagged_only, notify)
}

fn cmd_scan_single(pkg: &str, json: bool, verbose: bool) -> i32 {
    match coordinator::scan_package(pkg, json, verbose) {
        Ok(tier) => {
            use shared::scoring::Tier;
            match tier {
                Tier::Trusted | Tier::Ok | Tier::Sketchy => 0,
                Tier::Suspicious | Tier::Malicious => 1,
            }
        }
        Err(e) => {
            eprintln!("Error scanning {pkg}: {e}");
            1
        }
    }
}

fn cmd_scan_all_installed(
    jobs: usize,
    json: bool,
    verbose: bool,
    flagged_only: bool,
    notify: bool,
) -> i32 {
    use crate::shared::bulk::{
        batch_fetch_metadata, clone_with_retry, prefetch_maintainer_packages,
    };
    use crate::shared::scoring::{ScanResult, Tier};
    use colored::Colorize;
    use indicatif::{ProgressBar, ProgressStyle};
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    let names = match get_installed_aur_packages() {
        Ok(names) if names.is_empty() => {
            eprintln!("No AUR packages installed.");
            return 0;
        }
        Ok(names) => names,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    eprintln!(
        "  Fetching package metadata for {} installed packages...",
        names.len()
    );
    let batch = match batch_fetch_metadata(&names) {
        Ok(metadata) => metadata,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };
    if !batch.missing.is_empty() {
        eprintln!(
            "  error: AUR metadata response omitted {} installed foreign package(s): {}",
            batch.missing.len(),
            batch.missing.join(", ")
        );
    }
    let metadata = batch.packages;
    let scan_names: Vec<&String> = names
        .iter()
        .filter(|name| metadata.contains_key(name.as_str()))
        .collect();
    let total = names.len();
    eprintln!(
        "{}",
        format!("Scanning {} of {} foreign packages...", scan_names.len(), total).bold()
    );

    let maintainer_packages = prefetch_maintainer_packages(&metadata);

    let config = shared::config::load_config();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .expect("Failed to build thread pool");

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({per_sec})")
            .unwrap()
            .progress_chars("##-"),
    );

    let tier_counts: [AtomicU64; 5] = std::array::from_fn(|_| AtomicU64::new(0));
    let error_count = AtomicU64::new(batch.missing.len() as u64);
    let flagged = std::sync::Mutex::new(Vec::<ScanResult>::new());
    pb.inc(batch.missing.len() as u64);

    pool.install(|| {
        scan_names.par_iter().for_each(|name| {
            let meta = metadata
                .get(name.as_str())
                .expect("scan names are present in metadata")
                .clone();
            let result = match shared::bulk::maintainer_packages_for(&meta, &maintainer_packages)
                .and_then(|maint_pkgs| clone_with_retry(name, meta, maint_pkgs))
            {
                Ok(ctx) => Ok(coordinator::run_scan_context_with_config(&ctx, &config)),
                Err(e) => Err(e),
            };

            match result {
                Ok(scan) => {
                    let idx = match scan.tier {
                        Tier::Trusted => 0,
                        Tier::Ok => 1,
                        Tier::Sketchy => 2,
                        Tier::Suspicious => 3,
                        Tier::Malicious => 4,
                    };
                    tier_counts[idx].fetch_add(1, Ordering::Relaxed);

                    if !flagged_only || scan.tier >= Tier::Sketchy {
                        flagged.lock().unwrap().push(scan);
                    }
                }
                Err(e) => {
                    eprintln!("  error: {name}: {e}");
                    error_count.fetch_add(1, Ordering::Relaxed);
                }
            }

            pb.inc(1);
        });
    });

    pb.finish_and_clear();

    let mut flagged = flagged.into_inner().unwrap();
    let errors = error_count.load(Ordering::Relaxed) as usize;
    let scanned = total - errors;

    if json {
        flagged.sort_by(|a, b| b.tier.cmp(&a.tier).then(a.score.cmp(&b.score)));
        let json_str = serde_json::to_string_pretty(&flagged).expect("Failed to serialize");
        println!("{json_str}");
    } else {
        println!();
        println!("{}", "=== bewaur scan results ===".bold());
        println!("  Scanned: {} packages ({} errors)", scanned, errors);
        println!(
            "  TRUSTED: {}  OK: {}  SKETCHY: {}  SUSPICIOUS: {}  MALICIOUS: {}",
            tier_counts[0].load(Ordering::Relaxed),
            tier_counts[1].load(Ordering::Relaxed),
            tier_counts[2].load(Ordering::Relaxed),
            tier_counts[3].load(Ordering::Relaxed),
            tier_counts[4].load(Ordering::Relaxed),
        );

        if !flagged.is_empty() {
            flagged.sort_by(|a, b| b.tier.cmp(&a.tier).then(a.score.cmp(&b.score)));
            println!();
            println!(
                "{}",
                format!(
                    "=== {} {} ===",
                    flagged.len(),
                    if flagged_only {
                        "flagged packages (SKETCHY+)"
                    } else {
                        "packages"
                    }
                )
                .bold()
            );
            for result in &flagged {
                println!();
                shared::output::print_text(result, verbose);
            }
        } else {
            println!();
            println!("{}", "All packages look clean.".green());
        }
    }

    if notify {
        notify_flagged(
            tier_counts[2].load(Ordering::Relaxed),
            tier_counts[3].load(Ordering::Relaxed),
            tier_counts[4].load(Ordering::Relaxed),
            errors as u64,
        );
    }

    bulk_scan_exit_code(
        errors,
        tier_counts[3].load(Ordering::Relaxed),
        tier_counts[4].load(Ordering::Relaxed),
    )
}

/// Body for an unattended-scan notification, or `None` when nothing needs
/// attention. Package names are deliberately left out: they are untrusted
/// strings, and the terminal report is where details belong.
fn flagged_notification(
    sketchy: u64,
    suspicious: u64,
    malicious: u64,
    errors: u64,
) -> Option<String> {
    let parts: Vec<String> = [
        (malicious, "MALICIOUS"),
        (suspicious, "SUSPICIOUS"),
        (sketchy, "SKETCHY"),
        (errors, "not scanned"),
    ]
    .iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, label)| format!("{count} {label}"))
    .collect();
    (!parts.is_empty()).then(|| {
        format!(
            "Installed AUR packages need review: {}. Run 'bewaur scan --flagged-only' for details.",
            parts.join(", ")
        )
    })
}

/// Desktop notification for `scan --notify`. Failure to notify (no
/// `notify-send`, no session bus under a system timer) is not an error; the
/// exit status still reports the outcome.
fn notify_flagged(sketchy: u64, suspicious: u64, malicious: u64, errors: u64) {
    let Some(body) = flagged_notification(sketchy, suspicious, malicious, errors) else {
        return;
    };
    let urgency = if suspicious > 0 || malicious > 0 || errors > 0 {
        "--urgency=critical"
    } else {
        "--urgency=normal"
    };
    let _ = std::process::Command::new("notify-send")
        .args([
            urgency,
            "--app-name=bewaur",
            "bewaur: AUR packages need review",
            &body,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Bulk scans are security checks: an unscanned package is a failure just like
/// a suspicious or malicious result.
fn bulk_scan_exit_code(errors: usize, suspicious: u64, malicious: u64) -> i32 {
    if errors > 0 || suspicious > 0 || malicious > 0 {
        1
    } else {
        0
    }
}

/// Get list of installed AUR (foreign) package names via `pacman -Qm`.
fn get_installed_aur_packages() -> Result<Vec<String>, String> {
    use std::process::Command;

    let output = Command::new("pacman")
        .args(["-Qm"])
        .output()
        .map_err(|e| format!("Failed to run pacman: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pacman -Qm failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let names: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().next()?;
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect();

    Ok(names)
}

fn cmd_approve(build_dir: &std::path::Path, reviewed_digest: Option<&str>) -> i32 {
    let config = match shared::config::load_config_strict() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("bewaur approve: {error}");
            return 1;
        }
    };

    let initial_tree = match shared::local_build::load_build_tree_for_approval(build_dir) {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("bewaur approve: {error}");
            return 1;
        }
    };

    let (tree, result, approval_digest) = match inspect_stable_tree(
        initial_tree,
        || shared::local_build::load_build_tree_for_approval(build_dir),
        |tree| {
            coordinator::scan_local_build_with_config(
                &tree.pkgbase,
                &tree.pkgbuild_content,
                tree.install_script_content.as_deref(),
                tree.local_source_content.as_deref(),
                &tree.executed_artifacts,
                &config,
            )
        },
    ) {
        Ok(stable) => stable,
        Err(error) => {
            eprintln!("bewaur approve: {error}");
            return 1;
        }
    };
    shared::output::print_text(&result, true);
    eprintln!("bewaur approve: reviewed local source-tree digest {approval_digest}");
    let Some(reviewed_digest) = reviewed_digest else {
        eprintln!(
            "bewaur approve: approval was not saved; review the report, then rerun with '--reviewed {approval_digest}'"
        );
        return 1;
    };
    if reviewed_digest != approval_digest {
        eprintln!(
            "bewaur approve: reviewed digest does not match the current build tree; no approval was saved"
        );
        eprintln!("  Reviewed: {reviewed_digest}");
        eprintln!("  Current:  {approval_digest}");
        return 1;
    }

    match shared::config::approve_tree(&tree.pkgbase, &approval_digest) {
        Ok(()) => {
            eprintln!("Approved exact build tree: {}", tree.pkgbase);
            eprintln!("  Digest: {approval_digest}");
            eprintln!("  Saved to {}", shared::config::config_path().display());
            0
        }
        Err(error) => {
            eprintln!("bewaur approve: {error}");
            1
        }
    }
}

fn cmd_inspect_artifact(
    archives: &[std::path::PathBuf],
    expected_pkgbase: Option<&str>,
    json: bool,
) -> i32 {
    let config = match shared::config::load_config_strict() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("bewaur inspect-artifact: {error}");
            return 1;
        }
    };
    if let Some(expected) = expected_pkgbase
        && let Err(error) = shared::aur_git::validate_package_name(expected)
    {
        eprintln!("bewaur inspect-artifact: invalid expected package base: {error}");
        return 1;
    }

    let mut outcomes = Vec::with_capacity(archives.len());
    for archive in archives {
        let outcome = match artifact::inspect_artifact(archive, expected_pkgbase, &config) {
            Ok(report) => artifact::ArtifactOutcome::inspected(report),
            Err(error) => artifact::ArtifactOutcome::failed(archive, error),
        };
        outcomes.push(outcome);
    }
    let blocked = outcomes.iter().any(artifact::ArtifactOutcome::blocks);

    if json {
        match serde_json::to_string_pretty(&outcomes) {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("bewaur inspect-artifact: cannot serialize report: {error}");
                return 1;
            }
        }
    } else {
        let stdout = std::io::stdout();
        let mut writer = stdout.lock();
        for (index, outcome) in outcomes.iter().enumerate() {
            if index > 0 {
                use std::io::Write;
                let _ = writeln!(writer);
            }
            if let Some(report) = &outcome.report {
                if let Err(error) = artifact::write_text(report, &mut writer) {
                    eprintln!("bewaur inspect-artifact: cannot write report: {error}");
                    return 1;
                }
            } else if let Some(error) = &outcome.error {
                eprintln!("Artifact: {}", outcome.artifact);
                eprintln!("Error:    {error}");
            }
        }
    }

    if blocked { 1 } else { 0 }
}

fn cmd_allow(package: &str, forever: bool) -> i32 {
    if !forever {
        eprintln!(
            "bewaur allow: refusing a name-wide bypass without --forever; use 'bewaur approve --build-dir .' for an exact-tree approval"
        );
        return 1;
    }

    match shared::config::add_to_permanent_allow(package) {
        Ok(()) => {
            eprintln!("Permanently allowed by package base: {package}");
            eprintln!("  Saved to {}", shared::config::config_path().display());
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

fn cmd_approvals(package: Option<&str>) -> i32 {
    let config = match shared::config::load_config_strict() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("bewaur approvals: {error}");
            return 1;
        }
    };
    if let Some(package) = package
        && let Err(error) = shared::aur_git::validate_package_name(package)
    {
        eprintln!("bewaur approvals: {error}");
        return 1;
    }

    let exact: Vec<_> = config
        .approvals
        .trees
        .iter()
        .filter(|approval| package.is_none_or(|name| name == approval.package_base))
        .collect();
    let permanent: Vec<_> = config
        .permanent_allow
        .packages
        .iter()
        .filter(|candidate| package.is_none_or(|name| name == candidate.as_str()))
        .collect();

    if exact.is_empty() && permanent.is_empty() {
        println!("No matching approvals.");
        return 0;
    }
    for approval in exact {
        println!("exact     {}  {}", approval.package_base, approval.digest);
    }
    for package in permanent {
        println!("permanent {package}");
    }
    0
}

fn cmd_revoke(package: &str, forever: bool, all: bool) -> i32 {
    let result = if all {
        shared::config::revoke_all_approvals(package).map(|(tree, permanent)| {
            format!(
                "Revoked for {package}: exact-tree={}, permanent={}",
                if tree { "yes" } else { "not present" },
                if permanent { "yes" } else { "not present" }
            )
        })
    } else if forever {
        shared::config::revoke_permanent_allow(package).map(|removed| {
            if removed {
                format!("Revoked permanent allowance: {package}")
            } else {
                format!("No permanent allowance existed for: {package}")
            }
        })
    } else {
        shared::config::revoke_tree_approval(package).map(|removed| {
            if removed {
                format!("Revoked exact-tree approval: {package}")
            } else {
                format!("No exact-tree approval existed for: {package}")
            }
        })
    };

    match result {
        Ok(message) => {
            eprintln!("{message}");
            0
        }
        Err(error) => {
            eprintln!("bewaur revoke: {error}");
            1
        }
    }
}

fn cmd_signals(json: bool) -> i32 {
    use shared::scoring::SignalCategory;
    use shared::signal_registry::all_signal_definitions;

    let defs = all_signal_definitions();
    let config = shared::config::load_config();
    let ignored_signals = &config.ignored.signals;
    let ignored_categories = &config.ignored.categories;

    let is_ignored = |d: &shared::signal_registry::SignalDef| -> bool {
        if ignored_signals.contains(&d.id) {
            return true;
        }
        let cat_str = format!("{:?}", d.category);
        ignored_categories
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&cat_str))
    };

    if json {
        let entries: Vec<serde_json::Value> = defs
            .iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id,
                    "category": format!("{:?}", d.category),
                    "description": d.description,
                    "ignored": is_ignored(d),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).expect("Failed to serialize")
        );
        return 0;
    }

    let categories = [
        (SignalCategory::Metadata, "Metadata (weight 0.15)"),
        (SignalCategory::Pkgbuild, "Pkgbuild (weight 0.45)"),
        (SignalCategory::Behavioral, "Behavioral (weight 0.25)"),
        (SignalCategory::Temporal, "Temporal (weight 0.15)"),
    ];

    let mut total = 0;
    let mut ignored_count = 0;

    for (cat, label) in &categories {
        let cat_defs: Vec<_> = defs.iter().filter(|d| d.category == *cat).collect();
        if cat_defs.is_empty() {
            continue;
        }
        println!("\n  {label}");
        for d in &cat_defs {
            let sig_ignored = is_ignored(d);
            let marker = if sig_ignored { " [IGNORED]" } else { "" };
            println!("  {:<36} {}{}", d.id, d.description, marker);
            total += 1;
            if sig_ignored {
                ignored_count += 1;
            }
        }
    }

    println!();
    if ignored_count > 0 {
        println!("  {total} signals ({ignored_count} ignored)");
    } else {
        println!("  {total} signals");
    }
    0
}

fn cmd_ignore(signal_id: Option<&str>, category: Option<&str>) -> i32 {
    match (signal_id, category) {
        (Some(id), None) => {
            if !shared::signal_registry::is_known_signal(id) {
                eprintln!("Unknown signal: {id}");
                eprintln!("Use 'bewaur signals' to list available signal IDs.");
                return 1;
            }
            match shared::config::add_to_ignored(id) {
                Ok(()) => {
                    eprintln!("Ignored: {id}");
                    eprintln!("  Saved to {}", shared::config::config_path().display());
                    0
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    1
                }
            }
        }
        (None, Some(cat)) => {
            if shared::signal_registry::category_from_str(cat).is_none() {
                eprintln!("Unknown category: {cat}");
                eprintln!("Valid categories: Metadata, Pkgbuild, Behavioral, Temporal");
                return 1;
            }
            match shared::config::add_category_to_ignored(cat) {
                Ok(()) => {
                    eprintln!("Ignored category: {cat}");
                    eprintln!("  Saved to {}", shared::config::config_path().display());
                    0
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("Provide either a signal ID or --category, not both.");
            1
        }
    }
}

fn cmd_unignore(signal_id: Option<&str>, category: Option<&str>) -> i32 {
    match (signal_id, category) {
        (Some(id), None) => match shared::config::remove_from_ignored(id) {
            Ok(()) => {
                eprintln!("Unignored: {id}");
                eprintln!("  Saved to {}", shared::config::config_path().display());
                0
            }
            Err(e) => {
                eprintln!("Error: {e}");
                1
            }
        },
        (None, Some(cat)) => {
            if shared::signal_registry::category_from_str(cat).is_none() {
                eprintln!("Unknown category: {cat}");
                eprintln!("Valid categories: Metadata, Pkgbuild, Behavioral, Temporal");
                return 1;
            }
            match shared::config::remove_category_from_ignored(cat) {
                Ok(()) => {
                    eprintln!("Unignored category: {cat}");
                    eprintln!("  Saved to {}", shared::config::config_path().display());
                    0
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("Provide either a signal ID or --category, not both.");
            1
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn notification_only_when_something_needs_attention() {
        assert_eq!(flagged_notification(0, 0, 0, 0), None);
        let body = flagged_notification(2, 0, 1, 3).unwrap();
        assert!(body.contains("1 MALICIOUS"), "{body}");
        assert!(body.contains("2 SKETCHY"), "{body}");
        assert!(body.contains("3 not scanned"), "{body}");
        assert!(!body.contains("SUSPICIOUS"), "{body}");
    }

    use super::{
        bulk_scan_exit_code, flagged_notification, inspect_stable_tree, shared::local_build,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn bulk_scan_fails_closed_when_any_package_cannot_be_scanned() {
        assert_eq!(bulk_scan_exit_code(1, 0, 0), 1);
    }

    #[test]
    fn bulk_scan_preserves_critical_tier_failures() {
        assert_eq!(bulk_scan_exit_code(0, 1, 0), 1);
        assert_eq!(bulk_scan_exit_code(0, 0, 1), 1);
    }

    #[test]
    fn bulk_scan_succeeds_when_every_scan_is_below_suspicious() {
        assert_eq!(bulk_scan_exit_code(0, 0, 0), 0);
    }

    #[test]
    fn stable_tree_inspection_rejects_a_mutation_during_the_scan() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("bewaur-stable-tree-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("PKGBUILD"),
            "pkgname=demo\npkgver=1\npkgrel=1\npackage() { :; }\n",
        )
        .unwrap();
        fs::write(root.join(".SRCINFO"), "pkgbase = demo\n\npkgname = demo\n").unwrap();

        let initial = local_build::load_build_tree(&root, "demo").unwrap();
        let result = inspect_stable_tree(
            initial,
            || local_build::load_build_tree(&root, "demo"),
            |_| {
                fs::write(
                    root.join("PKGBUILD"),
                    "pkgname=demo\npkgver=2\npkgrel=1\npackage() { :; }\n",
                )
                .unwrap();
            },
        );

        assert!(
            result
                .unwrap_err()
                .contains("changed while it was being scanned or reviewed")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
