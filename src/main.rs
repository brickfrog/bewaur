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

        /// Scan a local PKGBUILD directory
        #[arg(long)]
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
    },
    /// Fail-closed scan of the exact local tree before an AUR helper builds it
    Gate {
        /// Paru build directory containing PKGBUILD and .SRCINFO
        #[arg(long, value_name = "DIR")]
        build_dir: std::path::PathBuf,
    },
    /// Inspect or prune cached AUR Git repositories
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// Whitelist a package (skip future scans)
    Allow {
        /// Package name to whitelist
        package: String,
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
        } => cmd_scan(
            package,
            pkgbuild,
            all_installed,
            jobs,
            json,
            verbose,
            flagged_only,
        ),
        Commands::Gate { build_dir } => cmd_gate(&build_dir),
        Commands::Cache { command } => cmd_cache(command),
        Commands::Allow { package } => cmd_allow(&package),
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
    use shared::config::is_whitelisted_in;
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

    if is_whitelisted_in(&config, manifest.pkgbase()) {
        eprintln!(
            "bewaur gate: package base {} is whitelisted; allowing build",
            manifest.pkgbase()
        );
        return 0;
    }

    let tree = match shared::local_build::load_build_tree_from_manifest(manifest) {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("bewaur gate: {error}");
            return 1;
        }
    };

    let result = coordinator::scan_local_build_with_config(
        &tree.pkgbase,
        &tree.pkgbuild_content,
        tree.install_script_content.as_deref(),
        tree.local_source_content.as_deref(),
        &config,
    );
    shared::output::print_text(&result, true);

    if result.tier >= Tier::Sketchy {
        eprintln!(
            "bewaur gate: {} package blocked before build; review the findings or run 'bewaur allow {}' to bypass",
            result.tier, tree.pkgbase
        );
        1
    } else {
        0
    }
}

fn cmd_scan(
    package: Option<String>,
    pkgbuild: Option<String>,
    _all_installed: bool,
    jobs: usize,
    json: bool,
    verbose: bool,
    flagged_only: bool,
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
    cmd_scan_all_installed(jobs, json, verbose, flagged_only)
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

fn cmd_scan_all_installed(jobs: usize, json: bool, verbose: bool, flagged_only: bool) -> i32 {
    use crate::shared::bulk::{
        batch_fetch_metadata, clone_with_retry, prefetch_maintainer_packages,
    };
    use crate::shared::scoring::{ScanResult, Tier};
    use colored::Colorize;
    use indicatif::{ProgressBar, ProgressStyle};
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut names = match get_installed_aur_packages() {
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
    let metadata = match batch_fetch_metadata(&names) {
        Ok(metadata) => metadata,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };
    let not_found: Vec<&str> = names
        .iter()
        .filter(|n| !metadata.contains_key(n.as_str()))
        .map(|n| n.as_str())
        .collect();
    if !not_found.is_empty() {
        eprintln!(
            "  Skipping {} not on AUR: {}",
            not_found.len(),
            not_found.join(", ")
        );
        names.retain(|n| metadata.contains_key(n.as_str()));
    }
    let total = names.len();
    eprintln!("{}", format!("Scanning {} AUR packages...", total).bold());

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
    let error_count = AtomicU64::new(0);
    let flagged = std::sync::Mutex::new(Vec::<ScanResult>::new());

    pool.install(|| {
        names.par_iter().for_each(|name| {
            let result = if let Some(meta) = metadata.get(name).cloned() {
                let maint_pkgs = meta
                    .maintainer
                    .as_deref()
                    .and_then(|m| maintainer_packages.get(m))
                    .cloned()
                    .unwrap_or_default();

                match clone_with_retry(name, meta, maint_pkgs) {
                    Ok(ctx) => Ok(coordinator::run_scan_context_with_config(&ctx, &config)),
                    Err(e) => Err(e),
                }
            } else {
                Err("not found on AUR".to_string())
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
        flagged.sort_by(|a, b| a.score.cmp(&b.score));
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
            flagged.sort_by(|a, b| a.score.cmp(&b.score));
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

    bulk_scan_exit_code(
        errors,
        tier_counts[3].load(Ordering::Relaxed),
        tier_counts[4].load(Ordering::Relaxed),
    )
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

fn cmd_allow(package: &str) -> i32 {
    match shared::config::add_to_whitelist(package) {
        Ok(()) => {
            eprintln!("Whitelisted: {package}");
            eprintln!("  Saved to {}", shared::config::config_path().display());
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
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
    use super::bulk_scan_exit_code;

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
}
