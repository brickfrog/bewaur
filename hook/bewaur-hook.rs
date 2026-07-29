//! bewaur-hook: ALPM pre-transaction hook binary.
//! Reads package names from stdin (passed by pacman/paru via NeedsTargets),
//! filters to AUR-only packages, scans each silently, then shows a summary.
//! Detail is only printed for SKETCHY+ packages. No prompt when all clean.
//!
//! Interactive output and confirmation use /dev/tty. When no controlling
//! terminal is available, output falls back to stderr and the hook still scans;
//! any result that would require confirmation is blocked.

use bewaur::coordinator;
use bewaur::shared::bulk;
use bewaur::shared::config::{self, is_permanently_allowed_in};
use bewaur::shared::output;
use bewaur::shared::scoring::{ScanResult, Tier};
use colored::Colorize;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::process::Command;

enum HookIo {
    Interactive(File),
    NonInteractive(io::Stderr),
}

impl HookIo {
    fn open() -> Self {
        match OpenOptions::new().read(true).write(true).open("/dev/tty") {
            Ok(tty) => Self::Interactive(tty),
            Err(_) => Self::NonInteractive(io::stderr()),
        }
    }

    fn is_interactive(&self) -> bool {
        matches!(self, Self::Interactive(_))
    }

    fn read_line(&mut self, line: &mut String) -> io::Result<usize> {
        match self {
            Self::Interactive(tty) => BufReader::new(tty).read_line(line),
            Self::NonInteractive(_) => Ok(0),
        }
    }
}

impl Write for HookIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Interactive(tty) => tty.write(buf),
            Self::NonInteractive(stderr) => stderr.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Interactive(tty) => tty.flush(),
            Self::NonInteractive(stderr) => stderr.flush(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum GateDecision {
    Allow,
    BlockMalicious,
    BlockScanErrors,
    BlockFlaggedNonInteractive,
    PromptFlagged,
}

fn gate_decision(tier_counts: &[u32; 5], has_scan_errors: bool, interactive: bool) -> GateDecision {
    if tier_counts[4] > 0 {
        GateDecision::BlockMalicious
    } else if has_scan_errors {
        GateDecision::BlockScanErrors
    } else if tier_counts[2] > 0 || tier_counts[3] > 0 {
        if interactive {
            GateDecision::PromptFlagged
        } else {
            GateDecision::BlockFlaggedNonInteractive
        }
    } else {
        GateDecision::Allow
    }
}

fn read_targets(reader: impl BufRead) -> Result<Vec<String>, String> {
    reader
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| {
            lines
                .into_iter()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect()
        })
        .map_err(|error| format!("failed to read ALPM target list: {error}"))
}

fn main() {
    // Collect all package names from stdin (ALPM NeedsTargets)
    let stdin = io::stdin();
    let packages = match read_targets(stdin.lock()) {
        Ok(packages) => packages,
        Err(error) => {
            eprintln!("bewaur: {error} — blocking transaction");
            std::process::exit(1);
        }
    };

    if packages.is_empty() {
        return;
    }

    // Filter to AUR-only packages (single pacman -Sl call instead of per-package -Si)
    let official = official_repo_packages();
    let aur_packages: Vec<String> = packages
        .into_iter()
        .filter(|pkg| !official.contains(pkg.as_str()))
        .collect();

    if aur_packages.is_empty() {
        return;
    }

    // A controlling terminal gives immediate hook output and an independent
    // confirmation channel. Without one, continue fail-closed using stderr.
    let mut hook_io = HookIo::open();
    let interactive = hook_io.is_interactive();
    colored::control::set_override(interactive);

    let config = match config::load_config_strict() {
        Ok(config) => config,
        Err(error) => {
            let _ = writeln!(
                hook_io,
                "{}",
                format!(
                    "bewaur: invalid or unreadable security config — blocking transaction: {error}"
                )
                .red()
                .bold()
            );
            std::process::exit(1);
        }
    };

    let _ = writeln!(
        hook_io,
        "{}",
        r#"
  ╔╗ ╔═╗╦ ╦╔═╗╦ ╦╦═╗
  ╠╩╗║╣ ║║║╠═╣║ ║╠╦╝
  ╚═╝╚═╝╚╩╝╩ ╩╚═╝╩╚═"#
            .red()
            .bold()
    );
    let _ = writeln!(hook_io, "  {}", "Trust scoring for AUR packages".dimmed());
    let _ = writeln!(hook_io);

    // --- Phase 1: Collect results silently ---

    // Batch-fetch metadata for every non-official target. Omissions remain
    // explicit security decisions rather than silently becoming local-only packages.
    let batch = match bulk::batch_fetch_metadata(&aur_packages) {
        Ok(metadata) => metadata,
        Err(e) => {
            let _ = writeln!(hook_io, "{}", format!("  error: {e}").red());
            let _ = writeln!(
                hook_io,
                "{}",
                "bewaur: AUR metadata could not be fetched — blocking transaction"
                    .red()
                    .bold()
            );
            std::process::exit(1);
        }
    };
    let metadata = batch.packages;
    // Exact-tree approvals apply only to the Paru pre-build gate. Resolve each
    // transaction package to its AUR package base before applying the explicit
    // permanent allowance, so split-package outputs behave consistently. If
    // metadata is absent, only an allowance for the exact transaction name can
    // authorize the otherwise unscanned package.
    let (mut permanently_allowed_count, mut scan_errors) =
        missing_metadata_decisions(&config, &batch.missing);
    let scan_packages: Vec<String> = aur_packages
        .into_iter()
        .filter(|name| {
            let Some(package) = metadata.get(name.as_str()) else {
                return false;
            };
            if transaction_has_permanent_allowance(&config, package.package_base.as_deref()) {
                permanently_allowed_count += 1;
                false
            } else {
                true
            }
        })
        .collect();

    let any_scanned = !scan_packages.is_empty();
    let total_scan = scan_packages.len();

    // Pre-fetch maintainer data for all packages
    let maintainer_packages = bulk::prefetch_maintainer_packages(&metadata);

    let mut results: Vec<ScanResult> = Vec::new();
    let mut tier_counts: [u32; 5] = [0, 0, 0, 0, 0]; // Trusted, Ok, Sketchy, Suspicious, Malicious

    for (i, pkg) in scan_packages.iter().enumerate() {
        // Progress indicator (single line, overwritten each iteration)
        let _ = write!(
            hook_io,
            "\r  Scanning {} ({}/{})...          ",
            pkg,
            i + 1,
            total_scan
        );
        let _ = hook_io.flush();

        let meta = metadata.get(pkg.as_str()).cloned().unwrap();
        let maint_pkgs = meta
            .maintainer
            .as_deref()
            .and_then(|m| maintainer_packages.get(m))
            .cloned()
            .unwrap_or_default();

        match bulk::clone_with_retry(pkg, meta, maint_pkgs) {
            Ok(ctx) => {
                let result = coordinator::run_scan_context_with_config(&ctx, &config);
                let idx = match result.tier {
                    Tier::Trusted => 0,
                    Tier::Ok => 1,
                    Tier::Sketchy => 2,
                    Tier::Suspicious => 3,
                    Tier::Malicious => 4,
                };
                tier_counts[idx] += 1;
                results.push(result);
            }
            Err(e) => {
                scan_errors.push((pkg.clone(), e));
            }
        }
    }

    // Clear the progress line
    let _ = write!(hook_io, "\r{}\r", " ".repeat(72));
    let _ = hook_io.flush();

    // --- Phase 2: Output + decision ---

    // Case 1: All permanently allowed
    if !any_scanned && scan_errors.is_empty() {
        if permanently_allowed_count > 0 {
            let _ = writeln!(
                hook_io,
                "  {} package(s) permanently allowed, nothing to scan.",
                permanently_allowed_count
            );
        }
        return;
    }

    // Print tier summary
    let scanned: u32 = tier_counts.iter().sum();
    let _ = writeln!(hook_io, "  Scanned: {} package(s)", scanned);

    let tier_labels = [
        ("TRUSTED", tier_counts[0]),
        ("OK", tier_counts[1]),
        ("SKETCHY", tier_counts[2]),
        ("SUSPICIOUS", tier_counts[3]),
        ("MALICIOUS", tier_counts[4]),
    ];
    let tier_parts: Vec<String> = tier_labels
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(label, count)| {
            let colored_label = match *label {
                "TRUSTED" => label.green().to_string(),
                "OK" => label.yellow().to_string(),
                "SKETCHY" => label.truecolor(255, 165, 0).to_string(),
                "SUSPICIOUS" => label.red().to_string(),
                "MALICIOUS" => label.red().bold().to_string(),
                _ => label.to_string(),
            };
            format!("{}: {}", colored_label, count)
        })
        .collect();
    if !tier_parts.is_empty() {
        let _ = writeln!(hook_io, "  {}", tier_parts.join("  "));
    }

    // Full detail for all results
    if !results.is_empty() {
        results.sort_by(|a, b| a.score.cmp(&b.score));
        for result in &results {
            let _ = writeln!(hook_io);
            output::write_text(&mut hook_io, result, false);
        }
    }

    // Print scan errors
    if !scan_errors.is_empty() {
        let _ = writeln!(hook_io);
        for (pkg, err) in &scan_errors {
            let _ = writeln!(hook_io, "{}", format!("  error: {pkg}: {err}").red());
        }
    }

    match gate_decision(&tier_counts, !scan_errors.is_empty(), interactive) {
        // Case 2: MALICIOUS detected -> hard block, needs explicit authorization
        GateDecision::BlockMalicious => {
            let _ = writeln!(hook_io);
            let _ = writeln!(
                hook_io,
                "{}",
                "bewaur: MALICIOUS package(s) detected — blocking transaction"
                    .red()
                    .bold()
            );
            let _ = writeln!(
                hook_io,
                "bewaur: return to the reviewed Paru build directory and run 'bewaur approve --build-dir .'; use 'bewaur allow <package-base> --forever' only for a name-wide bypass"
            );
            std::process::exit(1);
        }
        // Case 3: Scan errors -> hard block (fail closed)
        GateDecision::BlockScanErrors => {
            let _ = writeln!(hook_io);
            let _ = writeln!(
                hook_io,
                "{}",
                "bewaur: scan errors occurred — blocking transaction"
                    .red()
                    .bold()
            );
            let _ = writeln!(
                hook_io,
                "bewaur: fix the scan error, or use 'bewaur allow <package-base> --forever' for an explicit name-wide bypass"
            );
            std::process::exit(1);
        }
        // Case 4a: SKETCHY/SUSPICIOUS without a tty -> hard block. Reading
        // ALPM's stdin here would consume target data, not user confirmation.
        GateDecision::BlockFlaggedNonInteractive => {
            let _ = writeln!(hook_io);
            let _ = writeln!(
                hook_io,
                "{}",
                "bewaur: package(s) require confirmation, but no interactive terminal is available — blocking transaction"
                    .red()
                    .bold()
            );
            std::process::exit(1);
        }
        // Case 4b: SKETCHY or SUSPICIOUS with a tty -> prompt [y/N]
        GateDecision::PromptFlagged => {
            let _ = writeln!(hook_io);
            let _ = write!(
                hook_io,
                "{} ",
                "bewaur: Continue with installation? [y/N]".bold()
            );
            let _ = hook_io.flush();

            let mut line = String::new();
            let response = match hook_io.read_line(&mut line) {
                Ok(0) => "",
                Ok(_) => line.trim(),
                Err(_) => "",
            };

            let proceed = matches!(response.to_lowercase().as_str(), "y" | "yes");

            if !proceed {
                let _ = writeln!(hook_io, "bewaur: aborting transaction");
                std::process::exit(1);
            }
        }
        // Case 5: All clean -> no prompt
        GateDecision::Allow => {
            let _ = writeln!(hook_io, "\n  {}", "All packages look clean.".green());
        }
    }
}

fn transaction_has_permanent_allowance(
    config: &config::Config,
    package_base: Option<&str>,
) -> bool {
    package_base.is_some_and(|package_base| is_permanently_allowed_in(config, package_base))
}

fn missing_metadata_decisions(
    config: &config::Config,
    missing: &[String],
) -> (u32, Vec<(String, String)>) {
    let mut allowed = 0u32;
    let mut errors = Vec::new();
    for name in missing {
        if is_permanently_allowed_in(config, name) {
            allowed += 1;
        } else {
            errors.push((
                name.clone(),
                "AUR metadata response omitted this non-official transaction target".to_string(),
            ));
        }
    }
    (allowed, errors)
}

/// Get all package names from official sync databases in one call.
/// Output format: "repo package_name version [installed]"
fn official_repo_packages() -> HashSet<String> {
    Command::new("pacman")
        .arg("-Sl")
        .output()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| line.split_whitespace().nth(1).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn noninteractive_flagged_results_block_instead_of_prompting() {
        assert_eq!(
            gate_decision(&[0, 0, 1, 0, 0], false, false),
            GateDecision::BlockFlaggedNonInteractive
        );
        assert_eq!(
            gate_decision(&[0, 0, 0, 1, 0], false, false),
            GateDecision::BlockFlaggedNonInteractive
        );
    }

    #[test]
    fn interactive_flagged_results_still_prompt() {
        assert_eq!(
            gate_decision(&[0, 0, 1, 0, 0], false, true),
            GateDecision::PromptFlagged
        );
    }

    #[test]
    fn noninteractive_clean_results_are_allowed() {
        assert_eq!(
            gate_decision(&[1, 1, 0, 0, 0], false, false),
            GateDecision::Allow
        );
    }

    #[test]
    fn operational_errors_and_malicious_results_block_in_every_mode() {
        for interactive in [false, true] {
            assert_eq!(
                gate_decision(&[0, 0, 0, 0, 0], true, interactive),
                GateDecision::BlockScanErrors
            );
            assert_eq!(
                gate_decision(&[0, 0, 0, 0, 1], false, interactive),
                GateDecision::BlockMalicious
            );
        }
    }

    #[test]
    fn permanent_allowance_uses_the_aur_package_base_for_split_outputs() {
        let mut config = config::Config::default();
        config.permanent_allow.packages.push("demo".to_string());

        assert!(transaction_has_permanent_allowance(&config, Some("demo")));
        assert!(!transaction_has_permanent_allowance(
            &config,
            Some("other-base")
        ));
        assert!(!transaction_has_permanent_allowance(&config, None));
    }

    #[test]
    fn target_stream_errors_fail_closed_instead_of_dropping_packages() {
        let error = read_targets(Cursor::new(b"valid\ninvalid-\xff\n")).unwrap_err();
        assert!(error.contains("failed to read ALPM target list"), "{error}");
    }

    #[test]
    fn missing_metadata_requires_an_exact_permanent_allowance() {
        let mut config = config::Config::default();
        config
            .permanent_allow
            .packages
            .push("allowed-local".to_string());
        let missing = vec!["blocked-local".to_string(), "allowed-local".to_string()];

        let (allowed, errors) = missing_metadata_decisions(&config, &missing);

        assert_eq!(allowed, 1);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "blocked-local");
        assert!(errors[0].1.contains("omitted"));
    }
}
