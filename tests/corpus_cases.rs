//! Offline corpus harness.
//!
//! Two corpora under `tests/corpus/<kind>/<case>/`, each a PKGBUILD plus
//! optional `.install` scripts and committed helper files:
//!
//! - **benign**: real AUR packages. They set the false-positive budget. The
//!   pre-build gate blocks `SKETCHY` and worse, so every benign case declares
//!   `max_tier` (normally `ok`) as a policy, not a snapshot of current output.
//! - **malicious**: incident-derived samples. They set the recall floor with
//!   `min_tier` and the bewaur signal IDs that must fire.
//!
//! The benign corpus and the first malicious samples were imported from the
//! upstream traur project (MIT). CASE expectations are rewritten in bewaur's
//! own signal IDs and tier policy.
//!
//! Contexts are built from file contents only. Nothing is sourced or executed.
//!
//! `CASE` keys: `max_tier`, `min_tier`, `required`, `forbidden` (comma lists),
//! `helpers` (comma list of committed files analysed as executable helpers),
//! `install` (comma list of install scripts; default: every `*.install`),
//! `expect_error` (the gate loader must refuse the tree; needs `.SRCINFO`),
//! and the informational `note`, `revision`.
//!
//! Run `cargo test --test corpus_cases -- --nocapture` for the full report.

use bewaur::coordinator::scan_local_build_with_config;
use bewaur::shared::config::Config;
use bewaur::shared::scoring::{ScanResult, Tier};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
struct Case {
    name: String,
    max_tier: Option<Tier>,
    min_tier: Option<Tier>,
    required: Vec<String>,
    forbidden: Vec<String>,
    helpers: Vec<String>,
    install: Option<Vec<String>>,
    /// The gate loader must refuse the tree with an error containing this.
    expect_error: Option<String>,
}

fn parse_tier(value: &str) -> Tier {
    match value.to_ascii_lowercase().as_str() {
        "trusted" => Tier::Trusted,
        "ok" => Tier::Ok,
        "sketchy" => Tier::Sketchy,
        "suspicious" => Tier::Suspicious,
        "malicious" => Tier::Malicious,
        other => panic!("unknown tier `{other}`"),
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn parse_case(dir: &Path) -> Case {
    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    let text = std::fs::read_to_string(dir.join("CASE"))
        .unwrap_or_else(|error| panic!("{name}: missing CASE file: {error}"));
    let mut case = Case {
        name: name.clone(),
        ..Default::default()
    };
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{name}: malformed CASE line `{line}`"));
        let value = value.trim();
        match key.trim() {
            "max_tier" => case.max_tier = Some(parse_tier(value)),
            "min_tier" => case.min_tier = Some(parse_tier(value)),
            "required" => case.required = split_list(value),
            "forbidden" => case.forbidden = split_list(value),
            "helpers" => case.helpers = split_list(value),
            "install" => case.install = Some(split_list(value)),
            "expect_error" => case.expect_error = Some(value.to_string()),
            "note" | "revision" => {}
            other => panic!("{name}: unknown CASE key `{other}`"),
        }
    }
    case
}

fn case_dirs(kind: &str) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(kind);
    let mut dirs: Vec<_> = std::fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", root.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("PKGBUILD").is_file())
        .collect();
    dirs.sort();
    dirs
}

fn read_joined(dir: &Path, names: &[String]) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    let parts: Vec<String> = names
        .iter()
        .map(|name| {
            let bytes = std::fs::read(dir.join(name))
                .unwrap_or_else(|error| panic!("{}: cannot read {name}: {error}", dir.display()));
            String::from_utf8_lossy(&bytes).into_owned()
        })
        .collect();
    Some(parts.join("\n"))
}

fn load_error(dir: &Path) -> Option<String> {
    let srcinfo = std::fs::read_to_string(dir.join(".SRCINFO")).ok()?;
    let pkgbase = srcinfo
        .lines()
        .find_map(|line| line.trim().strip_prefix("pkgbase = "))?;
    bewaur::shared::local_build::load_build_tree(dir, pkgbase).err()
}

fn scan_case(dir: &Path, case: &Case) -> ScanResult {
    // A case with a `.SRCINFO` goes through the real inert gate loader, so
    // helper discovery, install resolution and artifact detection are tested
    // exactly as `bewaur gate` runs them.
    if let Ok(srcinfo) = std::fs::read_to_string(dir.join(".SRCINFO")) {
        let pkgbase = srcinfo
            .lines()
            .find_map(|line| line.trim().strip_prefix("pkgbase = "))
            .unwrap_or_else(|| panic!("{}: .SRCINFO without pkgbase", case.name));
        let tree = bewaur::shared::local_build::load_build_tree(dir, pkgbase)
            .unwrap_or_else(|error| panic!("{}: gate loader failed: {error}", case.name));
        return scan_local_build_with_config(
            &tree.pkgbase,
            &tree.pkgbuild_content,
            tree.install_script_content.as_deref(),
            tree.local_source_content.as_deref(),
            &tree.executed_artifacts,
            &Config::default(),
        );
    }
    let pkgbuild = std::fs::read_to_string(dir.join("PKGBUILD")).unwrap();
    let install_names = case.install.clone().unwrap_or_else(|| {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".install"))
            .collect();
        names.sort();
        names
    });
    let install = read_joined(dir, &install_names);
    let helpers = read_joined(dir, &case.helpers);
    scan_local_build_with_config(
        &case.name,
        &pkgbuild,
        install.as_deref(),
        helpers.as_deref(),
        &[],
        &Config::default(),
    )
}

fn describe(result: &ScanResult) -> String {
    let ids: Vec<String> = result
        .signals
        .iter()
        .map(|signal| format!("{}({})", signal.id, signal.points))
        .collect();
    format!("{:?} {} [{}]", result.tier, result.score, ids.join(", "))
}

fn check(kind: &str) {
    let mut failures = Vec::new();
    for dir in case_dirs(kind) {
        let case = parse_case(&dir);
        if let Some(expected) = &case.expect_error {
            match load_error(&dir) {
                Some(error) if error.contains(expected.as_str()) => {
                    eprintln!("{kind}/{}: refused: {error}", case.name);
                }
                other => failures.push(format!(
                    "{kind}/{}: expected loader error containing {expected:?}, got {other:?}",
                    case.name
                )),
            }
            continue;
        }
        if kind == "benign" {
            assert!(
                case.max_tier.is_some(),
                "{}: benign case needs max_tier",
                case.name
            );
        } else {
            assert!(
                case.min_tier.is_some() && !case.required.is_empty(),
                "{}: malicious case needs min_tier and required",
                case.name
            );
        }
        let result = scan_case(&dir, &case);
        eprintln!("{kind}/{}: {}", case.name, describe(&result));

        let mut problems = Vec::new();
        if let Some(max) = case.max_tier
            && result.tier > max
        {
            problems.push(format!("tier {:?} is worse than max {max:?}", result.tier));
        }
        if let Some(min) = case.min_tier
            && result.tier < min
        {
            problems.push(format!("tier {:?} is better than min {min:?}", result.tier));
        }
        for id in &case.required {
            if !result.signals.iter().any(|signal| &signal.id == id) {
                problems.push(format!("required signal {id} missing"));
            }
        }
        for id in &case.forbidden {
            if result.signals.iter().any(|signal| &signal.id == id) {
                problems.push(format!("forbidden signal {id} fired"));
            }
        }
        if !problems.is_empty() {
            failures.push(format!(
                "{kind}/{}: {} -> {}",
                case.name,
                problems.join("; "),
                describe(&result)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "corpus failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn benign_corpus_stays_within_the_false_positive_budget() {
    check("benign");
}

#[test]
fn malicious_corpus_meets_the_recall_floor() {
    check("malicious");
}
