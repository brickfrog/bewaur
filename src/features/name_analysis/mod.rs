use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use std::sync::LazyLock;
use strsim::levenshtein;

/// Suspicious suffixes that indicate impersonation attempts.
const IMPERSONATION_SUFFIXES: &[&str] = &[
    "-fix", "-fixed", "-patch", "-patched", "-updated", "-secure", "-plus", "-mod", "-modded",
    "-pro", "-premium", "-free", "-cracked", "-hack", "-custom", "-lite",
];

/// Popular brand names commonly targeted for impersonation.
const BRAND_NAMES: &[&str] = &[
    "firefox",
    "chromium",
    "chrome",
    "brave",
    "librewolf",
    "zen-browser",
    "discord",
    "slack",
    "telegram",
    "signal",
    "vscode",
    "code",
    "steam",
    "spotify",
    "obsidian",
    "1password",
    "bitwarden",
    "keepass",
    "vlc",
    "mpv",
    "neovim",
    "gimp",
    "blender",
    "thunderbird",
    "protonvpn",
    "mullvad",
    "nordvpn",
    "tor-browser",
];

static TOP_PACKAGES: LazyLock<Vec<String>> = LazyLock::new(|| {
    [
        "yay",
        "paru",
        "google-chrome",
        "spotify",
        "visual-studio-code-bin",
        "brave-bin",
        "discord",
        "slack-desktop",
        "zoom",
        "teams",
        "librewolf-bin",
        "zen-browser-bin",
        "firefox",
        "chromium",
        "steam",
        "lutris",
        "mangohud",
        "gamemode",
        "proton-ge-custom",
        "timeshift",
        "pamac-aur",
        "octopi",
        "downgrade",
        "nerd-fonts-complete",
        "ttf-ms-fonts",
        "obs-studio",
        "vlc",
        "mpv",
        "neovim",
        "vim",
        "emacs",
        "gimp",
        "blender",
        "thunderbird",
        "protonvpn",
        "mullvad-vpn",
        "nordvpn-bin",
        "tor-browser",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
});

/// Hyphen-separated tokens that denote a build or packaging variant of the
/// same upstream project rather than a different project.
const VARIANT_TOKENS: &[&str] = &[
    "git", "bin", "svn", "hg", "bzr", "nightly", "beta", "dev", "stable", "lts", "appimage",
    "wayland", "x11", "qt", "qt5", "qt6", "gtk", "gtk3", "gtk4", "nvidia", "vulkan", "full", "cli",
    "desktop", "legacy", "electron", "native",
];

/// Ecosystem prefixes for bindings, plugins and multilib builds that embed an
/// upstream name without impersonating it (`python-steam`, `lib32-mpv`).
const BINDING_PREFIXES: &[&str] = &[
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "nodejs",
    "node",
    "go",
    "rust",
    "haskell",
    "ocaml",
    "lua",
    "r",
    "lib32",
    "lib",
    "ttf",
    "otf",
    "vim",
    "neovim",
    "emacs",
    "kodi-addon",
    "gnome-shell-extension",
    "obs",
    "mpv",
    "firefox-extension",
    "steam",
];

/// Whether every hyphen-separated token of `rest` is a known variant token.
fn only_variant_tokens(rest: &str) -> bool {
    !rest.is_empty() && rest.split('-').all(|token| VARIANT_TOKENS.contains(&token))
}

/// `name` is `top` plus variant tokens (`vim-git`, `proton-ge-custom-bin`,
/// `slack-desktop-wayland`) or a binding prefix plus `top` (`python-steam`).
fn is_legitimate_variant(name: &str, top: &str) -> bool {
    if let Some(rest) = name
        .strip_prefix(top)
        .and_then(|rest| rest.strip_prefix('-'))
        && only_variant_tokens(rest)
    {
        return true;
    }
    name.strip_suffix(top)
        .and_then(|prefix| prefix.strip_suffix('-'))
        .is_some_and(|prefix| BINDING_PREFIXES.contains(&prefix))
}

/// Strip trailing variant tokens: `pary-bin` -> `pary`.
fn strip_variant_suffixes(name: &str) -> &str {
    let mut base = name;
    while let Some((head, token)) = base.rsplit_once('-')
        && VARIANT_TOKENS.contains(&token)
        && !head.is_empty()
    {
        base = head;
    }
    base
}

pub struct NameAnalysis;

impl Feature for NameAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        if let Some(ref meta) = ctx.metadata {
            if meta.num_votes >= 10 {
                return Vec::new();
            }
        }

        let mut signals = Vec::new();
        let name = &ctx.name;

        // Check impersonation suffixes against brand names
        for brand in BRAND_NAMES {
            for suffix in IMPERSONATION_SUFFIXES {
                let impersonation = format!("{brand}{suffix}");
                if name == &impersonation
                    || name == &format!("{impersonation}-bin")
                    || name == &format!("{impersonation}-git")
                {
                    signals.push(Signal {
                        id: "B-NAME-IMPERSONATE".to_string(),
                        category: SignalCategory::Behavioral,
                        points: 65,
                        description: format!(
                            "Name '{name}' looks like impersonation of '{brand}' with suspicious suffix"
                        ),
                        is_override_gate: false,
                        matched_line: None,
                        min_tier: None,
                    });
                    // Only fire once per package
                    return signals;
                }
            }
        }

        // Check typosquatting against top packages, also after removing
        // variant suffixes so `pary-bin` is compared as `pary`.
        let base = strip_variant_suffixes(name);
        for top in TOP_PACKAGES.iter() {
            if top == name || is_legitimate_variant(name, top) {
                continue;
            }
            // The stripped comparison skips very short names (`yay`, `vim`,
            // `mpv`), where one edit already lands on unrelated projects.
            let dist = levenshtein(name, top).min(if base == name.as_str() || top.len() < 4 {
                usize::MAX
            } else {
                levenshtein(base, top)
            });
            if dist == 1 {
                signals.push(Signal {
                    id: "B-TYPOSQUAT".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 55,
                    description: format!(
                        "Name '{name}' is {dist} edit(s) away from popular package '{top}'"
                    ),
                    is_override_gate: false,
                    matched_line: None,
                    min_tier: None,
                });
                break;
            }
        }

        // Check if name embeds a popular package as prefix/suffix (no hyphen boundary)
        for top in TOP_PACKAGES.iter() {
            if name == top.as_str() || name.len() <= top.len() || is_legitimate_variant(name, top) {
                continue;
            }
            let is_prefix = name.starts_with(top.as_str());
            let is_suffix = name.ends_with(top.as_str());
            if is_prefix || is_suffix {
                signals.push(Signal {
                    id: "B-TYPOSQUAT".to_string(),
                    category: SignalCategory::Behavioral,
                    points: 55,
                    description: format!("Name '{name}' embeds popular package '{top}'"),
                    is_override_gate: false,
                    matched_line: None,
                    min_tier: None,
                });
                break;
            }
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(name: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: name.into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        NameAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    fn analyze_with_votes(name: &str, votes: u32) -> Vec<String> {
        use crate::shared::models::AurPackage;
        let ctx = PackageContext {
            name: name.into(),
            metadata: Some(AurPackage {
                name: name.into(),
                package_base: None,
                url: None,
                num_votes: votes,
                popularity: 0.0,
                out_of_date: None,
                maintainer: None,
                submitter: None,
                first_submitted: 0,
                last_modified: 0,
                license: None,
            }),
            pkgbuild_content: None,
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        NameAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    #[test]
    fn impersonate_suffix() {
        assert!(has(&analyze("firefox-fix"), "B-NAME-IMPERSONATE"));
        assert!(has(&analyze("discord-cracked-bin"), "B-NAME-IMPERSONATE"));
        assert!(has(&analyze("librewolf-patched-bin"), "B-NAME-IMPERSONATE"));
    }

    #[test]
    fn typosquat_edit_distance() {
        assert!(has(&analyze("pary"), "B-TYPOSQUAT")); // 1 edit from "paru"
        assert!(
            !has(&analyze("rad"), "B-TYPOSQUAT"),
            "2 edits from 'yay', should not flag"
        );
    }

    #[test]
    fn typosquat_containment() {
        assert!(has(&analyze("yay2"), "B-TYPOSQUAT")); // prefix
        assert!(has(&analyze("2vim"), "B-TYPOSQUAT")); // suffix
        assert!(has(&analyze("yay-bin2"), "B-TYPOSQUAT")); // prefix, unknown variant
        assert!(has(&analyze("yay-helper"), "B-TYPOSQUAT")); // prefix, not a variant
        assert!(has(&analyze("pary-bin"), "B-TYPOSQUAT")); // typo behind a variant suffix
        assert!(
            !has(&analyze("myay-bin"), "B-TYPOSQUAT"),
            "No prefix/suffix match"
        );
    }

    #[test]
    fn legitimate_variants_are_not_typosquats() {
        for name in [
            "yay-bin",
            "yay-git",
            "vim-git",
            "slack-desktop-wayland",
            "proton-ge-custom-bin",
            "python-steam",
            "lib32-mpv",
            "obs-studio-git",
        ] {
            let ids = analyze(name);
            assert!(!has(&ids, "B-TYPOSQUAT"), "{name}: {ids:?}");
        }
        // Impersonation is a separate check and is unaffected.
        assert!(has(&analyze("firefox-patch-bin"), "B-NAME-IMPERSONATE"));
    }

    #[test]
    fn exact_match_no_typosquat() {
        assert!(
            !has(&analyze("yay"), "B-TYPOSQUAT"),
            "Exact match should not flag"
        );
        assert!(!has(&analyze("firefox"), "B-TYPOSQUAT"));
    }

    #[test]
    fn normal_name_no_signals() {
        let ids = analyze("my-custom-tool");
        assert!(
            ids.is_empty(),
            "Normal name should trigger no signals, got: {ids:?}"
        );
    }

    #[test]
    fn established_packages_skip_all_name_signals() {
        // Packages with enough votes skip all name-based checks
        assert!(analyze_with_votes("pary", 50).is_empty());
        assert!(analyze_with_votes("firefox-fix", 50).is_empty());
        assert!(analyze_with_votes("yay2", 50).is_empty());
        assert!(analyze_with_votes("python-steam", 37).is_empty());
        assert!(analyze_with_votes("proton-ge-custom-bin", 267).is_empty());
    }

    #[test]
    fn new_packages_still_checked() {
        assert!(has(&analyze_with_votes("pary", 0), "B-TYPOSQUAT"));
        assert!(has(
            &analyze_with_votes("firefox-fix", 0),
            "B-NAME-IMPERSONATE"
        ));
        assert!(has(&analyze_with_votes("yay2", 0), "B-TYPOSQUAT"));
    }

    #[test]
    fn no_metadata_runs_all_checks() {
        // analyze() uses metadata: None — all string checks run
        assert!(has(&analyze("pary"), "B-TYPOSQUAT"));
        assert!(has(&analyze("firefox-fix"), "B-NAME-IMPERSONATE"));
        assert!(has(&analyze("yay2"), "B-TYPOSQUAT"));
    }
}
