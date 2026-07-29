//! Non-executing analysis of JavaScript package-manager commands in shell files.
//!
//! One parser is shared by static PKGBUILD analysis, `.install` analysis, and
//! PKGBUILD-diff analysis so arrays, heredocs, wrappers, options, variables, and
//! local dependency exclusions cannot drift between those paths.

use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::LazyLock;

const JUNE_2026_IOCS: [&str; 4] = ["atomic-lockfile", "js-digest", "lockfile-js", "nextfile-js"];

static DEPENDENCY_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^[ \t]*(?:depends|makedepends|checkdepends|optdepends)(?:_[a-z0-9_]+)?[ \t]*\+?=[ \t]*\(",
    )
    .unwrap()
});

static ARRAY_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^ \t\n]+[ \t]+)*(?:(?:declare|local|readonly|typeset)(?:[ \t]+-{1,2}[A-Za-z]+)*[ \t]+)?[A-Za-z_][A-Za-z0-9_]*(?:\[[^]\n]*\])?[ \t]*\+?=[ \t]*\(",
    )
    .unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NamedJsInstall {
    pub manager: String,
    pub package: String,
    pub matched_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KnownJuneIocInstall {
    pub package: String,
    pub matched_line: String,
}

#[derive(Debug, Default)]
pub struct JsPackageManagerAnalysis {
    pub named_installs: Vec<NamedJsInstall>,
    pub known_june_iocs: Vec<KnownJuneIocInstall>,
}

/// Analyze executable shell commands without evaluating the input.
pub fn analyze(content: &str) -> JsPackageManagerAnalysis {
    let mut assignments = HashMap::new();
    let mut analysis = JsPackageManagerAnalysis::default();

    analyze_content(content, &mut assignments, &mut analysis, 0);

    analysis.named_installs.sort_by(|a, b| {
        (&a.manager, &a.package, &a.matched_line).cmp(&(&b.manager, &b.package, &b.matched_line))
    });
    analysis
        .named_installs
        .dedup_by(|a, b| a.manager == b.manager && a.package == b.package);
    analysis
        .known_june_iocs
        .sort_by(|a, b| (&a.package, &a.matched_line).cmp(&(&b.package, &b.matched_line)));
    analysis
        .known_june_iocs
        .dedup_by(|a, b| a.package == b.package);

    analysis
}

fn analyze_content(
    content: &str,
    assignments: &mut HashMap<String, String>,
    analysis: &mut JsPackageManagerAnalysis,
    depth: usize,
) {
    if depth > 8 {
        return;
    }

    let masked = mask_shell_arrays(content);

    for logical_line in executable_logical_lines(&masked) {
        for command in shell_command_segments(&logical_line) {
            let Some(command) = expand_env_split(command) else {
                continue;
            };
            record_static_assignments(&command, assignments);
            let resolved: Vec<String> = command
                .iter()
                .map(|word| resolve_exact_variable(word, assignments))
                .collect();

            if let Some(script) = executed_shell_source(&resolved) {
                analyze_content(&script, assignments, analysis, depth + 1);
            }

            let Some((manager, action_index)) = install_command(&resolved) else {
                continue;
            };

            let packages = match install_packages(&resolved, action_index + 1) {
                Ok(packages) => packages,
                Err(ambiguous_start) => {
                    // Unknown option arity suppresses generic findings. Only
                    // after that genuine ambiguity do exact incident names get
                    // a raw-token fail-safe; known option values never enter it.
                    for argument in &resolved[ambiguous_start..] {
                        if let Some(package) = normalize_named_remote_package(argument)
                            && is_known_june_ioc(&package)
                        {
                            analysis.known_june_iocs.push(KnownJuneIocInstall {
                                package,
                                matched_line: logical_line.trim().to_string(),
                            });
                        }
                    }
                    continue;
                }
            };

            for package in packages {
                if let Some(manager) = manager {
                    analysis.named_installs.push(NamedJsInstall {
                        manager: manager.to_string(),
                        package: package.clone(),
                        matched_line: logical_line.trim().to_string(),
                    });
                }
                if is_known_june_ioc(&package) {
                    analysis.known_june_iocs.push(KnownJuneIocInstall {
                        package,
                        matched_line: logical_line.trim().to_string(),
                    });
                }
            }
        }
    }
}

/// Find an executable chmod/install that sets SUID or SGID. This uses the same
/// active-shell view as package-manager detection, so arrays and inert heredoc
/// data cannot turn a mode example into an install-time finding.
pub fn find_privileged_chmod(content: &str) -> Option<String> {
    find_privileged_mode_change(content, false)
}

/// Find specifically an executable `install` invocation with a privileged
/// mode. This lets GTFOBins keep its PKGBUILD signal without a raw regex that
/// also fires on prose and inert heredocs.
pub fn find_privileged_install(content: &str) -> Option<String> {
    find_privileged_mode_change(content, true)
}

fn find_privileged_mode_change(content: &str, install_only: bool) -> Option<String> {
    let masked = mask_shell_arrays(content);

    for logical_line in executable_logical_lines(&masked) {
        for command in shell_command_segments(&logical_line) {
            let Some(command) = expand_env_split(command) else {
                continue;
            };
            let Some(executable) = executable_index(&command) else {
                continue;
            };
            let command_name = command[executable]
                .rsplit('/')
                .next()
                .unwrap_or(&command[executable]);

            if command_name == "chmod" && !install_only {
                let mut i = executable + 1;
                while i < command.len() && command[i].starts_with('-') {
                    if command[i] == "--" {
                        i += 1;
                        break;
                    }
                    // --reference performs a different operation with no
                    // explicit mode to prove statically.
                    if command[i] == "--reference" || command[i].starts_with("--reference=") {
                        i = command.len();
                        break;
                    }
                    i += 1;
                }
                if i + 1 < command.len() && is_privileged_mode(&command[i]) {
                    return Some(logical_line.trim().to_string());
                }
            } else if command_name == "install"
                && privileged_install_mode(&command[executable + 1..]).is_some()
            {
                return Some(logical_line.trim().to_string());
            }
        }
    }

    None
}

fn privileged_install_mode(arguments: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < arguments.len() {
        let argument = &arguments[i];
        if argument == "--" {
            return None;
        }
        if argument == "-m" || argument == "--mode" {
            return arguments
                .get(i + 1)
                .filter(|mode| is_privileged_mode(mode))
                .map(String::as_str);
        }
        if let Some(mode) = argument
            .strip_prefix("--mode=")
            .or_else(|| argument.strip_prefix("-m").filter(|mode| !mode.is_empty()))
            && is_privileged_mode(mode)
        {
            return Some(mode);
        }
        i += 1;
    }
    None
}

fn is_privileged_mode(mode: &str) -> bool {
    let octal = mode.trim_start_matches('0');
    if octal.len() == 4
        && octal.chars().all(|ch| matches!(ch, '0'..='7'))
        && matches!(octal.as_bytes()[0], b'2'..=b'7')
    {
        return true;
    }

    mode.split(',').any(|clause| {
        let Some((who, permissions)) = clause.split_once('+').or_else(|| clause.split_once('='))
        else {
            return false;
        };
        permissions.contains('s')
            && (who.is_empty() || who.chars().all(|ch| matches!(ch, 'u' | 'g' | 'a')))
    })
}

pub fn is_known_june_ioc(package: &str) -> bool {
    JUNE_2026_IOCS.contains(&package.to_ascii_lowercase().as_str())
}

/// Extract exact JS package-manager package dependencies from all Arch
/// dependency-array variants, including multiline and architecture-specific
/// arrays. Values are tokenized as shell words rather than split on whitespace.
pub fn extract_manager_dependencies(content: &str) -> HashSet<String> {
    let mut managers = HashSet::new();

    for assignment in DEPENDENCY_ARRAY_RE.find_iter(content) {
        let open_paren = assignment.end() - 1;
        let Some(close_paren) = matching_paren(content, open_paren) else {
            continue;
        };

        for word in shell_array_words(&content[open_paren + 1..close_paren]) {
            let dependency_name = word
                .split(['<', '>', '=', ':'])
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if canonical_js_manager(&dependency_name).is_some() {
                managers.insert(dependency_name);
            }
        }
    }

    managers
}

fn record_static_assignments(words: &[String], assignments: &mut HashMap<String, String>) {
    for word in words {
        let Some((name, value)) = split_shell_assignment(word) else {
            break;
        };
        let value = resolve_exact_variable(value, assignments);
        if value.is_empty()
            || value
                .chars()
                .any(|ch| ch.is_whitespace() || matches!(ch, '$' | '`' | '(' | ')' | ';' | '|'))
        {
            assignments.remove(name);
        } else {
            assignments.insert(name.to_string(), value);
        }
    }
}

fn resolve_exact_variable(word: &str, assignments: &HashMap<String, String>) -> String {
    let variable = word
        .strip_prefix("${")
        .and_then(|word| word.strip_suffix('}'))
        .or_else(|| word.strip_prefix('$'));
    variable
        .and_then(|name| assignments.get(name))
        .cloned()
        .unwrap_or_else(|| word.to_string())
}

fn split_shell_assignment(word: &str) -> Option<(&str, &str)> {
    let (name, value) = word.split_once('=')?;
    let valid_name = !name.is_empty()
        && name.chars().enumerate().all(|(index, ch)| {
            ch == '_' || ch.is_ascii_alphanumeric() && (index > 0 || !ch.is_ascii_digit())
        });
    valid_name.then_some((name, value))
}

/// Expand GNU `env -S/--split-string` only for a literal, control-free string.
/// Anything involving expansion or shell syntax is intentionally ambiguous and
/// suppresses analysis of that command rather than guessing.
fn expand_env_split(mut words: Vec<String>) -> Option<Vec<String>> {
    let mut i = 0;
    while i < words.len() {
        let basename = words[i].rsplit('/').next().unwrap_or(&words[i]);
        if basename != "env" {
            i += 1;
            continue;
        }

        let mut option = i + 1;
        while option < words.len() {
            let (value, consumed) = if matches!(words[option].as_str(), "-S" | "--split-string") {
                (words.get(option + 1)?.as_str(), 2)
            } else if let Some(value) = words[option].strip_prefix("--split-string=") {
                (value, 1)
            } else {
                option += 1;
                if words[option - 1] == "--" || !words[option - 1].starts_with('-') {
                    break;
                }
                continue;
            };

            let split = safe_env_split(value)?;
            words.splice(option..option + consumed, split);
            break;
        }
        i += 1;
    }
    Some(words)
}

fn safe_env_split(value: &str) -> Option<Vec<String>> {
    if value.is_empty()
        || value.chars().any(|ch| {
            matches!(
                ch,
                '$' | '`' | '\\' | '\'' | '"' | ';' | '|' | '&' | '<' | '>' | '(' | ')' | '{' | '}'
            )
        })
    {
        return None;
    }
    let words: Vec<String> = value.split_whitespace().map(str::to_string).collect();
    (!words.is_empty()).then_some(words)
}

fn executed_shell_source(words: &[String]) -> Option<String> {
    let executable = executable_index(words)?;
    let name = words[executable]
        .rsplit('/')
        .next()
        .unwrap_or(&words[executable]);

    if name == "eval" {
        let mut start = executable + 1;
        if words.get(start).is_some_and(|word| word == "--") {
            start += 1;
        }
        return (start < words.len()).then(|| words[start..].join(" "));
    }

    if !is_shell_interpreter(name) {
        return None;
    }

    let mut i = executable + 1;
    while i < words.len() {
        let option = &words[i];
        if option == "--" {
            return None;
        }
        if option == "-c" || option == "--command" {
            return words.get(i + 1).cloned();
        }
        if option.starts_with('-') && option[1..].chars().any(|ch| ch == 'c') {
            return words.get(i + 1).cloned();
        }
        if !option.starts_with('-') {
            return None;
        }
        i += 1;
    }
    None
}

fn is_shell_interpreter(name: &str) -> bool {
    matches!(name, "bash" | "sh" | "dash" | "ksh" | "zsh")
}

fn install_command(words: &[String]) -> Option<(Option<&'static str>, usize)> {
    let executable_index = executable_index(words)?;
    let executable = words[executable_index]
        .rsplit('/')
        .next()
        .unwrap_or(&words[executable_index]);
    let manager = canonical_js_manager(executable);
    let unresolved_manager = exact_variable_name(executable).is_some();
    if manager.is_none() && !unresolved_manager {
        return None;
    }

    let action_index = install_action_index(manager, words, executable_index + 1)?;
    Some((manager, action_index))
}

fn executable_index(words: &[String]) -> Option<usize> {
    let mut i = 0;

    while i < words.len() {
        if split_shell_assignment(&words[i]).is_some() {
            i += 1;
            continue;
        }

        let executable = words[i].rsplit('/').next().unwrap_or(&words[i]);
        let Some(wrapper) = wrapper_kind(executable) else {
            return Some(i);
        };
        if matches!(wrapper, WrapperKind::Builtin) {
            return None;
        }
        i += 1;

        while i < words.len() {
            if words[i] == "--" {
                i += 1;
                break;
            }
            if split_shell_assignment(&words[i]).is_some() {
                i += 1;
                continue;
            }
            if !words[i].starts_with('-') {
                break;
            }

            match wrapper_option_kind(wrapper, &words[i]) {
                OptionKind::Boolean => i += 1,
                OptionKind::Value if i + 1 < words.len() => i += 2,
                OptionKind::InlineValue => i += 1,
                OptionKind::Unknown | OptionKind::Value | OptionKind::NonExecuting => return None,
            }
        }
    }

    None
}

#[derive(Debug, Clone, Copy)]
enum WrapperKind {
    Builtin,
    Command,
    Env,
    Exec,
    Nohup,
    Sudo,
    Time,
}

fn wrapper_kind(word: &str) -> Option<WrapperKind> {
    match word {
        "builtin" => Some(WrapperKind::Builtin),
        "command" => Some(WrapperKind::Command),
        "env" => Some(WrapperKind::Env),
        "exec" => Some(WrapperKind::Exec),
        "nohup" => Some(WrapperKind::Nohup),
        "sudo" | "doas" => Some(WrapperKind::Sudo),
        "time" => Some(WrapperKind::Time),
        _ => None,
    }
}

fn wrapper_option_kind(wrapper: WrapperKind, option: &str) -> OptionKind {
    match wrapper {
        // `builtin npm ...` cannot execute the external npm binary.
        WrapperKind::Builtin => OptionKind::NonExecuting,
        WrapperKind::Command => match option {
            "-p" => OptionKind::Boolean,
            // `command -v/-V` inspect a name; they do not execute it.
            "-v" | "-V" => OptionKind::NonExecuting,
            _ => OptionKind::Unknown,
        },
        WrapperKind::Env => match option {
            "-i" | "--ignore-environment" | "-0" | "--null" => OptionKind::Boolean,
            "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string" => OptionKind::Value,
            option
                if ["--unset=", "--chdir="]
                    .iter()
                    .any(|prefix| option.starts_with(prefix)) =>
            {
                OptionKind::InlineValue
            }
            _ => OptionKind::Unknown,
        },
        WrapperKind::Exec | WrapperKind::Nohup | WrapperKind::Time => match option {
            "-a" => OptionKind::Value,
            "-c" | "-l" | "-p" | "--" => OptionKind::Boolean,
            _ => OptionKind::Unknown,
        },
        WrapperKind::Sudo => match option {
            "-u" | "--user" | "-g" | "--group" | "-h" | "--host" | "-p" | "--prompt" | "-C"
            | "--close-from" | "-T" | "--command-timeout" | "-R" | "--chroot" | "-D"
            | "--chdir" => OptionKind::Value,
            "-E" | "--preserve-env" | "-H" | "--set-home" | "-n" | "--non-interactive" | "-S"
            | "--stdin" | "-i" | "--login" | "-b" | "--background" => OptionKind::Boolean,
            "-e" | "--edit" | "-l" | "--list" | "-v" | "--validate" | "-V" | "--version" => {
                OptionKind::NonExecuting
            }
            option if sudo_inline_value_option(option) => OptionKind::InlineValue,
            _ => OptionKind::Unknown,
        },
    }
}

fn sudo_inline_value_option(option: &str) -> bool {
    [
        "--user=",
        "--group=",
        "--host=",
        "--prompt=",
        "--close-from=",
        "--command-timeout=",
        "--chroot=",
        "--chdir=",
    ]
    .iter()
    .any(|prefix| option.starts_with(prefix))
        || ["-u", "-g", "-h", "-p", "-C", "-T", "-R", "-D"]
            .iter()
            .any(|prefix| option.starts_with(prefix) && option.len() > prefix.len())
}

fn install_action_index(manager: Option<&str>, words: &[String], mut i: usize) -> Option<usize> {
    while i < words.len() {
        let word = words[i].to_ascii_lowercase();
        let supported = match manager {
            Some("yarn") => word == "add",
            Some("npm" | "pnpm" | "bun") | None => {
                matches!(word.as_str(), "add" | "install" | "i")
            }
            Some(_) => false,
        };
        if supported {
            return Some(i);
        }
        if word == "--" {
            i += 1;
            continue;
        }
        if word.starts_with('-') {
            match package_manager_option_kind(&word) {
                OptionKind::Boolean | OptionKind::InlineValue => i += 1,
                OptionKind::Value if i + 1 < words.len() => i += 2,
                OptionKind::Unknown | OptionKind::Value | OptionKind::NonExecuting => return None,
            }
            continue;
        }
        return None;
    }
    None
}

fn install_packages(words: &[String], mut i: usize) -> Result<Vec<String>, usize> {
    let mut packages = Vec::new();
    let mut options_ended = false;

    while i < words.len() {
        let argument = &words[i];
        if !options_ended && argument == "--" {
            options_ended = true;
            i += 1;
            continue;
        }
        if !options_ended && argument.starts_with('-') {
            match package_manager_option_kind(argument) {
                OptionKind::Boolean | OptionKind::InlineValue => i += 1,
                OptionKind::Value if i + 1 < words.len() => i += 2,
                OptionKind::Unknown | OptionKind::NonExecuting => return Err(i + 1),
                OptionKind::Value => return Err(words.len()),
            }
            continue;
        }
        if let Some(package) = normalize_named_remote_package(argument) {
            packages.push(package);
        }
        i += 1;
    }

    Ok(packages)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionKind {
    Boolean,
    Value,
    InlineValue,
    NonExecuting,
    Unknown,
}

fn package_manager_option_kind(option: &str) -> OptionKind {
    let value_option = matches!(
        option,
        "--cache"
            | "--config"
            | "--cwd"
            | "--dir"
            | "--filter"
            | "--prefix"
            | "--registry"
            | "--userconfig"
            | "--workspace"
            | "--omit"
            | "--include"
            | "--tag"
            | "--access"
            | "--scope"
            | "--arch"
            | "--platform"
            | "--target"
            | "--loglevel"
            | "--save-prefix"
            | "--script-shell"
            | "--store-dir"
            | "--virtual-store-dir"
            | "--node-linker"
            | "--network-concurrency"
            | "--fetch-retries"
            | "--fetch-retry-factor"
            | "--fetch-retry-mintimeout"
            | "--fetch-retry-maxtimeout"
            | "--proxy"
            | "--https-proxy"
            | "-C"
    );
    if value_option {
        return OptionKind::Value;
    }

    if [
        "--cache=",
        "--config=",
        "--cwd=",
        "--dir=",
        "--filter=",
        "--prefix=",
        "--registry=",
        "--userconfig=",
        "--workspace=",
        "--omit=",
        "--include=",
        "--tag=",
        "--access=",
        "--scope=",
        "--arch=",
        "--platform=",
        "--target=",
        "--loglevel=",
        "--save-prefix=",
        "--script-shell=",
        "--store-dir=",
        "--virtual-store-dir=",
        "--node-linker=",
        "--network-concurrency=",
        "--fetch-retries=",
        "--fetch-retry-factor=",
        "--fetch-retry-mintimeout=",
        "--fetch-retry-maxtimeout=",
        "--proxy=",
        "--https-proxy=",
    ]
    .iter()
    .any(|prefix| option.starts_with(prefix))
        || option.starts_with("-C") && option.len() > 2
    {
        return OptionKind::InlineValue;
    }

    if matches!(
        option,
        "--ignore-scripts"
            | "--save"
            | "--save-dev"
            | "--save-prod"
            | "--save-optional"
            | "--save-peer"
            | "--no-save"
            | "--global"
            | "-g"
            | "--dev"
            | "-D"
            | "--exact"
            | "-E"
            | "--force"
            | "-f"
            | "--legacy-peer-deps"
            | "--strict-peer-deps"
            | "--frozen-lockfile"
            | "--production"
            | "--optional"
            | "--peer"
            | "--offline"
            | "--prefer-offline"
            | "--no-optional"
            | "--no-audit"
            | "--no-fund"
            | "--dry-run"
    ) {
        return OptionKind::Boolean;
    }

    OptionKind::Unknown
}

fn exact_variable_name(word: &str) -> Option<&str> {
    word.strip_prefix("${")
        .and_then(|word| word.strip_suffix('}'))
        .or_else(|| word.strip_prefix('$'))
        .filter(|name| {
            !name.is_empty()
                && name.chars().enumerate().all(|(index, ch)| {
                    ch == '_' || ch.is_ascii_alphanumeric() && (index > 0 || !ch.is_ascii_digit())
                })
        })
}

fn canonical_js_manager(word: &str) -> Option<&'static str> {
    match word.to_ascii_lowercase().as_str() {
        "npm" => Some("npm"),
        "pnpm" => Some("pnpm"),
        "yarn" => Some("yarn"),
        "bun" => Some("bun"),
        _ => None,
    }
}

fn normalize_named_remote_package(argument: &str) -> Option<String> {
    let lower = argument.to_ascii_lowercase();
    if argument.is_empty()
        || matches!(argument, "." | "..")
        || matches!(argument.chars().next(), Some('.' | '/' | '$' | '~'))
        || argument.contains("://")
        || [
            "file:",
            "link:",
            "workspace:",
            "portal:",
            "patch:",
            "git+",
            "github:",
            "gitlab:",
            "bitbucket:",
            "ssh:",
        ]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
        || [".json", ".tgz", ".tar.gz"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
    {
        return None;
    }

    // npm aliases install the target after `@npm:`, not merely the harmless
    // alias on the left. Normalize to that target so exact incident names
    // remain visible for both unscoped and scoped aliases.
    if let Some(alias_end) = lower.find("@npm:") {
        let alias = &argument[..alias_end];
        let target = &argument[alias_end + 5..];
        normalize_plain_package_spec(alias)?;
        return normalize_named_remote_package(target);
    }

    normalize_plain_package_spec(argument)
}

fn normalize_plain_package_spec(argument: &str) -> Option<String> {
    let name = if argument.starts_with('@') {
        let slash = argument.find('/')?;
        let version = argument[slash + 1..]
            .find('@')
            .map(|offset| slash + 1 + offset)
            .unwrap_or(argument.len());
        &argument[..version]
    } else {
        argument.split('@').next().unwrap_or(argument)
    };

    let valid = if let Some((scope, package)) =
        name.strip_prefix('@').and_then(|name| name.split_once('/'))
    {
        valid_package_component(scope) && valid_package_component(package)
    } else {
        !name.contains('/') && valid_package_component(name)
    };

    valid.then(|| name.to_ascii_lowercase())
}

fn valid_package_component(component: &str) -> bool {
    !component.is_empty()
        && component
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn mask_shell_arrays(content: &str) -> String {
    let mut bytes = content.as_bytes().to_vec();

    for assignment in ARRAY_ASSIGNMENT_RE.find_iter(content) {
        let open_paren = assignment.end() - 1;
        let Some(close_paren) = matching_paren(content, open_paren) else {
            continue;
        };
        for byte in &mut bytes[open_paren..=close_paren] {
            if *byte != b'\n' && *byte != b'\r' {
                *byte = b' ';
            }
        }
    }

    String::from_utf8(bytes).expect("replacing array bytes with ASCII preserves UTF-8")
}

fn matching_paren(content: &str, open_paren: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut depth = 0_u32;
    let mut quote = None;
    let mut escaped = false;
    let mut in_comment = false;

    for (offset, ch) in content[open_paren..].char_indices() {
        let index = open_paren + offset;

        if in_comment {
            if ch == '\n' {
                in_comment = false;
            }
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == '\\' && delimiter == '"' {
                escaped = true;
            } else if ch == delimiter {
                quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => quote = Some(ch),
            '\\' => escaped = true,
            '#' if index == 0
                || bytes.get(index.wrapping_sub(1)).is_some_and(|byte| {
                    byte.is_ascii_whitespace() || b";|&({})".contains(byte)
                }) =>
            {
                in_comment = true;
            }
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }

    None
}

fn shell_array_words(content: &str) -> Vec<String> {
    let chars: Vec<char> = content.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut word_started = false;
    let mut quote = None;
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else if ch == '\\' && delimiter == '"' && i + 1 < chars.len() {
                i += 1;
                word.push(chars[i]);
            } else {
                word.push(ch);
            }
            i += 1;
            continue;
        }

        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                word_started = true;
            }
            '\\' if i + 1 < chars.len() => {
                i += 1;
                word.push(chars[i]);
                word_started = true;
            }
            '#' if !word_started => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            ch if ch.is_whitespace() => {
                push_shell_word(&mut words, &mut word, &mut word_started);
            }
            _ => {
                word.push(ch);
                word_started = true;
            }
        }
        i += 1;
    }

    push_shell_word(&mut words, &mut word, &mut word_started);
    words
}

#[derive(Debug)]
enum LogicalWork {
    Line(String),
    Content(String),
}

fn executable_logical_lines(content: &str) -> Vec<String> {
    let mut logical_lines = Vec::new();
    let mut work = vec![LogicalWork::Content(content.to_string())];
    while let Some(item) = work.pop() {
        match item {
            LogicalWork::Line(line) => logical_lines.push(line),
            LogicalWork::Content(content) => {
                let mut nested = executable_logical_items(&content);
                nested.reverse();
                work.extend(nested);
            }
        }
    }
    logical_lines
}

fn executable_logical_items(content: &str) -> Vec<LogicalWork> {
    #[derive(Debug)]
    struct PendingHeredoc {
        delimiter: String,
        strip_tabs: bool,
        execute: bool,
        body: String,
    }

    let mut logical_items = Vec::new();
    let mut pending = String::new();
    let mut pending_quote = None;
    let mut heredocs: VecDeque<PendingHeredoc> = VecDeque::new();

    for physical_line in content.lines() {
        if let Some(heredoc) = heredocs.front_mut() {
            let candidate = if heredoc.strip_tabs {
                physical_line.trim_start_matches('\t')
            } else {
                physical_line
            };
            if candidate == heredoc.delimiter {
                let completed = heredocs.pop_front().expect("front heredoc exists");
                if completed.execute && !completed.body.trim().is_empty() {
                    logical_items.push(LogicalWork::Content(completed.body));
                }
            } else if heredoc.execute {
                heredoc.body.push_str(candidate);
                heredoc.body.push('\n');
            }
            continue;
        }

        let mut piece = physical_line.to_string();
        let continued = has_trailing_continuation(&piece);
        if continued {
            let trimmed_len = piece.trim_end().len();
            piece.truncate(trimmed_len.saturating_sub(1));
        }

        if !pending.is_empty() {
            pending.push(if pending_quote.is_some() { '\n' } else { ' ' });
        }
        pending.push_str(&piece);
        pending_quote = quote_after_line(&piece, pending_quote);

        if continued || pending_quote.is_some() {
            continue;
        }

        let line = std::mem::take(&mut pending);
        heredocs.extend(
            find_heredoc_delimiters(&line)
                .into_iter()
                .map(|spec| PendingHeredoc {
                    execute: heredoc_feeds_shell(&line, spec.operator_index),
                    delimiter: spec.delimiter,
                    strip_tabs: spec.strip_tabs,
                    body: String::new(),
                }),
        );
        logical_items.push(LogicalWork::Line(line));
    }

    if !pending.trim().is_empty() {
        logical_items.push(LogicalWork::Line(pending));
    }

    logical_items
}

fn quote_after_line(line: &str, mut quote: Option<char>) -> Option<char> {
    let chars: Vec<char> = line.chars().collect();
    let mut escaped = false;
    let mut at_word_start = true;
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if escaped {
            escaped = false;
            at_word_start = false;
            i += 1;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else if ch == '\\' && delimiter == '"' {
                escaped = true;
            }
            i += 1;
            continue;
        }

        match ch {
            '\\' => {
                escaped = true;
                at_word_start = false;
            }
            '\'' | '"' => {
                quote = Some(ch);
                at_word_start = false;
            }
            '#' if at_word_start => break,
            ch if ch.is_whitespace() => at_word_start = true,
            ';' | '|' | '&' | '(' | ')' | '{' | '}' => at_word_start = true,
            _ => at_word_start = false,
        }
        i += 1;
    }

    quote
}

fn has_trailing_continuation(line: &str) -> bool {
    line.trim_end()
        .chars()
        .rev()
        .take_while(|ch| *ch == '\\')
        .count()
        % 2
        == 1
}

struct HeredocSpec {
    delimiter: String,
    strip_tabs: bool,
    operator_index: usize,
}

fn find_heredoc_delimiters(line: &str) -> Vec<HeredocSpec> {
    let chars: Vec<char> = line.chars().collect();
    let mut delimiters = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut arithmetic_depth = 0_usize;
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == '\\' && delimiter == '"' {
                escaped = true;
            } else if ch == delimiter {
                quote = None;
            }
            i += 1;
            continue;
        }
        if ch == '#' && (i == 0 || chars[i - 1].is_whitespace()) {
            break;
        }
        if ch == '\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
            i += 1;
            continue;
        }

        if arithmetic_depth > 0 {
            match ch {
                '(' => arithmetic_depth += 1,
                ')' => arithmetic_depth = arithmetic_depth.saturating_sub(1),
                _ => {}
            }
            i += 1;
            continue;
        }
        if ch == '$' && chars.get(i + 1) == Some(&'(') && chars.get(i + 2) == Some(&'(') {
            arithmetic_depth = 2;
            i += 3;
            continue;
        }
        if ch == '(' && chars.get(i + 1) == Some(&'(') {
            arithmetic_depth = 2;
            i += 2;
            continue;
        }

        if ch == '<' && chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') {
            let operator_index = chars[..i].iter().map(|ch| ch.len_utf8()).sum();
            i += 2;
            let strip_tabs = chars.get(i) == Some(&'-');
            if strip_tabs {
                i += 1;
            }
            while chars.get(i).is_some_and(|ch| ch.is_whitespace()) {
                i += 1;
            }
            let (delimiter, next) = parse_heredoc_word(&chars, i);
            if !delimiter.is_empty() {
                delimiters.push(HeredocSpec {
                    delimiter,
                    strip_tabs,
                    operator_index,
                });
            }
            i = next;
            continue;
        }

        i += 1;
    }

    delimiters
}

fn heredoc_feeds_shell(line: &str, operator_index: usize) -> bool {
    let (unit_start, unit_end) = control_unit_bounds(line, operator_index);
    let unit = &line[unit_start..unit_end];
    let relative_operator = operator_index.saturating_sub(unit_start);
    let pipelines = pipeline_ranges(unit);
    let Some(source_index) = pipelines
        .iter()
        .position(|(start, end)| *start <= relative_operator && relative_operator < *end)
    else {
        return false;
    };

    let source = command_words(&unit[pipelines[source_index].0..pipelines[source_index].1]);
    if command_reads_shell_stdin(&source) {
        return true;
    }

    let Some(source_executable) = executable_index(&source) else {
        return false;
    };
    let source_name = source[source_executable]
        .rsplit('/')
        .next()
        .unwrap_or(&source[source_executable]);
    if source_name != "cat" {
        return false;
    }

    pipelines
        .get(source_index + 1)
        .map(|(start, end)| command_words(&unit[*start..*end]))
        .is_some_and(|sink| command_reads_shell_stdin(&sink))
}

fn control_unit_bounds(line: &str, target: usize) -> (usize, usize) {
    let bytes = line.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut start = 0;
    let mut end = line.len();
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i] as char;
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == '\\' && delimiter == '"' {
                escaped = true;
            } else if ch == delimiter {
                quote = None;
            }
            i += 1;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(ch),
            ';' => {
                if i < target {
                    start = i + 1;
                } else {
                    end = i;
                    break;
                }
            }
            '&' if bytes.get(i + 1) == Some(&b'&') => {
                if i < target {
                    start = i + 2;
                } else {
                    end = i;
                    break;
                }
                i += 1;
            }
            '|' if bytes.get(i + 1) == Some(&b'|') => {
                if i < target {
                    start = i + 2;
                } else {
                    end = i;
                    break;
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    (start, end)
}

fn pipeline_ranges(unit: &str) -> Vec<(usize, usize)> {
    let bytes = unit.as_bytes();
    let mut ranges = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut start = 0;
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i] as char;
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == '\\' && delimiter == '"' {
                escaped = true;
            } else if ch == delimiter {
                quote = None;
            }
            i += 1;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(ch),
            '|' if bytes.get(i + 1) != Some(&b'|')
                && bytes.get(i.wrapping_sub(1)) != Some(&b'>') =>
            {
                ranges.push((start, i));
                i += usize::from(bytes.get(i + 1) == Some(&b'&'));
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    ranges.push((start, unit.len()));
    ranges
}

fn command_words(segment: &str) -> Vec<String> {
    let words = shell_command_segments(segment)
        .into_iter()
        .next()
        .unwrap_or_default();
    expand_env_split(words).unwrap_or_default()
}

fn command_reads_shell_stdin(words: &[String]) -> bool {
    let Some(executable) = executable_index(words) else {
        return false;
    };
    let name = words[executable]
        .rsplit('/')
        .next()
        .unwrap_or(&words[executable]);
    if !is_shell_interpreter(name) {
        return false;
    }

    let mut i = executable + 1;
    while i < words.len() {
        let argument = &words[i];
        if argument == "--" {
            return i + 1 == words.len();
        }
        if argument == "-c" || argument == "--command" {
            return false;
        }
        if let Some(flags) = argument.strip_prefix('-') {
            if flags.contains('c') {
                return false;
            }
            i += 1;
            continue;
        }
        return false;
    }
    true
}

fn parse_heredoc_word(chars: &[char], mut i: usize) -> (String, usize) {
    let mut delimiter = String::new();
    let mut quote = None;

    while i < chars.len() {
        let ch = chars[i];
        if let Some(quote_delimiter) = quote {
            if ch == quote_delimiter {
                quote = None;
            } else if ch == '\\' && quote_delimiter == '"' && i + 1 < chars.len() {
                i += 1;
                delimiter.push(chars[i]);
            } else {
                delimiter.push(ch);
            }
            i += 1;
            continue;
        }

        match ch {
            '\'' | '"' => quote = Some(ch),
            '\\' if i + 1 < chars.len() => {
                i += 1;
                delimiter.push(chars[i]);
            }
            ch if ch.is_whitespace() || ";&|<>".contains(ch) => break,
            _ => delimiter.push(ch),
        }
        i += 1;
    }

    (delimiter, i)
}

fn shell_command_segments(line: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = line.chars().collect();
    let mut segments = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut word_started = false;
    let mut discard_redirection_target = false;
    let mut quote = None;
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else if ch == '\\' && delimiter == '"' && i + 1 < chars.len() {
                i += 1;
                word.push(chars[i]);
            } else {
                word.push(ch);
            }
            i += 1;
            continue;
        }

        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                word_started = true;
            }
            '\\' if i + 1 < chars.len() => {
                i += 1;
                word.push(chars[i]);
                word_started = true;
            }
            '#' if !word_started => break,
            ch if ch.is_whitespace() => {
                finish_command_word(
                    &mut words,
                    &mut word,
                    &mut word_started,
                    &mut discard_redirection_target,
                );
            }
            '<' | '>' => {
                if word_started && word.chars().all(|ch| ch.is_ascii_digit()) {
                    word.clear();
                    word_started = false;
                } else {
                    finish_command_word(
                        &mut words,
                        &mut word,
                        &mut word_started,
                        &mut discard_redirection_target,
                    );
                }
                discard_redirection_target = true;
                while chars
                    .get(i + 1)
                    .is_some_and(|next| matches!(next, '<' | '>' | '&' | '|' | '-'))
                {
                    i += 1;
                }
            }
            '&' if chars.get(i + 1) == Some(&'>') => {
                finish_command_word(
                    &mut words,
                    &mut word,
                    &mut word_started,
                    &mut discard_redirection_target,
                );
                discard_redirection_target = true;
                while chars
                    .get(i + 1)
                    .is_some_and(|next| matches!(next, '>' | '&'))
                {
                    i += 1;
                }
            }
            ';' | '|' | '&' | '(' | ')' | '{' | '}' => {
                finish_command_word(
                    &mut words,
                    &mut word,
                    &mut word_started,
                    &mut discard_redirection_target,
                );
                discard_redirection_target = false;
                if !words.is_empty() {
                    segments.push(std::mem::take(&mut words));
                }
                if (matches!(ch, '|' | '&') && chars.get(i + 1) == Some(&ch))
                    || (ch == '|' && chars.get(i + 1) == Some(&'&'))
                {
                    i += 1;
                }
            }
            _ => {
                word.push(ch);
                word_started = true;
            }
        }
        i += 1;
    }

    finish_command_word(
        &mut words,
        &mut word,
        &mut word_started,
        &mut discard_redirection_target,
    );
    if !words.is_empty() {
        segments.push(words);
    }
    segments
}

fn finish_command_word(
    words: &mut Vec<String>,
    word: &mut String,
    word_started: &mut bool,
    discard: &mut bool,
) {
    if *discard && *word_started {
        word.clear();
        *word_started = false;
        *discard = false;
    } else {
        push_shell_word(words, word, word_started);
    }
}

fn push_shell_word(words: &mut Vec<String>, word: &mut String, word_started: &mut bool) {
    if *word_started {
        words.push(std::mem::take(word));
        *word_started = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(content: &str) -> HashSet<(String, String)> {
        analyze(content)
            .named_installs
            .into_iter()
            .map(|install| (install.manager, install.package))
            .collect()
    }

    #[test]
    fn handles_wrappers_flags_scopes_continuations_and_static_variables() {
        let content = r#"
manager=bun
dependency=js-digest
build() {
  /usr/bin/env npm --prefix=/tmp install --ignore-scripts atomic-lockfile
  command -- pnpm add @scope/pkg@1.2.3
  yarn --cwd project add lockfile-js
  "$manager" \
    add "${dependency}"
}
"#;
        let installs = named(content);
        assert!(installs.contains(&("npm".into(), "atomic-lockfile".into())));
        assert!(installs.contains(&("pnpm".into(), "@scope/pkg".into())));
        assert!(installs.contains(&("yarn".into(), "lockfile-js".into())));
        assert!(installs.contains(&("bun".into(), "js-digest".into())));
    }

    #[test]
    fn excludes_bare_local_array_comment_string_and_heredoc_installs() {
        let content = r#"
makedepends=('npm' 'bun')
commands=('npm install array-data')
local -a more_commands=('bun add array-data')
# npm install comment-data
echo "npm install quoted-data"
npm install
npm ci
npm install .
npm install ./vendor/package
npm install ../package
npm install /srv/package
npm install file:./package
npm install link:../package
npm install workspace:package
npm install "$srcdir/package"
cat <<'SCRIPT'
npm install heredoc-data
SCRIPT
cat <<\ESCAPED
bun add escaped-heredoc-data
ESCAPED
cat <<E"O"F
yarn add mixed-heredoc-data
EOF
printf '%s' "documentation:
bun add js-digest
"
"#;
        let result = analyze(content);
        assert!(
            result.named_installs.is_empty(),
            "{:#?}",
            result.named_installs
        );
        assert!(result.known_june_iocs.is_empty());
    }

    #[test]
    fn arithmetic_shift_is_not_a_heredoc() {
        let installs = named("value=$((1 << 2))\nnpm install atomic-lockfile");
        assert!(installs.contains(&("npm".into(), "atomic-lockfile".into())));
    }

    #[test]
    fn option_values_are_not_packages_and_unknown_options_are_ambiguous() {
        assert!(named("npm install --omit dev").is_empty());
        assert!(named("npm install --unknown value").is_empty());
        assert!(
            named("npm install --omit=dev atomic-lockfile")
                .contains(&("npm".into(), "atomic-lockfile".into()))
        );

        let fail_safe = analyze("bun add --future-option js-digest");
        assert!(fail_safe.named_installs.is_empty());
        assert_eq!(fail_safe.known_june_iocs.len(), 1);

        let known_value = analyze("npm install --tag js-digest ordinary");
        assert_eq!(
            named("npm install --tag js-digest ordinary"),
            HashSet::from([("npm".into(), "ordinary".into())])
        );
        assert!(known_value.known_june_iocs.is_empty());
    }

    #[test]
    fn analyzes_explicit_shell_inputs_but_not_inert_heredocs() {
        for content in [
            "bash -c 'bun add js-digest'",
            "sh -ec 'bun add js-digest'",
            "eval 'bun add js-digest'",
            "bash <<'EOF'\nbun add js-digest\nEOF",
            "cat <<EOF | sh\nbun add js-digest\nEOF",
        ] {
            let result = analyze(content);
            assert_eq!(result.known_june_iocs.len(), 1, "{content}");
        }

        let inert = analyze("cat <<EOF\nbun add js-digest\nEOF");
        assert!(inert.named_installs.is_empty());
        assert!(inert.known_june_iocs.is_empty());
    }

    #[test]
    fn deeply_nested_executable_heredocs_are_processed_without_recursion() {
        let depth = 256usize;
        let mut content = String::new();
        for index in 0..depth {
            content.push_str(&format!("bash <<'EOF{index}'\n"));
        }
        content.push_str("bun add js-digest\n");
        for index in (0..depth).rev() {
            content.push_str(&format!("EOF{index}\n"));
        }

        let result = analyze(&content);

        assert_eq!(result.known_june_iocs.len(), 1);
        assert_eq!(result.known_june_iocs[0].package, "js-digest");
    }

    #[test]
    fn masks_array_data_but_not_executing_subshells() {
        let content = r#"
FOO=bar commands=('npm install array-data')
local -ra more_commands=('bun add js-digest')
captured=$(npm install live-command)
(bun add live-subshell)
"#;
        let installs = named(content);
        assert_eq!(
            installs,
            HashSet::from([
                ("npm".into(), "live-command".into()),
                ("bun".into(), "live-subshell".into()),
            ])
        );
        assert!(analyze(content).known_june_iocs.is_empty());
    }

    #[test]
    fn npm_aliases_are_normalized_to_the_installed_target() {
        for alias in [
            "harmless@npm:js-digest",
            "@scope/harmless@npm:js-digest@1.2.3",
        ] {
            let result = analyze(&format!("npm install {alias}"));
            assert_eq!(result.known_june_iocs.len(), 1, "{alias}");
            assert_eq!(result.named_installs[0].package, "js-digest");
        }
    }

    #[test]
    fn wrappers_execute_only_their_real_command() {
        for content in [
            "sudo -i -b npm install js-digest",
            "sudo --chdir /tmp npm install js-digest",
            "sudo -D /tmp npm install js-digest",
            "env -S 'npm install js-digest'",
        ] {
            assert_eq!(analyze(content).known_june_iocs.len(), 1, "{content}");
        }
        for content in [
            "builtin npm install js-digest",
            "command -v npm install js-digest",
            "sudo --list npm install js-digest",
            "env -S '$manager install js-digest'",
        ] {
            assert!(analyze(content).known_june_iocs.is_empty(), "{content}");
        }
    }

    #[test]
    fn redirection_targets_and_trailing_arguments_are_not_commands() {
        for content in [
            "cat <<< npm install js-digest",
            "cat < npm install js-digest",
            "printf x > npm install js-digest",
        ] {
            let result = analyze(content);
            assert!(result.named_installs.is_empty(), "{content}");
            assert!(result.known_june_iocs.is_empty(), "{content}");
        }
    }

    #[test]
    fn unresolved_manager_can_support_known_ioc_but_not_generic_install() {
        let result = analyze("\"$manager\" add js-digest");
        assert!(result.named_installs.is_empty());
        assert_eq!(result.known_june_iocs.len(), 1);

        let unresolved_package = analyze("bun add \"$dependency\"");
        assert!(unresolved_package.named_installs.is_empty());
        assert!(unresolved_package.known_june_iocs.is_empty());
    }

    #[test]
    fn dependency_arrays_cover_all_manager_and_arch_forms() {
        let content = r#"
makedepends=('npm>=10' "pnpm")
checkdepends_x86_64=('yarn')
optdepends+=('bun: optional JavaScript tooling')
"#;
        assert_eq!(
            extract_manager_dependencies(content),
            HashSet::from([
                "bun".to_string(),
                "npm".to_string(),
                "pnpm".to_string(),
                "yarn".to_string(),
            ])
        );
    }

    #[test]
    fn privileged_chmod_uses_active_shell_view_and_accepts_leading_zero() {
        for command in [
            "chmod u+s /usr/bin/helper",
            "chmod u=s /usr/bin/helper",
            "chmod u=rwxs /usr/bin/helper",
            "chmod g+s /usr/bin/helper",
            "chmod 4755 /usr/bin/helper",
            "chmod 04755 /usr/bin/helper",
            "chmod 004755 /usr/bin/helper",
            "chmod -v 2750 /usr/bin/helper",
            "install -m 4755 helper /usr/bin/helper",
            "install -m4755 helper /usr/bin/helper",
            "install --mode=004755 helper /usr/bin/helper",
        ] {
            assert!(find_privileged_chmod(command).is_some(), "{command}");
        }
        for content in [
            "chmod 0755 /usr/bin/helper",
            "chmod 1755 /var/tmp/helper",
            "modes=('chmod 4755 /usr/bin/helper')",
            "cat <<'EOF'\nchmod 4755 /usr/bin/helper\nEOF",
            "cat <<'EOF'\ninstall -m 4755 helper /usr/bin/helper\nEOF",
        ] {
            assert!(find_privileged_chmod(content).is_none(), "{content}");
        }

        assert!(
            find_privileged_chmod("bash <<'EOF'\ninstall -m 4755 helper /usr/bin/helper\nEOF")
                .is_some()
        );
    }
}
