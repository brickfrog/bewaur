# Shell Analysis

Lightweight static analysis of PKGBUILD and install scripts that goes beyond regex pattern matching. Catches obfuscation techniques that regex fundamentally cannot detect. Runs all sub-analyzers on both `pkgbuild_content` and `install_script_content`.

## What it detects

### Variable Resolution (SA-VAR-CONCAT-EXEC, SA-VAR-CONCAT-CMD)
Tracks variable assignments (`VAR=value`) in textual execution order and resolves
`$VAR`/`${VAR}` references against the state available at each use. Later
reassignments cannot rewrite earlier commands. SA-VAR-CONCAT-EXEC detects
download-and-execute pipes assembled from variables (override gate).
SA-VAR-CONCAT-CMD only fires when a dangerous command is assembled from 2+
variable fragments (genuine concatenation obfuscation like
`a=cu;b=rl;$a$b`); single-variable-holds-command cases are handled by
SA-INDIRECT-EXEC instead. Uses word boundary matching to prevent substring false
positives.

### Indirect Execution (SA-INDIRECT-EXEC)
Detects variables holding dangerous command names (`bash`, `curl`, `python`, etc.) used in execution position (after `|`, at line start, after `;`/`&&`/`||`).

### Quoted Command Reconstruction (SA-QUOTED-DOWNLOAD-EXEC)
Lexes shell command words without executing them so adjacent quote or escape
fragments such as `cu""rl | ba''sh` cannot bypass download-and-execute gates.
Quoted prose and comment text do not create executable pipeline tokens. The
lexer understands common `sudo`, `command`, `env`, and `exec` wrappers, follows
only literal `sh`/`bash -c` and `eval` strings, and analyzes heredoc bodies only
when they feed an interpreter directly or through `cat | interpreter`.
Downloader-stdout and interpreter-stdin redirections take precedence over a
pipe, matching shell fd behavior. Dynamic shell strings and process
substitutions remain deliberately unanalyzed rather than guessed.

### Char-by-Char Construction (SA-CHARBYCHAR-CONSTRUCT)
Detects 3+ `$(printf '\xNN')` or `$(echo -e '\xNN')` subshells on a single line, indicating character-by-character command assembly.

### Data Blob Detection (SA-DATA-BLOB-HEX, SA-DATA-BLOB-BASE64, SA-HIGH-ENTROPY-HEREDOC)
Flags long hex strings (129+ chars, so SHA-512 values remain excluded), long base64 strings
(100+ chars), and heredocs with Shannon entropy > 5.0 bits/byte only when the
heredoc flows directly into an interpreter or decoder. Arithmetic shifts do
not mask later heredocs, and escaped or mixed-quote delimiters undergo the same
quote removal as Bash before matching their terminator.

### Binary Download Heuristic (SA-BINARY-DOWNLOAD-NOCOMPILE)
Flags when a PKGBUILD downloads a file (`curl -o`/`wget -O`) and `chmod +x` it
without any active build commands (`make`, `cmake`, `cargo`, `gcc`, etc.).
Build-tool names in comments, quoted data, inert heredocs, and arguments to
unrelated commands do not suppress the signal.

## Signals emitted

| ID | Points | Override | Description |
|----|--------|----------|-------------|
| SA-VAR-CONCAT-EXEC | 85 | yes | Variable concat resolves to download-and-execute |
| SA-VAR-CONCAT-CMD | 55 | no | Variable concat resolves to dangerous command |
| SA-INDIRECT-EXEC | 70 | no | Variable with dangerous cmd in exec position |
| SA-CHARBYCHAR-CONSTRUCT | 75 | no | Printf/echo subshell char-by-char construction |
| SA-DATA-BLOB-HEX | 50 | no | Long hex string (encoded payload) |
| SA-DATA-BLOB-BASE64 | 50 | no | Long base64 string (encoded payload) |
| SA-HIGH-ENTROPY-HEREDOC | 55 | no | High-entropy heredoc content |
| SA-BINARY-DOWNLOAD-NOCOMPILE | 60 | no | Download + chmod +x, no compilation |
| SA-QUOTED-DOWNLOAD-EXEC | 90 | yes | Quoted/escaped download-to-interpreter pipeline |

All signals use `SignalCategory::Pkgbuild` (weight 0.45). Install script signals use the same IDs with `IS-` prefix (e.g., `IS-SA-VAR-CONCAT-EXEC`).

## Design decisions

- **Ordered single-pass variable resolution** — no recursive expansion; each
  assignment affects only later textual uses
- **PKGBUILD standard vars excluded** — prevents false positives on `$pkgname`, `$pkgver`, etc.
- **No overlap with regex feature** — only emits signals when obfuscation hides the pattern from literal matching
- **All regexes via `LazyLock`** — compiled once, zero per-invocation overhead

## Dependencies

- `PackageContext.pkgbuild_content` — the PKGBUILD content to analyze
- `PackageContext.install_script_content` — the .install file content to analyze
