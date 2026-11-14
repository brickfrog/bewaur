# PKGBUILD Analysis

Static analysis of PKGBUILD shell code for dangerous patterns.

## What it detects

- **Download-and-execute**: `curl|bash`, `curl|python`, `curl|perl`, `wget|sh`, `wget|python`, `source <(curl ...)`, process substitution, decompression pipes, Ruby/Perl fetch-exec — override gates (-> MALICIOUS)
- **Reverse shells**: `/dev/tcp/`, `/dev/udp/`, `nc -e`, `socat TCP EXEC`, Python socket+subprocess, Perl Socket, Ruby TCPSocket, Awk /inet/tcp, Lua socket.tcp, PHP fsockopen — override gates
- **Shell obfuscation**: `$IFS`, ANSI-C hex quoting, ROT13 via `tr`, octal encoding, string reversal via `rev`
- **Encoding bypasses**: `base64 -d`, `base32 -d`, `xxd -r`, `printf \xHH`, OpenSSL decryption
- **Code execution**: `eval $var`, `eval $(base64 ...)`, gzip+exec, `python -c`, telnet pipe
- **Credential access**: SSH keys, browser profiles, GPG keyring, /etc/passwd, clipboard
- **Persistence**: systemd services, systemd user services, cron jobs, XDG autostart, udev rules, `at` jobs, PROMPT_COMMAND, .bash_logout, shell profile modification, LD_PRELOAD
- **Privilege escalation**: SUID/SGID bit, sudoers modification, polkit rules, Linux capabilities (setcap), named pipes (mkfifo)
- **Anti-forensics**: shell history clearing, system log clearing/truncation
- **Exfiltration**: Discord webhooks, URL shorteners, OpenSSL client connections, direct disk read/write, telnet
- **AUR-specific**: pacman hook creation, alias overrides of common commands

## Signals emitted

All signals use `SignalCategory::Pkgbuild` (weight 0.45). See `data/patterns.toml` section `pkgbuild_analysis` for full pattern list.

## Dependencies

- `shared/patterns.rs` — loads and compiles regex patterns from TOML
- `PackageContext.pkgbuild_content` — the PKGBUILD file content to analyze

## Matching views

Every pattern is matched against the comment-stripped PKGBUILD and, if that
misses, against a quote-joined view (`shell_syntax::join_quoted_fragments`) in
which prose-free quote/escape fragments are joined (`ba""sh`, `/dev/t''cp`,
`c\url`). Quoted text containing whitespace or operators is never unquoted.
Both views preserve line numbers. `P-CRYPTO-WALLET` additionally masks
checksum arrays.

`P-SUID-BIT` is replaced by `P-SUID-CHROME-SANDBOX` (+30) only when every SUID
change the active-shell parser sees targets a file whose basename is exactly
`chrome-sandbox` (the Electron convention) and every regex hit is such a line.

## Known false positives

- `P-SYSTEMD-CREATE` (+35): Enabling units, or installing units into `/etc/systemd` or a user's home. Shipping units under `$pkgdir/usr/lib/systemd/{system,user}` is deliberately not matched.
- `P-KERNEL-MODULE-MODPROBE` (+25): Loading an in-tree module by name (e.g. `uinput`). Loading from a file path is the stronger `P-KERNEL-MODULE-LOAD`.
- `P-BASE64` (+60): Some packages use base64 for icon encoding in desktop files.
- `P-LD-PRELOAD` (+60): Some legitimate packages (like gamemode) use LD_PRELOAD.
- `P-PYTHON-INLINE` (+45): Legitimate packages may use `python -c` for version checks or build logic.
- `P-CLIPBOARD-READ` (+50): Clipboard managers legitimately use xclip/xsel/wl-paste.
- `P-UDEV-RULE` (+45): Some legitimate packages install udev rules.
- `P-PACMAN-HOOK` (+50): Some legitimate packages install pacman hooks (e.g., bewaur itself).
