# bewaur

**Inspect before you install.**

Bewaur is a Rust CLI and ALPM hook that assigns AUR packages a pre-install trust
score. It analyzes PKGBUILDs, install scripts, source URLs, metadata, maintainer
history, and git history before pacman commits a transaction.

This is a personal continuation of
[traur](https://github.com/Sohimaster/traur), with a deliberately separate
binary, hook, config, and cache identity.

## Installation

Bewaur is not published to the AUR. Build a local Arch package from a committed
checkout:

```bash
git clone git@github.com:brickfrog/bewaur.git
cd bewaur

pkgver=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
git archive \
  --format=tar.gz \
  --prefix="bewaur-${pkgver}/" \
  --output="pkg/bewaur-${pkgver}.tar.gz" \
  HEAD

(cd pkg && makepkg -Ccfsi)
```

The package conflicts with `traur` and `traur-bin`, so pacman will offer to
remove the old package rather than leave two pre-transaction hooks active.

On CachyOS, packaging installs the hook variant containing
`NetworkAccess = allowed`. Standard Arch pacman receives the portable hook.
Selection is based on support for `pacman --disable-sandbox-network`.

For development without installing the hook:

```bash
cargo build --release --frozen
./target/release/bewaur scan paru-bin
```

## Usage

```bash
bewaur scan                # scan all installed AUR packages
bewaur scan <package>      # scan a package
bewaur allow <package>     # whitelist a package
bewaur signals             # list scoring signals
```

Runtime state lives under `~/.config/bewaur/` and `~/.cache/bewaur/`. The fork
does not read or migrate the previous `traur` state directories.

## How it works

12 independent features emit scored signals per package:

| Feature | What it checks |
|---------|---------------|
| PKGBUILD analysis | Dangerous shell code |
| Install script analysis | Suspicious .install hooks |
| Source URL analysis | Untrusted source domains |
| Checksum analysis | Missing, skipped, or weak checksums |
| Metadata analysis | AUR votes, popularity, maintainer status |
| Name analysis | Typosquatting and brand impersonation |
| Maintainer analysis | New accounts, batch uploads |
| Orphan takeover analysis | Submitter != maintainer, orphan takeover patterns |
| Git history analysis | New network code, author changes |
| Shell analysis | Beyond-regex obfuscation (var concat, indirect exec, data blobs) |
| GTFOBins analysis | Legitimate binary abuse |
| Bin source verification | -bin package source domain vs upstream URL mismatch |

## Detection coverage

Patterns derived from real AUR malware incidents:

- **CHAOS RAT (2025)** — browser impersonation packages, RAT distribution
- **Google Chrome RAT (2025)** — .install script, Python download+execute
- **Acroread (2018)** — orphan takeover, curl from paste service, systemd persistence

Categories: download-and-execute, reverse shells, credential theft, persistence mechanisms, privilege escalation, C2/exfiltration, cryptocurrency mining, code obfuscation, kernel module loading, environment variable theft, system reconnaissance.

## License

MIT
