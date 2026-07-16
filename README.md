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
bewaur gate --build-dir .  # fail-closed scan before an AUR helper builds
bewaur approve --build-dir .       # display the exact-tree scan/digest; do not save
bewaur approve --build-dir . --reviewed <digest> # save only the reviewed inputs
bewaur approvals [<base>]          # list exact and permanent authorization
bewaur revoke <base>               # remove the exact-tree approval
bewaur allow <base> --forever      # explicit name-wide emergency bypass
bewaur signals             # list scoring signals
bewaur cache stats         # inspect cached AUR Git repositories
bewaur cache clean <base>  # remove one package-base repository
bewaur cache clean --all   # explicitly clear the full Git cache
```

Runtime state lives under `~/.config/bewaur/` and `~/.cache/bewaur/`. The fork
does not read or migrate the previous `traur` state directories.

`bewaur scan` fails with a nonzero exit status if any installed package cannot
be scanned; an operational error never turns a partial bulk scan into a clean
result. Every network-backed scan refreshes a clean cached repository to the
exact fetched AUR `master` commit and applies the same path-confined build-tree
loader used by `bewaur gate`; a failed refresh or unreadable declared input is
an error rather than permission to use stale or partial data.

## Cache maintenance

`bewaur cache stats` reports the repository count and exact byte total under
the normal AUR Git cache. `bewaur cache clean <base>` validates the package base
and removes only that direct cache child. Clearing every cached repository
requires the explicit `--all` flag; `bewaur cache clean` by itself is rejected.
Cache inspection does not follow symlink entries, and targeted cleanup refuses
to remove one.

## Block AUR packages before Paru builds them

The ALPM hook runs before package installation, but an AUR helper has already
run the PKGBUILD's build functions by then. Paru can invoke Bewaur earlier,
before `makepkg`, through its supported pre-build command. Add this to
`~/.config/paru/paru.conf` (reuse an existing `[bin]` section rather than adding
a second one):

```ini
[bin]
PreBuildCommand = /usr/bin/bewaur gate --build-dir .
```

Paru runs the command from the package's build directory and supplies
`PKGBASE`. The gate reads that directory's `PKGBUILD` and `.SRCINFO` as inert
text; it never sources the PKGBUILD. It scans the union of `.install` paths
declared by `.SRCINFO` and actual `install=` assignment commands independently
found in the PKGBUILD; `install=` text in command arguments or array data does
not count. Common `$pkgname`/`$pkgbase` filenames are accepted only when every
resolved path is declared by `.SRCINFO`. Dynamic direct assignments and
recognizable indirect mutations through commands such as `printf -v`, `read`,
`mapfile`, `unset`, and shell declarations fail closed. This is static shell
inspection, not a claim that every arbitrary `eval` or computed mutation can be
reconstructed without executing attacker-controlled code.

Local executable helpers come from the union of resolved `.SRCINFO` local
sources, literal `source`/`source_ARCH` arrays independently read from the
PKGBUILD, and literal files reached by `source` or `.` commands. Helpers with a
script extension, executable mode, shebang, or explicit invocation are decoded
lossily and appended to the analysis, up to 1 MiB per file and 4 MiB total, so
an invalid UTF-8 byte cannot suppress nearby shell findings. Inert archives,
patches, documentation, and configuration are resolved but not treated as
executable shell. Remote and dynamically generated source names rely on
`.SRCINFO`; the gate does not evaluate arbitrary PKGBUILD expressions to recover
them. Package identities and all referenced local paths are validated, symlinks
are resolved, and every file read must remain inside the canonical build
directory.

The command writes its human-readable report to stderr and normally returns
success only for `TRUSTED` or `OK`. It blocks `SKETCHY`, `SUSPICIOUS`,
`MALICIOUS`, and every read, parse, fingerprint, or config error.

For a finding you have manually reviewed, run `bewaur approve --build-dir .`
from that Paru build directory. Bewaur reloads and scans the current tree,
prints its versioned digest, and intentionally saves nothing. Rerun with the
displayed `--reviewed <digest>` only after reviewing that report; Bewaur refuses
if the tree no longer matches it. The stored approval is scoped to the
validated package base and the complete local source tree: every file,
directory, raw filename/content byte, relevant Unix mode, and symlink target is
fingerprinted recursively, including otherwise undeclared files and `.git`
state that build code could read or execute. Only the absolute checkout
location, ownership, and timestamps are excluded.

An approved tree is still scanned and its current findings are still printed;
the matching approval overrides only the final risk-tier block. Any local tree
change invalidates it. A source fetched later is naturally outside this local
snapshot, so strong makepkg checksums remain the content pin; `SKIP` and mutable
VCS sources are not transformed into immutable artifacts by an approval.
Use `bewaur approvals`, `bewaur revoke <pkgbase>`, and
`bewaur revoke <pkgbase> --all` to inspect or remove authorization.

`bewaur allow <pkgbase> --forever` is deliberately different: after `.SRCINFO`
validates the package base, it is a permanent name-wide total bypass across
future tree changes and loader failures. The bare `allow` command is refused.
Use `--forever` only as an explicit recovery path, not ordinary review.
`bewaur revoke <pkgbase> --forever` removes it. Legacy `[whitelist]` config
fails closed and must be consciously removed or re-entered with `--forever`.

The ALPM hook remains installed as a second, pre-transaction check. It has no
local helper tree with which to verify an exact approval, so only an explicit
permanent package-base allowance applies there. In an interactive pacman
transaction, that hook prompts for
`SKETCHY`/`SUSPICIOUS` results. Without a controlling terminal it still scans:
clean results pass, while flagged results and scan errors block instead of
silently skipping the check.

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
