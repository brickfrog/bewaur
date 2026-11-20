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
bewaur scan --flagged-only --notify  # desktop notification when something is flagged
bewaur scan <package>      # scan a package
bewaur gate --build-dir .  # fail-closed scan before an AUR helper builds
bewaur approve --build-dir .       # display the exact-tree scan/digest; do not save
bewaur approve --build-dir . --reviewed <digest> # save only the reviewed inputs
bewaur inspect-artifact --expected-pkgbase <base> ./*.pkg.tar.zst
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

### Unattended scans

New detections and the vendored compromise list also apply to packages that are
already installed. The package ships an opt-in daily user timer:

```bash
systemctl --user enable --now bewaur-scan.timer
```

It runs `bewaur scan --all-installed --flagged-only --notify` and sends a
desktop notification only when a package is SKETCHY or worse or could not be
scanned.

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
them. It does resolve simple literal variables (a single top-level
`_appimage="App_${pkgver}.AppImage"` with no other way to change it), so an
AppImage package that runs `./"${_appimage}" --appimage-extract` on its own
checksum-pinned download scans normally and reports
`P-EXEC-DOWNLOADED-ARTIFACT`; running an unpinned download still blocks.
Helper/source discovery resolves unmodified `CARCH` for every concrete
architecture declared in `.SRCINFO`, including literal substitutions such as
`${CARCH/aarch64/arm64}`. Glob substitutions and computed values fail closed.
Package identities and all referenced local paths are validated, symlinks
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
Packages absent from a successful AUR lookup are reported as local/non-AUR
and skipped, so local builds need no permanent allowance. Lookup failures and
malformed responses still block the transaction.

## Inspect the package that was actually built

The pre-build gate covers source inputs; `bewaur inspect-artifact` covers the
resulting ALPM package bytes. It streams each archive without extracting or
executing it, validates the root `.PKGINFO`, `.BUILDINFO`, and gzip-compressed
`.MTREE`, checks metadata against the filename and optional expected package
base, scans `.INSTALL` through the transaction-time analyzers, and reports a
SHA-256 for the exact opened artifact. Multiple archive arguments are processed
in order, including split-package outputs; `--json` emits one outcome per
argument.

Malformed archives, identity mismatches, path traversal, duplicate paths,
link-pivot layouts, special files, unsafe modes, privileged account/sudo/loader
payloads, suspicious install scripts, and resource-limit violations return
nonzero. Common persistence surfaces such as pacman hooks, systemd units, udev
rules, polkit policy, tmpfiles, sysusers, kernel modules, cron, PAM, NSS, and
session startup files are reported for review but do not by themselves change
the exit status. Artifact structural findings cannot be bypassed with a source
tree approval or permanent package allowance.

The bounded first version accepts uncompressed, zstd, gzip, xz, and bzip2 ALPM
packages. It deliberately rejects legacy compression formats, sparse entries,
and GNU/PAX extension headers instead of letting an archive parser interpret
them outside Bewaur's limits. Absolute symlink targets used by normal Arch
packages are treated as rooted in the installation filesystem; paths nested
beneath any archive link are still rejected.

For a clean build, install Arch's `devtools` package once and create a base
chroot:

```bash
sudo mkarchroot /var/lib/bewaur/chroot/root base-devel
```

Then, from a fresh reviewed PKGBUILD directory with no old package outputs:

```bash
bewaur gate --build-dir .
makechrootpkg -c -u -T -r /var/lib/bewaur/chroot

pkgbase=$(sed -n 's/^[[:space:]]*pkgbase = //p' .SRCINFO | head -n 1)
sudo install -d -o root -g root -m 0755 /var/lib/bewaur
stage=$(sudo mktemp -d /var/lib/bewaur/artifacts.XXXXXX)
sudo chmod 0755 "$stage"
sudo install -o root -g root -m 0644 -- ./*.pkg.tar.zst "$stage"/
artifacts=("$stage"/*.pkg.tar.zst)

if sudo bewaur inspect-artifact --expected-pkgbase "$pkgbase" "${artifacts[@]}"; then
  printf 'Review the report above. Install these exact artifacts? [y/N] '
  read -r reply
  case "$reply" in
    [yY]) sudo pacman -U -- "${artifacts[@]}" ;;
  esac
fi
```

The root-owned staging directory keeps an unprivileged build process from
replacing the inspected files before `pacman -U`; the explicit install uses the
same paths that produced the displayed hashes. This is intentionally a manual
handoff: Paru exposes a pre-build command but no equivalent post-build gate.

A devtools "clean chroot" isolates build dependencies and the build functions;
it is not complete containment for an adversarial PKGBUILD. `makechrootpkg`
still performs source preparation and reads PKGBUILD metadata on the host. The
static pre-build gate reduces that exposure but cannot prove arbitrary dynamic
shell harmless. Build a package you already suspect is actively hostile inside
a disposable VM, not merely a host-side devtools chroot.

Artifact inspection does not verify signatures or provenance, prove arbitrary
binaries benign, reconcile every payload byte with `.MTREE`, or install
anything. It answers the narrower question of whether these exact archive bytes
have a consistent identity and avoid obvious structural, privileged-payload,
and transaction-script hazards.

## How it works

16 independent features emit scored signals per package, including:

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
| Shell analysis | Beyond-regex obfuscation and composition: multi-stage download/decode-to-interpreter pipelines, credential exfiltration, executed command substitutions |
| GTFOBins analysis | Legitimate binary abuse |
| Bin source verification | -bin package source domain vs upstream URL mismatch |
| Known compromised | Packages on the June 2026 AUR compromise list (forces review) |

## Detection coverage

Patterns derived from real AUR malware incidents:

- **CHAOS RAT (2025)** — browser impersonation packages, RAT distribution
- **Google Chrome RAT (2025)** — .install script, Python download+execute
- **Acroread (2018)** — orphan takeover, curl from paste service, systemd persistence
- **June 2026 AUR campaign** — adopted orphans, named npm/bun payload installs, `.install` credential exfiltration, download-decode-execute pipelines

An offline corpus of real AUR packages and incident-derived samples
(`tests/corpus/`) keeps the false-positive budget and recall floor under test.

Categories: download-and-execute, reverse shells, credential theft, persistence mechanisms, privilege escalation, C2/exfiltration, cryptocurrency mining, code obfuscation, kernel module loading, environment variable theft, system reconnaissance.

## License

MIT
