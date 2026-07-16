# Hook

ALPM (pacman) hook integration for automatic pre-install scanning.

## Files

- `bewaur.hook` — portable ALPM hook definition for standard pacman
- `bewaur-network.hook` — variant for pacman builds that isolate hook networking;
  opts in with `NetworkAccess = allowed`
- `bewaur-hook.rs` — Hook binary entry point, compiled as a separate binary

## How it works

1. pacman triggers the hook before any Install or Upgrade transaction
2. ALPM passes matched package names to `bewaur-hook` via stdin (one per line)
3. `bewaur-hook` filters out official repo packages using `pacman -Sl`
4. Batch-fetches AUR metadata to identify which packages actually exist on AUR; packages not found (e.g. local `-debug` split packages) are skipped with an info message
5. Remaining AUR packages are scanned silently (progress indicator only)
5. After all scans, a tier summary is printed (counts per tier)
6. Decision logic:
   - **All TRUSTED/OK**: prints "All packages look clean.", exits 0 — no prompt
   - **SKETCHY or SUSPICIOUS**: prints detail for flagged packages, prompts [y/N]
   - **MALICIOUS**: prints detail, hard-blocks (exit 1), must whitelist to proceed
   - **Scan errors**: hard-blocks (exit 1), fail-closed
7. `AbortOnFail` in the hook definition causes pacman to abort on exit 1

## Installation

```bash
pkgver=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
git archive --format=tar.gz --prefix="bewaur-${pkgver}/" \
  --output="pkg/bewaur-${pkgver}.tar.gz" HEAD
(cd pkg && makepkg -Ccfsi)
```

The package installs the hook binary as `/usr/bin/bewaur-hook` and registers the
`bewaur` dependency required by the ALPM hook. Avoid copying only the hook file:
an unregistered manual install does not satisfy `Depends = bewaur`.

The PKGBUILD probes `pacman --disable-sandbox-network --version` and installs
`bewaur-network.hook` only when that extension is supported. Standard pacman
rejects the extension's `NetworkAccess` key, so it must continue to receive
`bewaur.hook`.

## Design decisions

- **Silent on clean**: TRUSTED/OK packages produce only a summary count. Detail is shown only for SKETCHY+ packages. No prompt when all packages are clean.
- **Only MALICIOUS hard-blocks**: SKETCHY and SUSPICIOUS prompt the user [y/N] but don't require whitelisting. Only MALICIOUS packages force `bewaur allow` to proceed.
- **Fail closed**: If a scan errors out (git clone timeout, network failure, etc.), the hook blocks the transaction. Unscanned packages are not allowed through. Git operations have a 30-second timeout to prevent indefinite hangs. Packages not found on AUR are skipped (not treated as errors) since they are locally-built packages (e.g. `-debug` split packages).
- **Official repo skip**: `pacman -Sl` is fast and reliable for filtering. AUR packages are not in sync databases.
