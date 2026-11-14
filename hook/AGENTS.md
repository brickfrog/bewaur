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
4. Batch-fetches AUR metadata and requires an explicit outcome for every
   non-official target; an omitted target blocks unless its exact transaction
   name has a permanent allowance
5. Remaining AUR packages are scanned silently (progress indicator only)
6. After all scans, a tier summary is printed (counts per tier)
7. Decision logic:
   - **All TRUSTED/OK**: prints "All packages look clean.", exits 0 — no prompt
   - **SKETCHY or SUSPICIOUS**: prints detail and prompts [y/N] with a controlling terminal; blocks when noninteractive
   - **MALICIOUS**: prints detail and hard-blocks (exit 1); exact-tree review belongs at the Paru gate
   - **Scan errors**: hard-blocks (exit 1), fail-closed
8. `AbortOnFail` in the hook definition causes pacman to abort on exit 1

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
- **Terminal-safe decisions**: `/dev/tty` is used only for an interactive
  prompt, never ALPM's target-list stdin. Without a controlling terminal,
  TRUSTED/OK results pass but SKETCHY/SUSPICIOUS results block because nobody
  can approve them; MALICIOUS results always block.
- **Fail closed**: If target input, metadata, or a package scan is incomplete
  (Git timeout, network failure, omitted RPC row, invalid target stream, etc.),
  the hook blocks the transaction. Git operations have a 30-second timeout to
  prevent indefinite hangs. A local-only or debug package omitted by the AUR
  must be authorized explicitly with `allow <exact-transaction-name> --forever`.
- **Authorization scope**: exact-tree approvals cannot apply because ALPM does
  not provide the helper's checked-out tree. The hook resolves split outputs to
  their AUR package base and honors `allow <pkgbase> --forever`. When metadata
  is absent, only the exact transaction name can be matched. Malformed, legacy,
  or unreadable config blocks rather than silently becoming defaults.
- **Official repo skip**: `pacman -Sl` is fast and reliable for filtering. AUR packages are not in sync databases.
