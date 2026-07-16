# Package

Local Arch package for the personal fork. This package is not published to the
AUR and there is no prebuilt `-bin` package.

## Build and install

From a committed repository root:

```bash
pkgver=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
git archive \
  --format=tar.gz \
  --prefix="bewaur-${pkgver}/" \
  --output="pkg/bewaur-${pkgver}.tar.gz" \
  HEAD

(cd pkg && makepkg -Ccfsi)
```

`PKGBUILD` uses `--locked`/`--frozen`, runs the test suite, and packages the
generated local archive. Its `SKIP` checksum is intentional for this local-only
workflow; use immutable sources and a real checksum before distributing it.

The package conflicts with `traur` and `traur-bin`. Do not add `provides=('traur')`:
the renamed CLI and state paths intentionally do not implement the old package
interface.

Packaging selects `bewaur-network.hook` when the build host's pacman supports
`--disable-sandbox-network`; otherwise it installs the portable `bewaur.hook`.
Both variants install to the destination name `bewaur.hook`.

## Installed files

| File | Path |
|------|------|
| CLI binary | `/usr/bin/bewaur` |
| Hook binary | `/usr/bin/bewaur-hook` |
| ALPM hook | `/usr/share/libalpm/hooks/bewaur.hook` |
| Pattern DB | `/usr/share/bewaur/patterns.toml` |
| License | `/usr/share/licenses/bewaur/LICENSE` |
