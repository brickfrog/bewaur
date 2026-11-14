# Known Compromised

Flags package names and package bases that appear on the public list of AUR
packages compromised in the June 2026 incident.

## Data

`data/june-2026-compromised.txt` is a vendored snapshot of
<https://md.archlinux.org/s/SxbqukK6IA>, embedded at compile time. It is never
fetched at scan time: the source is an editable page and the ALPM hook may run
with networking isolated. Refresh it by re-fetching and regenerating the file
(sorted, one valid AUR name per line, header kept).

## Signals emitted

| ID | Points | Category | Floor | Override |
|----|--------|----------|-------|----------|
| B-JUNE-2026-COMPROMISED | 50 | Behavioral | Sketchy | no |

## Design decisions

- **Floor, not gate.** Many listed packages were long-standing projects that
  were adopted, poisoned, and later cleaned up. A MALICIOUS override would
  brand restored packages permanently. The SKETCHY floor makes the strict
  pre-build gate block until the exact tree is reviewed and approved, and makes
  the ALPM hook prompt, without claiming MALICIOUS.
- Checks both `ctx.name` and the AUR `package_base`, so split outputs match.
