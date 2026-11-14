# PKGBUILD Diff Analysis

Compares the current PKGBUILD with `HEAD~1` and emits temporal evidence for
security-relevant changes.

## JavaScript package-manager behavior

- `T-DIFF-NEW-JS-MANAGER-DEP` (+35 Temporal) records a newly added `npm`,
  `pnpm`, `yarn`, or `bun` dependency. Dependency arrays are parsed as shell
  arrays, including multiline, `+=`, architecture-specific, versioned, and
  optional dependency forms.
- `T-DIFF-NEW-NAMED-JS-INSTALL` (+55 Temporal) records an executable named
  package install newly added through one of those managers. Bare lockfile
  installs and local/path dependencies are excluded.
- `T-DIFF-NEW-JUNE-2026-IOC` (+80 Temporal) records a newly added install of a
  dependency tied to the June incident.
- `B-TAKEOVER-NAMED-JS-INSTALL` (+95 Behavioral, non-override) requires an
  established adopted package, recent and aligned RPC/git update timestamps, a
  latest author absent from the available earlier history, and a named install
  introduced by the same diff. It is intentionally supporting evidence because
  the cached AUR history is bounded.
- `B-RECENT-TAKEOVER-JUNE-2026-IOC` (+98 Behavioral, override gate) additionally
  requires a known incident dependency and a normalized identity match between
  the latest git author and current maintainer.

A historical submitter/maintainer difference, stale update, ordinary named
install, or newly added package-manager dependency alone must never fire the
override gate.

That invariant covers override gates only. A *tier floor* (`Signal.min_tier`) is
a distinct, weaker mechanism: it can raise the reported tier but never reach
MALICIOUS, so attaching a floor to a signal here would not violate the rule
above. No signal in this feature currently carries one.

The shared command scanner never runs package code. It ignores arrays, shell
comments, quoted prose, inert heredoc bodies, bare installs, local/path
dependency forms, and ambiguous unknown options. It does analyze script text
explicitly passed to a shell through `-c`, `eval`, direct shell stdin heredocs,
or `cat`-heredoc pipelines into a shell. It resolves only exact variables with
statically known literal assignments.

## Other diff signals

- Newly introduced high-severity PKGBUILD patterns
- Removed checksum arrays or replacement with all `SKIP`
- New source domains
- Major PKGBUILD rewrites
