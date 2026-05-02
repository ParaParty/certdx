# ADR 0003: TOML key aliasing policy for the v0.5 refactor

## Status

Accepted.

## Context

The v0.5 refactor (PRD #25) renames packages and CLI subcommands but
deliberately leaves the user-facing TOML config key names alone. The
refactor's clarity goals would benefit from also renaming awkward keys
(`renewTimeLeft`, `Common`, mixed-case section names), but the cost of
breaking every operator's config file in one release is steep, and
v0.5 is meant to be a drop-in replacement.

At the same time, post-v0.5 work (or a hypothetical v1.0) may want to
rename TOML keys for clarity. We need a policy to land those renames
without forcing a flag-day upgrade for every deployment.

## Decision

When a TOML key is renamed in a future release, the old name remains a
valid alias for **at least one full release cycle**. The aliasing layer
lives in `pkg/config`'s `Validate` path, which has access to the parsed
struct and can copy values from old field names into new ones before
final validation runs. Both the old and new names parse to the same
canonical field; specifying both is an error.

Concretely:

- A renamed key is added to the struct under its new name with a
  `toml:"<new>"` tag.
- The old name is preserved on the struct via a separate field with
  `toml:"<old>"`, marked deprecated in godoc.
- `Validate` checks: if both are set, return an error pointing at the
  new key. If only the old is set, copy into the new and log a
  deprecation warning. If only the new is set, no-op.
- Release notes call out the rename and the one-release timeline.

The deprecation warning must be loud enough to show up in normal logs
(use `logging.Notice` at startup, not `logging.Debug`).

## Consequences

- v0.5 itself does not rename any TOML keys, so this ADR has no
  immediate code impact. It is the contract for future rename work.
- Future renames cost one extra struct field plus a half-dozen lines of
  copy-and-warn code in `Validate`. Cheap.
- Operators get one release cycle to migrate their config files. If
  they ignore the deprecation warning, the next release after that
  removes the alias and their startup fails.

## Alternatives considered

- **Hard rename, no alias.** Forces every operator to edit config on
  upgrade. Rejected as too disruptive for what is mostly a
  cosmetic improvement.
- **Permanent aliases.** Two names for the same key forever. Rejected
  because it punishes new readers — they have to learn that two keys
  mean the same thing.
- **Silent migration without warning.** Hides the future deprecation
  from operators. Rejected: the warning is the whole point.
