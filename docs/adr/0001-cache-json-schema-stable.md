# ADR 0001: `cache.json` schema is stable across the v0.5 refactor

## Status

Accepted.

## Context

The v0.5 refactor (PRD #25) consolidates package layout, error handling,
and concurrency. One of the candidate cleanups was the on-disk cert
cache file (`cache.json`): it serializes
`map[domain.Key]ServerCacheFileEntry` directly, with the `domain.Key`
hash as the JSON object key.

Changing this format would let us drop the FNV hash key in favor of a
sorted-domain string, simplify cache reload, and align the cache file
with the wire format. The flip side is that every running
`certdx_server` deployment has a `cache.json` written by the previous
schema; a format change forces every operator to either delete the file
on upgrade or run a migration step.

## Decision

`cache.json`'s schema is frozen for the duration of the v0.5 refactor.
Slices may freely refactor the in-memory cache shape, the renewer
goroutine, and the broadcast notification primitive, but the JSON
written to disk must remain readable by both the previous release and
the post-refactor server.

Concretely:

- The map key type is `domain.Key` (`uint64`, FNV-1a sum) and stays so.
- The value shape (`ServerCacheFileEntry { Domains []string; Cert
  CertT }`) and `CertT` field tags stay so.
- The file is written with `os.WriteFile` at mode `0o600` next to the
  executable. The file path discovery rules are unchanged.

A future major-version release may revisit this; this ADR governs the
v0.5 series.

## Consequences

- A binary upgrade is a drop-in replacement: stop the old binary, swap
  it, start the new one, and the cache picks up where it left off.
- Internal types that participate in the JSON encoding cannot have
  their field names changed (only their godoc and helper methods).
- The renewer goroutine and the `version`-based broadcast machinery
  introduced in slice 5 do not surface in `cache.json`.

## Alternatives considered

- **Switch to a sorted-domain string key.** Cleaner for humans reading
  the file, but breaks the upgrade path.
- **Add a schema-version field.** Solves forward-compat at the cost of
  introducing a migration code path the v0.5 refactor doesn't need.
  Defer to whatever later release first wants to break the schema.
