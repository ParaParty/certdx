# ADR 0002: gRPC SDS contract is Envoy-facing and behavior-frozen

## Status

Accepted.

## Context

`certdx_server` exposes the standard Envoy
`envoy.service.secret.v3.SecretDiscoveryService` protocol on its gRPC
endpoint. Two distinct consumer populations sit behind this surface:

1. **`certdx_client` in gRPC mode** and the Caddy plugin in gRPC mode.
   These ship in the same repo, so any wire change here can be matched
   on the consumer side in the same release.
2. **Envoy itself**, configured via the operator's `envoy.yaml` or
   xDS bootstrap. Envoy is not under our control. Any wire change
   becomes a per-deployment migration we have no visibility into.

The v0.5 refactor (PRD #25) replaces the gRPC failover state machine's
internal mechanics (slice 6) without altering the wire format. There
was a temptation along the way to also clean up the cert-pack
metadata layout — currently passed in `Node.Metadata.Fields["domains"]`
as a nested struct of arrays. A cleaner shape would be one resource per
cert pack with the domains carried as resource names.

## Decision

The gRPC SDS protocol behavior is frozen. The certdx server continues
to:

- Implement `envoy.service.secret.v3.SecretDiscoveryService` over mTLS.
- Read cert-pack domain mappings from `Node.Metadata.Fields["domains"]`
  as a `map[string][]string` (cert-pack name → domain list).
- Stream `tlsv3.Secret` payloads keyed by cert-pack name.
- Honor ACK/NACK semantics by `VersionInfo` (formatted as RFC 3339).

Internal refactors must not change any byte that goes on the wire.
Adding new optional metadata fields is allowed; renaming or
restructuring existing fields is not.

## Consequences

- Envoy operators can upgrade `certdx_server` without touching their
  Envoy config.
- Internal cleanups that touch the gRPC handlers stay below the wire
  layer (e.g. slice 5's `WaitForUpdate` and slice 6's session ctx are
  pure mechanics, not contract changes).
- A future v1.0 may revisit this with a versioned protocol or a
  parallel cleaner endpoint, but v0.5 does not.

## Alternatives considered

- **Cert pack via resource names.** Cleaner shape but a one-shot break
  for every Envoy in the field.
- **Add a v2 endpoint alongside v1.** Doable but premature: no consumer
  has asked for it.
