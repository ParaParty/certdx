# CertDX handoff

This handoff is for continuing development of this project after the current
Slock team pauses work.

## Current state

- Repo: `ParaParty/certdx`.
- Local checkout used by the previous team: `/Users/nk/dev/src/certdx`.
- Current branch at handoff: `main`.
- Latest reviewed/pushed commit at handoff: `d4f295b` (`build: add timezone for build date`).
- All Slock tasks through task #27 are done. There is no active feature branch
  or open implementation task from this team.

## Start here

Read these first instead of reconstructing the project from commit history:

- `CONTEXT.md` — glossary, repository layout, wire contracts, and release
  invariants.
- `docs/setup.md` — deployment architecture and install paths.
- `docs/server.md` — server config contract.
- `docs/client.md` — standalone client config contract.
- `docs/caddytls.md` — Caddy plugin syntax and local xcaddy workflow.
- `docs/tools.md` — `certdx_tools` commands.

Use `CONTEXT.md` as the source of truth when naming concepts in code or docs.
If a future change introduces new domain vocabulary or changes a contract,
update that file in the same PR.

## Repository shape

The repo is a Go workspace with six modules:

- root module: library packages under `pkg/`.
- `exec/server`: `certdx_server`.
- `exec/client`: `certdx_client`.
- `exec/tools`: `certdx_tools`.
- `exec/caddytls`: Caddy plugin module.
- `test/e2e`: end-to-end harness.

`go.work` is intentionally tracked. Submodules also keep `replace
pkg.para.party/certdx => ../..` so they still work in contexts that do not use
the workspace.

## Main implementation history

The previous team completed a broad refactor/audit pass. Important merged
areas:

- server lifecycle hardening and subscriber/renewer cleanup.
- client daemon split into daemon / HTTP poller / gRPC streamer.
- gRPC failover and stream context cleanup.
- HTTP allow-list rejection routed through `domain.ErrNotAllowed`.
- ACME account-key and S3 provider crash fixes.
- retry loop off-by-one and context-aware retry fixes.
- mTLS fatal-log removal and daemon init error propagation.
- atomic cert/key writes in the standalone client.
- `go.work` plus local xcaddy docs.
- CI split into unit/e2e and release matrix builds.
- broad unit tests across API, CLI, paths, ACME user parsing, client, config,
  server, logging, and tools.

The commit history around `dfb68bf` through `d4f295b` contains this work in
small, reviewable commits.

## Important behavior to preserve

- The server is the only ACME issuer. Clients, Caddy, Envoy SDS, Tencent Cloud,
  and Kubernetes updater paths are certificate consumers.
- `domain.ErrNotAllowed` is the canonical allow-list rejection. Keep it
  detectable across HTTP handlers and tests.
- Server cert cache reads must use snapshot-style access so cert/version pairs
  are not torn across renewal.
- `Stop()` on server/client daemons should cancel one root context and let
  goroutines drain from that context.
- Standalone client writes cert and key files atomically, then runs
  `reloadCommand` only after rotation when both files already existed.
- gRPC client failover is session-scoped. Avoid reintroducing shared sentinel
  errors or ambiguous `ctx = stream.Context()` renames.
- Local Caddy development must verify `go version -m ./caddy | grep certdx`
  shows local `=> ... (devel)` replacements.
- Release Caddy builds intentionally use remote module versions, not the local
  workspace.

## Build and test commands

Use the module loop pattern. `go test ./...` from the repo root does not cover
every nested module by itself.

```sh
for mod in . exec/server exec/client exec/tools exec/caddytls; do
  (cd "$mod" && go test -race ./...)
done
```

End-to-end tests live under `test/e2e`:

```sh
cd test/e2e
go test -race ./...
```

Release/dev build script:

```sh
python3 release/build.py --dev
python3 release/build.py linux amd64
```

The release workflow calls `release/build.py` once per matrix target.

## Caddy module and tag notes

`exec/caddytls` is a nested module. Release tagging needs both the root module
tag and the nested module tag when publishing a plugin release:

```sh
git tag vX.Y.Z
git tag exec/caddytls/vX.Y.Z
git push origin main vX.Y.Z exec/caddytls/vX.Y.Z
```

Before tagging the nested module, ensure `exec/caddytls/go.mod` requires the
matching root version if that release is meant for public xcaddy consumers.

For local plugin work, use the documented command in `docs/caddytls.md` or
`release/build.py --dev`; both force the parent module replacement so xcaddy
does not silently use the registry version.

## Review workflow expectations

Prior certdx owner feedback established a conservative workflow:

- update docs with the same PR when changing API, CLI, config, setup, release,
  architecture, or domain language.
- keep changes single-concern and reviewable.
- prefer existing local helpers and style over new abstractions.
- for code review, lead with blockers and concrete file/line references.
- do not call a PR done only because it builds; state exactly what was tested.

## Suggested skills for the next session

- Use `grill-with-docs` before broad new requirements or architecture changes.
- Use `tdd` when fixing regressions in shared behavior.
- Use `diagnose` for runtime bugs, CI failures, or release/build issues.

## Open follow-up ideas

These are not active tasks, just likely next places to look:

- Add more tests around release/build behavior and nested module tagging.
- Decide whether to document the lockstep release process in a dedicated
  `docs/release.md`.
- Keep expanding unit tests for areas still mostly covered by e2e.
- Consider whether the client cert/key pair should become pair-atomic, not only
  per-file atomic. The current code prevents partial file writes, but readers
  can still observe a new cert with an old key between the two renames.
