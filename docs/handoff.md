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

## Code author notes

The following captures the implementing agent's (Alphinaud) perspective on
design decisions and known tricky areas. Cross-reference the sections above for
factual context.

### Design decisions worth knowing

**`CertDXServer.Stop()` / `Wait()` shape (PR #61)**

LDLDL asked for simplicity across three review rounds. The key request was to
hide all ctx and goroutine management behind a minimal public API. The final
shape: one root context, `Stop()` cancels it, `Wait()` blocks until drain. The
HTTPS handler keeps swap-cert (`tls.Config.GetCertificate`) rather than a
listener swap; SDS streams receive `rootCtx` directly so they exit on server
shutdown without a separate kill channel. If this pattern gets extended, keep
the rule: hidden ctx is better than exposing ctx via parameter or accessor.

**gRPC stream ctx naming (PR #64)**

The original code had ambiguous `ctx = stream.Context()` reassignments that
silently shadowed the caller's context in some paths. The fix is naming
discipline: distinguish the parent ctx (passed in) from the stream-local ctx at
declaration time. Never reassign the caller's `ctx` inside `Stream()`. If
future work adds a second stream or nests calls, follow the same discipline or
the cancel propagation breaks in subtle ways.

**Atomic cert/key writes (PR #65)**

Standalone client uses temp-file + rename per file. This prevents partial-write
races on individual files. The open gap: a reader between the two renames can
see new cert + old key. This is low-risk today because cert rotation happens
well before the pair matters in practice. If key pinning or mTLS is added for
clients, upgrade to pair-atomic writes (staging dir rename, or a per-domain
lockfile).

**`GOWORK=off` for xcaddy builds (PR #66)**

The `go.work` workspace is tracked intentionally, but xcaddy's module graph
resolution doesn't understand workspace files. `release/build.py` sets
`GOWORK=off` before invoking xcaddy so the build sees `go.mod`-declared
replacements only. If `go.work` is ever restructured or a new module added,
verify the xcaddy build still passes under `GOWORK=off` before merging.

**Nested module tagging lockstep**

When publishing a new `exec/caddytls` release, the root module tag and the
nested tag (`exec/caddytls/vX.Y.Z`) must be pushed together. Pushing only the
root tag leaves xcaddy consumers resolving the old nested version with no
visible error. The tag recipe is in the section above; consider adding it to
`docs/release.md` when that doc is written.

### Tricky areas

- The txc updater daemon runs in a goroutine after init. An init failure must
  propagate via a dedicated error channel, not only `Stop()`, because the
  `WaitGroup` counter does not drop until handlers fire. See PR #14 audit notes.
- The retry helper off-by-one (PR #59) was subtle: the loop ran `n+1` times for
  `maxRetry=n`. If retry logic is extended, add a table-driven test that counts
  actual invocations.
- `pkg/client/grpc_streamer.go` failover is session-scoped by design. Each
  `Stream()` call gets its own send guard and error channel. Reintroducing a
  shared sentinel or a cross-session cancel will break failover silently.

### Things I would look at next

- Pair-atomic cert/key writes (see above).
- A `docs/release.md` covering the tag lockstep recipe so it isn't only in
  commit messages and this handoff.
- Expanding e2e coverage of the Caddy plugin: the current e2e tests do not
  exercise the Caddy plugin path end-to-end.
