# Local MVP acceptance map

Base reviewed sequence on 2026-10-09: Gate 6S-4A `e69c133`, Gate 6S-4B `2a4cb8a`, local assembly r2 `2b814ec`, Gate 7 `bc11abc`. Gate 8 and the final local MVP passed independent review on 2026-10-09. The original local MVP acceptance scope is complete. Earlier gate review records remain historical; the final command logs establish this run's results.

| Existing requirement | Implementation and executable evidence |
| --- | --- |
| Core User → Project → Device → Tunnel; device credentials | internal/domain, internal/store; memory/state tests |
| One current session; replacement closes old; history cannot route | internal/session; manager linearization/history stress and router tests |
| Legacy bearer boundary, no raw token/vkey state | internal/security, internal/store; credential issuance/rotation and CLI persisted-state tests |
| KAPv1 challenge/response, role/version separation, carrier binding | internal/gateway/agent_v1 auth/carrier/security tests |
| Verified native TLS, separate control/data carriers | cmd/kavernd process test; tls_security_test; transport/client |
| Replaceable mux and bounded carrier pool/backpressure | internal/dataplane/mux and carrier tests; smux hidden behind interface; existing MIT dependency |
| Native actual TCP echo and directional EOF | actual three race-built commands; two carriers; exact 262 KiB EOF-dependent response; two persisted-state lifecycles |
| Pinned stock NPC actual connection/TCP | tests/legacy_npc tagged black-box matrices and same-package test-only companions; NPC_BIN required when tagged |
| Disabled device/tunnel, stored targets only | router negative tests, native unknown/injected target tests, legacy storage/ownership tests, offline CLI persistence/disable tests |
| Parser limits, replay/registry/history caps, cleanup | security/parser/history/standalone Serve regressions, four bounded fuzz targets, race/stress |
| Runnable local admin/server/agent | three command builds; help/version; strict config; locked encrypted state; OPERATIONS.md |
| Local benchmark and future backend comparison plan | experiments/muxbench; 36-row exact-payload loopback report, CPU/heap profiles; no TLS/WAN performance claim |

## Reproduce final validation

Use a local Go toolchain and cached dependencies. Set `GOPROXY=off GOSUMDB=off`; provide writable GOCACHE/GOMODCACHE if needed. Ordinary validation must work without NPC_BIN/NPS_BIN.

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go vet -tags=legacy_npc_integration ./...
go build ./...
go test -race ./cmd/kavernd -run TestActualCommandsNativeTLSHalfCloseAndRestart -count=3 -v
go test -race ./internal/gateway/legacy_npc ./internal/router -count=20 -timeout=5m
go test -race ./experiments/muxbench ./internal/dataplane/carrier -count=10
go test ./internal/config -run '^$' -fuzz '^FuzzStrictJSON$' -fuzztime=5s -parallel=2
go test ./internal/gateway/agent_v1 -run '^$' -fuzz '^FuzzNativeFrames$' -fuzztime=5s -parallel=2
go test ./internal/dataplane/mux -run '^$' -fuzz '^FuzzNativeRecords$' -fuzztime=5s -parallel=2
go test ./internal/gateway/legacy_npc -run '^$' -fuzz '^FuzzLegacyFrame$' -fuzztime=5s -parallel=2
NPC_BIN=/absolute/path/to/pinned-v0.26.34/npc go test -race -tags=legacy_npc_integration ./tests/legacy_npc ./internal/gateway/legacy_npc -count=1 -timeout=5m
```

With the integration tag but missing NPC_BIN, real acceptance tests must fail clearly. Record that expected nonzero result separately; it is not a passing compatibility run. Final review bundle holds commands, exit codes, complete logs, exact source hashes/diff, native binaries and their hashes/help/version, fuzz evidence and source guard results. No temporary test certificate/state/credential is delivered. Test processes/listeners are joined; retained caches/profiles and reviewed evidence are ordinary local files.

## Boundaries

All execution targets are isolated loopback or temporary local files. Build/test evidence covers Linux amd64, pinned NPC v0.26.34 and smux v1.5.57. Normal tests never download NPC. Legacy half-close is not supported; public-close is explicit cancellation. WAN/manual deployment, yamux/kavernmux/QUIC implementations, additional platforms/NPC variants, HA/multi-active, Web UI/management API, hot administration and indefinite soak remain outside this acceptance. No push, release or production deployment has occurred. Consult SECURITY.md and OPERATIONS.md before using the local deliverable; deployment/production credentials require separate authorization.
