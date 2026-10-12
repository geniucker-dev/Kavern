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
| Historical pinned v0.26.34 actual connection/TCP robustness | tests/legacy_npc tagged black-box matrices and same-package test-only companions; NPC_BIN required when tagged |
| Disabled device/tunnel, stored targets only | router negative tests, native unknown/injected target tests, legacy storage/ownership tests, offline CLI persistence/disable tests |
| Parser limits, replay/registry/history caps, cleanup | security/parser/history/standalone Serve regressions, four bounded fuzz targets, race/stress |
| Runnable local admin/server/agent | three command builds; help/version; strict config; locked encrypted state; OPERATIONS.md |
| Local benchmark and future backend comparison plan | experiments/muxbench; 36-row exact-payload loopback report, CPU/heap profiles; no TLS/WAN performance claim |

## Reviewed 2026-10-12 Compatibility Policy Supplement

On 2026-10-12, a separately reviewed isolated candidate passed basic server-configuration TCP echo and complete application close with official Linux amd64 NPC 0.26.17, 0.26.27, 0.26.34 and 0.26.39, invoked with `-server` and `-vkey`. Each fresh case used one application connection, exact 1/64/65536-byte echo, END/EOF, actual main/current mux readiness, offline verification and complete process/listener/directory cleanup. The externally reconciled 37-file evidence manifest is `79c6c11bb6197532cf93c28b221818a452f4a82a8ed02834c1f8d0bb3de157ad` (`npc-opaque-metadata-execution`, retained outside the repository). This is limited functional evidence, not all features, all versions, performance or an indefinite-soak result. Earlier v0.26.34 robustness evidence is historical and does not extend to the other releases.

The current implementation discards bounded core/client declarations instead of applying a literal allowlist. TST, per-field signed limits, one handshake deadline, fixed reply, auth/role and session/mux/tunnel targets retain their security checks. This change and limited evidence do not expand the original v0.26.34 robustness matrix. No instrumentation, experimental runner/coordinator, binary asset or upstream source is included in the working-tree change.


The final opaque policy also passed independently reviewed NPC39 diagnostics and lifecycle cases on 2026-10-12. The four cells used official NPC39 against opaque Kavern and isolated stock NPS39 in fast and wait-target-release modes: one immediate startup plus 100 warm probes per cell, 404 total, all within the original one-second READY threshold. This one NPC39 batch did not reproduce an approximately five-second READY stall; it does not show that the historical NPC34 root cause was identified or fixed.

Three NPC39 lifecycle cases passed once each: `TestLegacyNPCProcessRestartLifecycle`, `TestLegacyNPCClosePaths/npc-stop-active`, and `TestRealNPCCompanionMainReplacementCleanup` (2+1+2 NPC starts/exits; original 45/45/35-second contexts). The active-stop case explicitly cancels route; replacement changes main+chan and explicitly closes the old mux. These cases establish neither autonomous stream termination nor main-only replacement/automatic old-mux reclamation. No whole-case rerun or sample refill occurred; the original limited `ErrLegacyDataChannelUnavailable` fresh-route readiness retries remain. All owned processes/readers, private directories and registered listeners were cleaned up, with frozen inputs/shared snapshot unchanged. The lifecycle outer tool exit was 0, with post-seal/post-hash caller timing 5.629502187 seconds inside the original 300/90/32-second batch/case/cleanup bounds.

Evidence root on sms is `/home/zhuhaoyu/Documents/Codex/2026-10-11/task/`. In addition to the four-version basic TCP manifest above, reviewed manifest seals are:

- `npc-v0.26.39-opaque-grid-execution`: `ffb5a42483c04bae7f92b5d8e7aedbddbec55b0aad682f756b82f5ad2419a441` (46 files).
- `npc39-lifecycle-execution-r1`: `1c49b6da08fb6556f68b544a38491fe4cb038b7f4088509c2853fdf50a001912` (13 files).
- `npc39-lifecycle-tool-return-r1`: `ae9705213441e8ce6fc6f01b899e4cb7ca378a8022893fece796998875ff2076` (3 files; raw outer tool exit and timing boundaries).

[TESTING.md](TESTING.md#reviewed-npc39-diagnostics-and-lifecycle-2026-10-12) records the exact scope and cleanup counts. This supplement does not establish NPC39 simultaneous-stream, repeated/window-boundary flow-credit or full robustness coverage, and adds no throughput, all-version or all-feature claim. The in-repository v0.26.34 suites remain unchanged; no isolated NPC39 test/tool/binary was imported.

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

All execution targets are isolated loopback or temporary local files. The original broad build/test evidence covers Linux amd64, pinned NPC v0.26.34 and smux v1.5.57; the scoped four-release basic TCP and NPC39 diagnostic/lifecycle supplements are stated separately above. Normal tests never download NPC. Legacy half-close is not supported; public-close is explicit cancellation. WAN/manual deployment, yamux/kavernmux/QUIC implementations, additional platforms, untested NPC variants/features, HA/multi-active, Web UI/management API, hot administration and indefinite soak remain outside this acceptance. No push, release or production deployment has occurred. Consult SECURITY.md and OPERATIONS.md before using the local deliverable; deployment/production credentials require separate authorization.
