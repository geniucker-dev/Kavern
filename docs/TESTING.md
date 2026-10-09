# Testing Plan

This document defines the testing contract for Kavern. It is part of Gate 0 specification review and does not approve implementation.

## Test Tiers

1. Unit tests for domain, security helpers, configuration, and routing decisions.
2. Integration tests for local `kavernd` and `kavern-agent` behavior.
3. Legacy stock `npc` integration tests under `tests/legacy_npc`.
4. Benchmark experiments under `experiments/muxbench`.

## Normal Test Contract

Normal validation must be:

```sh
go test ./...
```

This command must not require:

- Internet access.
- `NPC_BIN`.
- A stock `npc` binary.
- External services.
- Human deployment.

## Legacy npc Integration Contract

Legacy npc integration tests are opt-in and must follow this contract:

- Tests live under `tests/legacy_npc`.
- Tests use a build tag such as `legacy_npc_integration`.
- Tests execute a real stock `npc` binary from `yisier/nps`.
- Tests use `NPC_BIN=<path-to-npc>`.
- When the build tag is enabled, `NPC_BIN` is required.
- If `NPC_BIN` is missing, the test must fail clearly.
- Missing `NPC_BIN` must not silently skip the test.
- Fake npc compatibility tests are not sufficient for acceptance.
- Normal `go test ./...` must not require internet or `NPC_BIN`.

Supported invocation:

```sh
npc -server=<host:port> -vkey=<vkey>
```

Server-side configuration mode is the only supported legacy mode.

Out of scope for legacy testing:

- `npc -config`
- `conf`
- `file`
- `p2p`
- `secret`
- `register`
- nps Web UI
- nps API

## Real npc Acceptance

Real stock `npc` compatibility must not be considered complete unless an integration test actually executes a real `npc` binary from `yisier/nps`.

Legacy credential test coverage must verify that Kavern-generated `vkey` values use at least 32 bytes of cryptographic randomness, use base64url or equivalent safe encoding, are shown only once at creation or rotation, are not stored raw, and cannot be recovered after loss. Rotation tests must verify that the old legacy lookup key is invalidated. Legacy authentication tests must verify that disabled devices cannot authenticate through stock `npc`.

Expected command shape:

```sh
NPC_BIN=/absolute/path/to/npc go test -tags=legacy_npc_integration ./tests/legacy_npc
```

Gate 6S-3 real TCP echo acceptance uses the pinned stock binary and does not
require `NPS_BIN`:

```sh
NPC_BIN="$PWD/.kavern-testbin/nps-v0.26.34/npc" \
PATH=/usr/local/go/bin:$PATH \
go test -tags=legacy_npc_integration \
  ./tests/legacy_npc \
  -run 'TestLegacyNPC(TCPEcho|MainReplacement)' \
  -count=1 -v -timeout=60s
```

`TestLegacyNPCMainReplacement` starts two pinned stock clients with the same
device credential and verifies that legacy-main replacement leaves the final
manager-current session with a usable device-scoped mux. It remains a bounded
Gate 6S-3 startup/replacement acceptance test, not the Gate 6S-4 payload and
flow-control matrix.

If the tag is enabled without `NPC_BIN`, the expected result is a clear failure explaining that `NPC_BIN` is required.

## Stock npc Binary Acquisition

The repository may later include placeholders:

- `scripts/build-npc.sh`
- `scripts/fetch-npc.sh`

These scripts may fetch or build stock `npc` from a pinned `yisier/nps` tag. They must not vendor `yisier/nps` source into this repository.

Before Gate 5 starts, a pinned `yisier/nps` tag or version must be selected and documented here. `scripts/build-npc.sh` and `scripts/fetch-npc.sh` must not use `master` or `latest`. The scripts may clone or download into temporary, cache, or testbin locations, but must not vendor `yisier/nps` source into the Kavern repository.

Gate 5 pins stock `npc` compatibility testing to:

```text
Pinned yisier/nps tag: v0.26.34
Source: https://github.com/yisier/nps
Release assets: https://github.com/yisier/nps/releases/tag/v0.26.34
Vendoring allowed: no
Scripts accepted in Gate 5: no
```

For Gate 5, `NPC_BIN` must point to an executable downloaded from the pinned GitHub release assets. Do not use `master`, `latest`, or an unpinned binary. The review packet must include the `NPC_BIN` absolute path, asset/source provenance, and SHA-256 of the binary or archive used.

Pinned legacy compatibility is a source-informed independent implementation documented in `docs/protocol/legacy-npc-v0.26.34.md`; it is not a clean-room claim. Tests and production code must not import, vendor, copy, or reuse `yisier/nps` GPL code, source files, identifiers, comments, tests, queue implementations, or window implementations. A separate license/compliance review is required before closed-source commercial distribution.

Developers may keep pinned stock `nps`/`npc` release binaries in a project-local ignored cache instead of `/tmp`:

```text
.kavern-testbin/
  nps-v0.26.34/
    linux_amd64_client.tar.gz
    linux_amd64_server.tar.gz
    npc
    nps
    SHA256SUMS.txt
```

Example environment exports:

```sh
export NPC_BIN="$PWD/.kavern-testbin/nps-v0.26.34/npc"
export NPS_BIN="$PWD/.kavern-testbin/nps-v0.26.34/nps"
```

`.kavern-testbin/` and `.kavern-observe/` are local developer caches only and must not be committed. Binaries, archives, generated stock `nps` config, captures, and logs must remain out of git. Tests do not auto-discover `.kavern-testbin/`; real legacy and observation tests still require explicit `NPC_BIN` and, where applicable, `NPS_BIN` environment variables. Do not place `NPS_OBSERVE_DIR` inside the repository unless a later reviewed change explicitly supports that; the current observe runtime should use `t.TempDir()` or an external directory outside the repo.

## Required Test Coverage by Gate

### Gate 1, Core Skeleton Review

- Domain model tests.
- Store tests.
- Legacy vkey helper tests using known vectors.
- `SessionManager` tests.
- `TunnelRouter` skeleton tests.
- Fake `AgentSession` tests.
- Legacy npc integration test harness that does not run in normal `go test ./...`.

### Gate 2, AgentV1 Review

- KAPv1 auth tests.
- `session_id` lifecycle tests.
- Control/data separation tests.
- Tests proving no MD5 dependency in `kavern-agent` path.
- TLS tests proving no `InsecureSkipVerify` default.
- Fake data carrier tests.

### Gate 3, Carrier Pool / Mux Review

- `MuxBackend` interface tests.
- `smux` or `yamux` backend tests.
- Dependency/license review for `smux`, `yamux`, or any mux backend.
- No GPL, AGPL, or other copyleft mux dependency without explicit review.
- Third-party mux packages hidden behind Kavern's `MuxBackend` interface.
- Business logic does not depend directly on `smux` or `yamux` types.
- `max_streams_per_carrier` enforcement.
- No infinite queue tests.
- Basic backpressure tests.
- Context cancellation tests.

### Gate 4, `kavern-agent` TCP Echo Review

- End-to-end TCP echo with `kavern-agent`.
- No stock `npc` involved.
- Local integration test only.

### Gate 5, Real npc Connect Review

- Real stock `npc` binary execution through `NPC_BIN`.
- Device online/offline assertions.
- No fake compatibility accepted.

### Gate 6, Real npc TCP Echo Review

- Stock `npc` end-to-end TCP echo.
- `target_addr` safety.
- Legacy mux boundary.
- Timeouts and cleanup.

### Gate 7, Benchmark Harness Review

- Local benchmark commands.
- Reproducible benchmark parameters.
- No WAN/server benchmark automation requirement.

### Gate 8, Security Review

- Parser limits.
- Auth failure behavior.
- Token handling.
- No secret logs.
- No arbitrary target.
- Disabled tunnel and disabled device semantics.

## Review Requirement

### Gate 6S-4A: Go-Peer Robustness

This phase uses only Go peers, net.Pipe, the production frame codec, and
explicitly joined test workers. It does not execute NPC_BIN or NPS_BIN.
The bounded peer has one reader and one serialized writer; worker failures and
harness overflow return to the owning test instead of calling FailNow from a
worker. State notifications and raw-write barriers replace mux-state polling.
Watchdogs bound failures; sleeps and elapsed-time-only blocked assertions are
not used by the new robustness tests.

| Proof | Tests / acceptance |
| --- | --- |
| Fragmentation, coalescing, partial raw writes | TestLegacyMuxFragmentedCoalescedTransport; production codec, one raw writer |
| Segmentation | TestLegacyMuxSegmentationMatrix; 0, 1, 5, 19, 257, 4084, 4085, 4086, 8192, 65536, 122549, 122550, 122551, 131072, 262144; zero-delta larger-window advertisement isolates shape |
| Receive reconstruction / credit | TestLegacyStreamReceiveReassemblyMatrix; same sizes, partial reads, exact consumed-credit total |
| Initial-window stall | TestLegacyStreamFlowExactInitialWindowThrough262144; exactly 122550 outstanding, next segment unadmitted, valid credit recovery, zero final outstanding |
| Concurrency and local stream limit | TestLegacyMuxConcurrentStreamMatrixAndLocalLimit; 1/2/8/32/64, 65th locally rejected by MaxStreams without 0x06, original streams usable |
| Payload ownership and isolation | TestLegacyStreamQueuedLargeWriteOwnsSourceBuffer; TestLegacyStreamFlowBlockedStreamDoesNotBlockOthers |
| Writer fairness and close barrier | TestLegacyMuxPingWindowDataFairnessBoundedDispatches; 512 selections, <=4 ping burst, <=10 control selections for eligible open/window service, <=16 controls before data/close; TestLegacyMuxCloseBarrierWinsReleasedQueueCapacity |
| Coalesced windows | TestLegacyStreamWindowRepeatedReadsCoalesceOneInflightSlot; immutable in-flight snapshot, pending credit emitted once; malformed states and wait-bit independence |
| Resource ownership | Existing legacy_storage tests plus tiny-wire/high-water tests; explicit counts, nilled references, bounded fixed blocks, no exact heap assertions |
| Pending opens and tombstones | Existing legacy_open_lifecycle tests plus real control-capacity cancellation; unsent/sent distinction, protected expiry, timeout cleanup |
| Liveness | Existing raw-deadline tests plus simultaneous opaque pings and sent-time/exact-pong expiry tests |
| Malformed peers | TestLegacyMuxMalformedWireMatrix, TestLegacyMuxDuplicateResolvedOpenControlIsProtocolFailure, TestLegacyMuxTruncatedFramesStopWorkers; unknown close and late closed-stream data remain scoped |
| Runtime ownership | Existing 6S-3 transition tests plus TestDeviceRuntimeTwoDeviceProtocolIsolationAndRecovery, TestDeviceRuntimeMainAndChanReplacementPolicies, TestDeviceRuntimeConcurrentLeaseCategoriesReturnToZero |
| Sanitized errors / stable EOF | TestLegacyMuxOperationErrorsAreSanitized, TestLegacyMuxOperationErrorsPreserveSafeSentinels, TestLegacyStreamTransportFailureAfterReturnIsSanitized, TestLegacyStreamRemoteEOFRemainsObservedAfterMuxFailure |
| Router / proxy cleanup | TestRouteTCPNilInboundRejectedBeforeStreamCreation, TestRouteTCPNilInboundRequiresCurrentSessionFirst, TestRouteTCPNilInboundRejectsDisabledTunnelAndDeviceFirst, TestRouteTCPCancellationPreservesMetadataOnlyAddress, TestProxyCancellationJoinsBlockedCopies |

The error-boundary and nil-inbound Router tests failed before their associated
correctness fixes. Raw transport failures now expose ErrLegacyMuxClosed, not
address-bearing errors. Normal drained stream EOF and safe protocol/resource
sentinels remain distinguishable. Once a Read observes normal EOF after peer
close and receive-buffer drain, later mux failure cannot change that EOF.
Explicit local Close still takes precedence, including when shutdown has
already marked a live stream fully closed. That call only sets caller-visible
localClosed; it emits no additional close frame and leaves mux maps, tombstones,
and accounting cleared. The deterministic regression covers protocol and
transport failures before EOF, each failure after EOF with cleanup blocked in
a raw write, and repeated Close in every case. Remote close without an observed
EOF does not hide a mux failure. Both protocol and address-bearing transport
failures are covered before and after EOF observation.

Nil Router inbound returns ErrInvalidInboundConnection before OpenStream, so
no remote stream or target dial is initiated. Disabled tunnel, device lookup /
disabled device, and current-session lookup retain precedence over this check.
The previous post-open cleanup workaround is removed. The shared proxy
implementation is unchanged.

Validation:

```sh
export PATH=/usr/local/go/bin:$PATH
gofmt -w ./internal/gateway/legacy_npc ./internal/router ./internal/session ./internal/store
go test ./internal/gateway/legacy_npc ./internal/router ./internal/session ./internal/store
go test -race ./internal/gateway/legacy_npc ./internal/router ./internal/session ./internal/store
go test -race ./internal/gateway/legacy_npc -run 'Test.*(Flow|Window|Concurrent|Close|Tombstone|Ping|Runtime|Replacement|Limit)' -count=100 -timeout=20m
go test -race ./internal/gateway/legacy_npc ./internal/router -run 'Test.*(ExplicitCloseAfterMuxShutdown|RemoteEOF|TransportFailure|NilInbound)' -count=500
go test -shuffle=6042026 -count=20 ./internal/gateway/legacy_npc -timeout=10m
go vet ./internal/gateway/legacy_npc ./internal/router ./internal/session
go test ./...
go test ./internal/gateway/legacy_npc -run '^TestProductionDoesNotImportForbiddenNPSPackages$' -count=1
git diff --check
```

The forbidden-import guard parses ImportSpec declarations in every Go file,
including tests and build-tagged files. Module/require/replace/exclude paths
are read using the Go tool's read-only module parser. Comments, documentation,
error text, and the guard's own literals are not imports.

The 4A review packet must retain failures as well as final successful runs,
shuffle seeds, count/race results, ownership assertions, and the scoped diff.
Passing Go-peer tests is not self-approval to implement 4B.

### Gate 6S-4B: Real Pinned TCP Robustness (Review Pending)

4A passed independent review on 2026-10-09 (local commit e69c133). 4B has
separate real-binary tests; passing them is evidence for review, not self-approval
or completion of the operational MVP.

The reviewed Linux amd64 NPC executable has SHA-256
`13c12ffd3ebbab07b62cfb7e396d2290276a679f00ecb018b44f0db8e5fab2c7`.
It is byte-for-byte the npc member of linux_amd64_client.tar.gz, whose SHA-256
`a2a3ba1caaf304e2015dca2efb65d26fa9483502899c74c6f17b9931cfd0fa42`
matches the official pinned v0.26.34 release asset listing:
https://github.com/yisier/nps/releases/expanded_assets/v0.26.34 .
The new 4B tests require this reviewed binary hash; they do not certify other
platform builds. The executable is a test dependency only and must not enter git.

Canonical Router black-box acceptance stays in tests/legacy_npc. Private
inspection exists only in internal/gateway/legacy_npc/real_npc_companion_test.go,
with the legacy_npc_integration build tag. There is no production or tagged
non-test bridge/API. Both new suites clearly fail if NPC_BIN is absent.
Ordinary go test ./... remains offline and independent of stock binaries.

| Real proof | Black-box / companion |
| --- | --- |
| Byte equality | TestLegacyNPCPayloadMatrix: 1, 5, 19, 257, 4085, 4086, 8192, 65536, 122549, 122550, 122551, 131072, 262144 |
| Sequential reuse | TestLegacyNPCSequential129; TestRealNPCCompanionSequentialGenerationAndOwnership verifies the unchanged device mux generation and zero live stream/reservation/buffer ownership after each |
| Simultaneous streams | TestLegacyNPCConcurrentMatrix: 2/8/16, each 262144 bytes; target accept barrier holds every target connection alive before echo is released |
| Close / lifecycle | TestLegacyNPCClosePaths covers target EOF, public close, route cancel, close before payload, stopping NPC during an active route, and measured half-close; TestLegacyNPCProcessRestartLifecycle and existing TestLegacyNPCMainReplacement |
| Idle / ping | TestLegacyNPCIdleRecovery: explicit 350ms idle; TestRealNPCCompanionIdlePingRecovery waits for at least three additional actual local pings with matching real responses, confirms >2 configured intervals, then echoes 262144 bytes on the same mux |
| Two devices / stored target | TestLegacyNPCMultiDeviceIsolation holds B's target connection alive while A exits; B's session remains current and its large echo completes. Caller-supplied TargetAddr and payload mention B, but A still uses the stored A target |
| Flow credit | TestRealNPCCompanionFlowCredits records real 0x05 consumed deltas and advertised max in both directions for payloads crossing 122550; no enlarged test receive window |
| Replacement / private cleanup | TestRealNPCCompanionMainReplacementCleanup and TestRealNPCCompanionTwoDeviceLeasesAndIsolation: generation isolation, old-mux worker/resource cleanup, surviving device session+chan lease categories, zero runtime map after final gateway worker joins |

All test resources are temporary loopback listeners and targets. NPC process
working directories use t.TempDir, stdout/stderr are not captured as bearer-bearing
logs, and processes are canceled and Wait is joined. Accept loops finish before
joining their workers; target connections, route copies, mux workers and runtime
leases have explicit cleanup checks. A test-only post-auth chan wire tap uses the
production codec, bounded partial-frame buffering and aggregate counters; it
never receives the outer bearer handshake or exposes payload/secret logs.

Readiness is event-driven in private checks. Canonical external Router tests may
retry only ErrLegacyDataChannelUnavailable using a bounded fresh connection;
other protocol/resource/replacement errors fail. Concurrent fixtures use target
accept events, not sleep-based live-stream assertions. The deliberate idle timer
and target half-close read deadline measure those specific scenarios rather than
stand in for state readiness. Test ping interval is 100ms and timeout is 3s;
production defaults remain 5s/15s. The initial allowance and server advertised
receive window remain 122550, and frame content remains at most 4085.

Example real flow evidence: five large companion transfers observed 761766
server-to-NPC data bytes including metadata/framing and the same total NPC
consumed credit, NPC advertised max 191484, and fixed server max 122550.
Server receive-credit totals may vary with read/window/close scheduling because
remote close discards unneeded final pending credit. These counters are wire
observations, not heap or throughput measurements.

Close semantics are deliberately limited: target close yields readable EOF;
public close and cancellation tests explicitly cancel the route to join blocked
copies. They do not claim autonomous TCP EOF propagation. In the bounded real
half-close probe, public CloseWrite succeeds after immediate echo, but the target
has not received write-half EOF by its 150ms read deadline. Independent legacy
TCP half-close is not claimed. No stock chan-only reconnect guarantee, arbitrary
NPS compatibility, indefinite soak, WAN, or production throughput is claimed.

Run the prescribed acceptance with the verified binary (all commands also passed
in race mode; retain full output and failures for review):

```sh
export NPC_BIN="$PWD/.kavern-testbin/nps-v0.26.34/npc"
export GOPROXY=off GOSUMDB=off
go test -race -tags=legacy_npc_integration ./tests/legacy_npc -run '^TestLegacyNPC(TCPEcho|MainReplacement)$' -count=20 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./tests/legacy_npc -run '^TestLegacyNPCPayloadMatrix$' -count=5 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./tests/legacy_npc -run '^TestLegacyNPCSequential129$' -count=3 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./tests/legacy_npc -run '^TestLegacyNPCConcurrentMatrix$' -count=10 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./tests/legacy_npc -run '^TestLegacyNPC(ClosePaths|ProcessRestartLifecycle|IdleRecovery)$' -count=20 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./tests/legacy_npc -run '^TestLegacyNPCMultiDeviceIsolation$' -count=10 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./internal/gateway/legacy_npc -run '^TestRealNPCCompanionSequentialGenerationAndOwnership$' -count=3 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./internal/gateway/legacy_npc -run '^TestRealNPCCompanionFlowCredits$' -count=5 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./internal/gateway/legacy_npc -run '^TestRealNPCCompanion(IdlePingRecovery|MainReplacementCleanup)$' -count=20 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./internal/gateway/legacy_npc -run '^TestRealNPCCompanionTwoDeviceLeasesAndIsolation$' -count=10 -v -timeout=10m
go test -race -tags=legacy_npc_integration ./tests/legacy_npc ./internal/gateway/legacy_npc -count=1 -timeout=5m
go vet -tags=legacy_npc_integration ./tests/legacy_npc ./internal/gateway/legacy_npc
go test ./... -count=1
go test -race ./... -count=1
go build ./...
git diff --check
```

After Gate 0 and after every implementation gate, generated files, diffs, and test output must be reviewed before proceeding to the next gate.

## Runnable local MVP assembly supplement (review pending)

Ordinary offline tests include `cmd/kavernd/TestActualCommandsNativeTLSHalfCloseAndRestart`. It builds all three actual commands with race instrumentation and `-buildvcs=false`, uses temporary state/certificates/credentials and loopback listeners, and verifies TLS, two attached carrier readiness, a byte-exact EOF-dependent 262 KiB response, state-lock exclusion, persisted credentials across restart and graceful shutdown. It needs a local Go toolchain and cached dependencies, never NPC_BIN or internet. `-short` explicitly excludes the process test; final acceptance runs without `-short`.

```sh
go test ./...
go test -race ./...
go test -race ./cmd/kavernd -run TestActualCommandsNativeTLSHalfCloseAndRestart -count=3 -v
go test -race ./internal/dataplane/... ./internal/gateway/agent_v1 -count=20
go vet ./...
go build ./...
```

New regressions cover aggregate pending-write budget/cancellation, combined receive/write budget rejection, pool cap/replacement, native EOF-dependent response, missing/oversized records, canonical injection, metadata short writes, canceled session cleanup, expired-session rejection/detachment, strict JSON ambiguity/limits, encrypted state/wrong-key rejection, private permissions and exclusive state locks. They do not establish WAN performance or the final Gate 8 adversarial matrix.

Assembly deadline review follow-up: `go test -race ./cmd/kavernd -run TestPublicRouteTimeout -count=20` exercises the production connection-handler cleanup with a real framed mux/carrier. An early local socket timeout sends directional request EOF while the peer intentionally remains silent; the per-route deadline must then retire the route, release its lease, make the stream capacity reusable, and free the handler slot without canceling the daemon. A companion test bounds stream opening. The existing actual-process EOF-dependent 262 KiB response test remains unchanged and must still pass.

Gate 7 implementation validation: `go test -race ./experiments/muxbench ./internal/dataplane/carrier -count=10` verifies real loopback smoke payloads, explicit capacity rejection, abort behavior, FD cleanup and exact local budget-wait statistics. The ordinary non-race `go run ./experiments/muxbench -suite matrix -iterations 3` supplies measured performance JSON; race timings are not performance results. See experiments/muxbench/README.md for reproducible parameters and profiling.
