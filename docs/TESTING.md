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

### Gate 6S-4B: Plan Only

No new real-binary robustness or tagged inspection helper belongs in 4A.
After a separate review, 4B may implement canonical Router matrices under
tests/legacy_npc and narrowly scoped tagged gateway-package companion tests
for private counters. Normal builds must remain NPC_BIN-free. Real 262144-byte
transfers, 129 sequential streams, concurrency through 16, and close-path
results are not claimed by 4A and require separate pinned-NPC evidence.
The source-informed independent implementation and commercial GPL/compliance
review boundary remain unchanged; no independent TCP half-close is claimed.

After Gate 0 and after every implementation gate, generated files, diffs, and test output must be reviewed before proceeding to the next gate.
