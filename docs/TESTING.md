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

If the tag is enabled without `NPC_BIN`, the expected result is a clear failure explaining that `NPC_BIN` is required.

## Stock npc Binary Acquisition

The repository may later include placeholders:

- `scripts/build-npc.sh`
- `scripts/fetch-npc.sh`

These scripts may fetch or build stock `npc` from a pinned `yisier/nps` tag. They must not vendor `yisier/nps` source into this repository.

Before Gate 5 starts, a pinned `yisier/nps` tag or version must be selected and documented here. `scripts/build-npc.sh` and `scripts/fetch-npc.sh` must not use `master` or `latest`. The scripts may clone or download into temporary, cache, or testbin locations, but must not vendor `yisier/nps` source into the Kavern repository.

The pinned tag or version must be documented here before the scripts are accepted:

```text
Pinned yisier/nps tag: TBD during implementation review
Source: https://github.com/yisier/nps
Vendoring allowed: no
```

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

After Gate 0 and after every implementation gate, generated files, diffs, and test output must be reviewed before proceeding to the next gate.
