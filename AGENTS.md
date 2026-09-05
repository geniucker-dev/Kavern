# AGENTS.md

This is the canonical project instruction file for the `kavern` repository, generated during Gate 0 specification work.

## Project Identity

- Project, repo, and folder name: `kavern`
- Product name: Kavern
- Server binary: `kavernd`
- First-party agent binary: `kavern-agent`
- CLI binary: `kavernctl`
- New protocol: Kavern Agent Protocol v1, abbreviated KAPv1
- Future mux implementation: `kavernmux`
- Legacy npc gateway package: `internal/gateway/legacy_npc`
- New agent gateway package: `internal/gateway/agent_v1`

## Canonical MVP Package Layout

The canonical MVP package layout is:

```text
cmd/kavernd
cmd/kavern-agent
cmd/kavernctl
internal/domain
internal/store
internal/config
internal/gateway/legacy_npc
internal/gateway/agent_v1
internal/session
internal/router
internal/dataplane/carrier
internal/dataplane/mux
internal/security
internal/observability
internal/testutil
tests/legacy_npc
experiments/muxbench
scripts
docs/adr
```

Later layout changes require an ADR.

## Non-Negotiable Scope

Kavern is a brand-new tunneling project. It is not an `nps` rewrite, not an `nps` fork, and not a compatibility clone. Kavern may partially support stock `npc` from `https://github.com/yisier/nps` as a legacy client, but only for:

```sh
npc -server=<host:port> -vkey=<vkey>
```

The pinned v0.26.34 legacy protocol specification is source-informed. Kavern's implementation is an independent compatibility implementation, not a clean-room claim. Wire-required protocol facts may be independently implemented, including `TST`, `sucs`, `vkey`, `main`, `chan`, mux flag numbers, and required Link JSON keys. Do not copy, vendor, import, or reuse `yisier/nps` GPL source-level implementation material: source files, functions, comments, tests, identifiers, queue implementations, window implementations, or other implementation structure. A separate license/compliance review is required before closed-source commercial distribution.

## Implementation Status

This specification phase does not approve server, agent, protocol, or compatibility implementation. After Gate 0 files are generated, they must be reviewed before any code is written.

## Architecture Rules

- The core model is `User -> Project -> Device -> Tunnel`.
- `vkey` belongs to `Device`, not `User`.
- One `User` can have many `Device` records.
- One `Device` can have many `Tunnel` records.
- One `Device` has at most one active `AgentSession` at a time in the MVP.
- A newly authenticated session for the same `Device` replaces the old active session.
- Historical sessions may be stored later, but routing uses only the current active session.
- Multi-active sessions, HA sessions, and per-device session pools are out of scope until a later ADR.
- The carrier pool belongs inside an `AgentSession` and must not be represented as multiple `AgentSession` records.
- `LegacyNpcGateway` and `AgentV1Gateway` are separate protocol handlers.
- Both protocol handlers adapt into the same internal `AgentSession` interface.
- Business logic may only depend on `Device`, `Tunnel`, `AgentSession`, and `TunnelRouter`.
- Wire protocols must not leak into business logic.

## Security Rules

- Legacy `npc` MD5 handling is only a legacy bearer-token compatibility boundary.
- Stock `npc` sends a legacy wire token expected to be `md5(vkey)` hex.
- `LegacyNpcGateway` validates the wire token format, computes `HMAC-SHA256(server_secret, wire_token)`, and looks up `DeviceCredential`.
- Never log or persist the raw wire token.
- Store `HMAC-SHA256(server_secret, wire_token)`, never raw `wire_token` or raw `md5(vkey)`.
- The raw `vkey` is not needed during connection authentication.
- Kavern generates `vkey` values by default using at least 32 bytes of cryptographic randomness and base64url or equivalent safe encoding.
- Show a `vkey` only once at creation or rotation. Lost `vkey` values cannot be recovered and must be rotated.
- Rotating a `vkey` invalidates the old legacy lookup key.
- `kavern-agent` must not use MD5.
- `kavern-agent` must not speak the `nps` protocol.
- `kavern-agent` must not use `nps_mux`.
- Do not log secrets, raw bearer material, raw vkeys, or derived token material.
- Do not default to `InsecureSkipVerify`. Any insecure TLS option must be dev-only, explicit, and documented as unsafe.
- Disabled devices and disabled tunnels must be enforced by business logic.
- Disabled devices must not authenticate through legacy `npc`.

## KAPv1 Authentication Rules

- `kavern-agent` sends `device_id` and `client_nonce`.
- `kavernd` returns `server_nonce` and `auth_challenge_id`.
- `kavern-agent` returns `HMAC-SHA256(device_secret, canonical(device_id, client_nonce, server_nonce, protocol_version, transport_role))`.
- `kavernd` verifies the response without receiving `device_secret`.
- `kavernd` issues `session_id` only after successful authentication.
- Data carriers must bind to the authenticated control session using `session_id` plus `carrier_nonce`/HMAC or an equivalent binding.
- Data carriers cannot attach to unauthenticated, expired, disabled, or replaced sessions.
- `device_secret` must never be transmitted in plaintext.
- `session_id` alone is not a sufficient bearer credential.

## Legacy npc Compatibility Rules

- Server-side configuration mode only.
- Out of scope: `npc -config`, `conf`, `file`, `p2p`, `secret`, `register`, nps Web UI, and nps API.
- Real stock `npc` compatibility is incomplete unless an integration test actually executes a real `npc` binary from `yisier/nps`.
- Fake clients, mocks, or protocol simulations are not sufficient for acceptance.
- Legacy tests must live under `tests/legacy_npc`.
- Legacy tests must use a build tag such as `legacy_npc_integration`.
- Normal `go test ./...` must not require `NPC_BIN` or internet access.
- When the legacy integration tag is enabled, `NPC_BIN` is required.
- If `NPC_BIN` is missing while the tag is enabled, tests must fail clearly and must not silently skip.

## Data Plane Rules

- Mux is required.
- Do not use HTTP/2 as the core raw TCP data plane.
- Do not design one unlimited TCP mux connection.
- Design control/data separation.
- Design a data carrier pool.
- Each carrier must enforce `max_streams`, `max_inflight`, and `max_buffer`.
- Mux backend must be replaceable through an interface.
- First implementation may use `smux` or `yamux` behind the interface.
- Future benchmarks should compare `smux`, `yamux`, `kavernmux`, and an optional QUIC carrier.

## Review Gates

After Gate 0 and after every implementation gate, generated files, diffs, and test output must be reviewed before proceeding to the next gate.

1. Gate 0, Spec Review: `AGENTS.md`, `docs/SPEC.md`, `docs/TESTING.md`, `docs/BENCHMARK_PLAN.md`, `docs/adr/*.md`, `MILESTONES.md`.
2. Gate 1, Core Skeleton Review: domain, store, legacy vkey helpers, `SessionManager`, `TunnelRouter` skeleton, fake `AgentSession` tests, legacy npc integration test harness.
3. Gate 2, AgentV1 Review: KAPv1 auth, `session_id`, control/data separation, no MD5, no `InsecureSkipVerify` default, fake data carrier tests.
4. Gate 3, Carrier Pool / Mux Review: `MuxBackend` interface, `smux`/`yamux` backend, `max_streams_per_carrier`, no infinite queue, basic backpressure, tests, dependency/license review, no GPL/AGPL/copyleft mux dependency without explicit review, third-party mux packages hidden behind Kavern's `MuxBackend`, and no business logic dependency on `smux`/`yamux` types.
5. Gate 4, `kavern-agent` TCP Echo Review: first-party agent end-to-end TCP echo, no npc involved, local integration test.
6. Gate 5, Real npc Connect Review: real stock `npc` binary test, `NPC_BIN` test contract, device online/offline, no fake compatibility.
7. Gate 6, Real npc TCP Echo Review: stock `npc` end-to-end TCP echo, `target_addr` safety, legacy mux boundary, timeouts.
8. Gate 7, Benchmark Harness Review: `experiments/muxbench`, local benchmarks only, WAN benchmark explicitly manual, `smux`/`yamux`/`kavernmux` comparison plan.
9. Gate 8, Security Review: parser limits, auth, token handling, no secret logs, no arbitrary target, disabled tunnel/device semantics.

### Gate 6S Sequencing

- Gate 6S-1 and Gate 6S-2 have passed review. Gate 6S-3 session/gateway integration and real pinned `NPC_BIN` TCP echo are the current approved scope.
- Gate 6S-3 legacy ownership is device-scoped: legacy main generations and the current legacy mux are independent runtime fields. Replacing a legacy main does not inherently close the device's current mux; replacing a chan closes only the old mux.
- Authenticated legacy main transitions register device-runtime interest before serialization. A chan remains retained while any live current/attached legacy main or pending main transition exists; state notifications are wakeups, not readiness truth.
- Legacy main runtime leases and pending-transition interest are acquired atomically. Each authenticated main starts one lifecycle-bound connection monitor before transition serialization; no later code may read that main connection concurrently.
- Gate 6S-4 robustness work is not approved in the current goal.
- Each Gate 6S subphase requires its own review; no later Gate 6S subphase may begin before the prior subphase passes review.

## Validation Expectations

Before completing any implementation milestone, run the relevant tests and validators. Normal validation must keep `go test ./...` offline and independent of `NPC_BIN`.
