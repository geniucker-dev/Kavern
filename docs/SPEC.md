# Kavern Specification

Kavern is a brand-new tunneling project in the `kavern` repository. This document specifies product scope and architecture for review only. This specification phase does not approve implementation. After Gate 0 files are generated, they must be reviewed before any code is written.

## Names

| Concept | Name |
| --- | --- |
| Project, repo, folder | `kavern` |
| Product | Kavern |
| Server binary | `kavernd` |
| First-party agent binary | `kavern-agent` |
| CLI binary | `kavernctl` |
| New protocol | Kavern Agent Protocol v1, KAPv1 |
| Future mux | `kavernmux` |
| Legacy npc gateway package | `internal/gateway/legacy_npc` |
| New agent gateway package | `internal/gateway/agent_v1` |

## Implementation Status

This Gate 0 specification phase does not approve implementation. Do not create server code, agent code, Go files, `go.mod`, fake compatibility code, implementation directories, or scripts until the relevant review gate explicitly approves that work.

## Goals

- Provide a Kavern-native tunneling system with clear domain, control plane, and data plane boundaries.
- Support the first-party `kavern-agent` using KAPv1.
- Partially support stock `npc` from `https://github.com/yisier/nps` as a legacy client.
- Keep business logic independent of wire protocol details.
- Use a bounded, replaceable mux data plane with carrier-pool limits.

## Explicit Out of Scope

- Rewriting `nps`.
- Forking `nps`.
- Copying, importing, vendoring, or reusing `yisier/nps` GPL code, source files, identifiers, comments, tests, queue implementations, or window implementations.
- Full stock `npc` compatibility.
- `npc -config`.
- `conf`.
- `file`.
- `p2p`.
- `secret`.
- `register`.
- nps Web UI.
- nps API.
- Using HTTP/2 as the core raw TCP data plane.
- One unlimited TCP mux connection.
- Production performance claims from local-only benchmarks.

## Text Architecture Diagram

```text
                 +------------------+
                 | User / kavernctl |
                 +---------+--------+
                           |
                           v
                    +------+------+
                    |  kavernd    |
                    +------+------+
                           |
         +-----------------+-----------------+
         |                                   |
         v                                   v
+------------------+              +------------------+
| LegacyNpcGateway |              |  AgentV1Gateway  |
| legacy_npc pkg   |              |  agent_v1 pkg    |
+--------+---------+              +---------+--------+
         |                                  |
         +----------------+-----------------+
                          |
                          v
                  +-------+--------+
                  |  AgentSession  |
                  +-------+--------+
                          |
        +-----------------+-----------------+
        |                                   |
        v                                   v
+---------------+                  +----------------+
| TunnelRouter  |                  | SessionManager |
+-------+-------+                  +----------------+
        |
        v
+---------------+        +---------------------+
| Device/Tunnel | <----> | Active Session      |
| Business Core |        | CarrierPool inside  |
+---------------+        | MuxBackend          |
                         +---------------------+
```

Wire protocols terminate in gateway packages. Business logic sees only domain objects and internal interfaces.

## Canonical MVP Package Layout

This layout is canonical for MVP. AGENTS.md must match it. Later layout changes require an ADR.

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

`scripts/build-npc.sh` or `scripts/fetch-npc.sh` are future placeholders for obtaining a real stock `npc` binary from a pinned `yisier/nps` tag. They must not be created during Gate 0. They must not use `master` or `latest`, and they must not vendor `yisier/nps` source into this repository. The pinned tag or version must be documented in `docs/TESTING.md` before Gate 5 starts.

## Data Model

```text
User 1 -- n Project
Project 1 -- n Device
Device 1 -- n Tunnel
Device 1 -- n DeviceCredential
Device 1 -- 0..1 active AgentSession
Tunnel n -- 1 TunnelRoute
```

### User

- Owns projects.
- Does not own legacy `vkey` directly.

### Project

- Groups devices and tunnels.
- Provides administrative scope.

### Device

- Belongs to one project.
- Owns the legacy `vkey`.
- Can have many tunnels.
- Can be disabled independently from tunnels.
- Has at most one active `AgentSession` at a time in the MVP.
- A newly authenticated session replaces the old active session for that device.
- Disabled devices must not authenticate through KAPv1 or legacy `npc`.

### Tunnel

- Belongs to one device.
- Defines protocol, public listener policy, target address policy, and enabled state.
- TCP is required for MVP.
- HTTP is a placeholder until explicitly approved.

### Legacy Credential

- `vkey` is generated by Kavern by default, not chosen by users.
- `vkey` generation must use at least 32 bytes of cryptographic randomness.
- `vkey` should be encoded with base64url or an equivalent safe encoding.
- `vkey` is shown only once at creation or rotation.
- Raw `vkey` is not stored.
- Lost `vkey` values cannot be recovered and must be rotated.
- Rotating a `vkey` invalidates the old legacy lookup key.
- Stock `npc` sends a legacy wire token expected to be `md5(vkey)` hex.
- The wire token is a legacy bearer token only.
- Store only `HMAC-SHA256(server_secret, wire_token)`.
- Never store raw `vkey`, raw wire token, or raw `md5(vkey)`.
- The new `kavern-agent` must not use MD5.

### AgentSession

- One `Device` has at most one active `AgentSession` at a time in the MVP.
- Routing uses only the current active session.
- Historical sessions may be stored later for observability or audit.
- Any list method is for observability/history only, not routing.
- Multi-active sessions, HA sessions, and per-device session pools are out of scope until a later ADR.
- The carrier pool belongs inside an `AgentSession` and must not be modeled as multiple `AgentSession` records.

## Core Go Interfaces

These interfaces are architecture targets. They are not implementation approval.

```go
type AgentSession interface {
    ID() SessionID
    DeviceID() DeviceID
    Protocol() AgentProtocol
    OpenStream(ctx context.Context, req StreamOpenRequest) (AgentStream, error)
    Close(ctx context.Context) error
    Done() <-chan struct{}
}

type AgentStream interface {
    io.Reader
    io.Writer
    Close() error
}

type TunnelRouter interface {
    RouteTCP(ctx context.Context, tunnel Tunnel, inbound net.Conn) error
    ResolveTunnel(ctx context.Context, listener ListenerRef) (Tunnel, error)
}

type SessionManager interface {
    Attach(ctx context.Context, session AgentSession) error
    Detach(ctx context.Context, sessionID SessionID) error
    CurrentForDevice(ctx context.Context, deviceID DeviceID) (AgentSession, error)
    ListForDevice(ctx context.Context, deviceID DeviceID) ([]AgentSessionInfo, error) // observability/history only
}

type MuxBackend interface {
    Name() string
    Client(conn net.Conn, cfg MuxConfig) (MuxSession, error)
    Server(conn net.Conn, cfg MuxConfig) (MuxSession, error)
}

type MuxSession interface {
    OpenStream(ctx context.Context) (MuxStream, error)
    AcceptStream(ctx context.Context) (MuxStream, error)
    Close() error
}

type CarrierPool interface {
    Acquire(ctx context.Context, req StreamOpenRequest) (CarrierLease, error)
    Release(lease CarrierLease)
    Close() error
}
```

## Gateway Boundaries

### `LegacyNpcGateway`

- Lives in `internal/gateway/legacy_npc`.
- Handles only stock `npc -server=<host:port> -vkey=<vkey>`.
- Uses server-side tunnel configuration.
- Adapts legacy protocol state into `AgentSession`.
- Receives the legacy wire token expected to be `md5(vkey)` hex.
- Validates the wire token format.
- Computes `HMAC-SHA256(server_secret, wire_token)` for lookup.
- Never logs or persists the raw wire token.
- Never needs the raw `vkey` during connection authentication.
- Isolates all legacy MD5 compatibility handling.
- Does not define business rules.
- Uses the source-informed, independently implemented pinned v0.26.34 wire contract in `docs/protocol/legacy-npc-v0.26.34.md`. This is not a clean-room implementation claim; it requires separate GPL/compliance review before closed-source commercial distribution.

### Legacy npc Protocol Boundary

The legacy gateway supports only the pinned stock `npc v0.26.34` bridge handshake and TCP tunnel compatibility described in `docs/protocol/legacy-npc-v0.26.34.md`. It uses one outer bridge handshake, three mux frame layouts, and nine mux flags. Kavern must not import, vendor, copy, or reuse upstream GPL implementation material. The gateway's internal implementation remains separate from business logic and KAPv1.

### `AgentV1Gateway`

- Lives in `internal/gateway/agent_v1`.
- Handles KAPv1 for `kavern-agent`.
- Must not use MD5.
- Must not speak the `nps` protocol.
- Must not use `nps_mux`.
- Must use explicit KAPv1 auth and `session_id`.
- Must keep control and data separated.
- Must bind data carriers to the authenticated control session with more than `session_id` alone.
- Must reject data carriers for unauthenticated, expired, disabled, or replaced sessions.

## KAPv1 Online Lifecycle

1. `kavern-agent` starts with server address, device credential, and configuration.
2. `kavern-agent` connects to `kavernd` using KAPv1.
3. `kavern-agent` sends `device_id` and `client_nonce`.
4. `kavernd` returns `server_nonce` and `auth_challenge_id`.
5. `kavern-agent` returns `HMAC-SHA256(device_secret, canonical(device_id, client_nonce, server_nonce, protocol_version, transport_role))`.
6. `kavernd` verifies the response without receiving `device_secret`.
7. `kavernd` issues `session_id`.
8. `AgentV1Gateway` registers an `AgentSession` with `SessionManager`.
9. If another active session exists for the device, the newly authenticated session replaces it.
10. Control channel reports device state, tunnel readiness, and carrier availability.
11. Data carriers bind to the authenticated control session using `session_id` plus `carrier_nonce`/HMAC or an equivalent binding.
12. Data carriers join the bounded carrier pool inside the active `AgentSession`.
13. `TunnelRouter` routes inbound tunnels through `SessionManager.CurrentForDevice`.
14. On disconnect or replacement, `SessionManager` marks the session offline and releases carrier resources.

`device_secret` must never be transmitted in plaintext. `session_id` alone is not a sufficient bearer credential. TLS must not default to `InsecureSkipVerify`; any insecure TLS option must be dev-only, explicit, and documented as unsafe.

## Stock npc Online Lifecycle

1. Operator starts stock `npc` as:

   ```sh
   npc -server=<host:port> -vkey=<vkey>
   ```

2. `LegacyNpcGateway` accepts the legacy connection.
3. Stock `npc` sends a legacy wire token expected to be `md5(vkey)` hex.
4. `LegacyNpcGateway` validates the wire token format.
5. `LegacyNpcGateway` computes `HMAC-SHA256(server_secret, wire_token)`.
6. `LegacyNpcGateway` looks up the matching `DeviceCredential`.
7. The raw wire token is never logged or persisted.
8. The raw `vkey` is not needed during connection authentication.
9. Matching non-disabled device is loaded.
10. Server-side tunnel configuration is attached to that device.
11. Gateway adapts the connection into an `AgentSession`.
12. `SessionManager` makes it the current active session for the device, replacing any old active session.
13. On disconnect or replacement, session and device presence are updated.

Real stock `npc` compatibility is not complete unless an integration test actually executes a real `npc` binary from `yisier/nps`.

## TCP Tunnel Flow

```text
client
  |
  v
kavernd TCP listener
  |
  v
TunnelRouter.ResolveTunnel
  |
  v
check Project / Device / Tunnel enabled state
  |
  v
SessionManager.CurrentForDevice
  |
  v
AgentSession.OpenStream
  |
  v
CarrierPool.Acquire
  |
  v
AgentSession carrier pool
  |
  v
MuxBackend stream
  |
  v
agent connects to configured target_addr
  |
  v
bidirectional copy with deadlines, limits, and cancellation
```

`target_addr` must be constrained by server-side tunnel configuration. Legacy `npc` must not be allowed to request arbitrary targets.

## HTTP Tunnel Placeholder

HTTP tunnel support is a placeholder. The data model may reserve tunnel protocol values for HTTP, but implementation is not part of MVP until a later reviewed milestone. HTTP support must not weaken TCP security boundaries, target policy, or protocol isolation.

## Data Plane

- Mux is required for TCP data.
- Control and data channels must be separated.
- A single unlimited mux connection is forbidden.
- Data carriers are pooled and bounded inside the active `AgentSession`.
- Each carrier has:
  - `max_streams`
  - `max_inflight`
  - `max_buffer`
- Queues must be bounded. Infinite queues are forbidden.
- Backpressure must be visible to callers as blocking with context cancellation or a clear error.
- `MuxBackend` must make the mux replaceable.
- Initial implementation may use `smux` or `yamux`.
- Future backends to compare: `smux`, `yamux`, `kavernmux`, optional QUIC carrier.
- Third-party mux packages must be hidden behind Kavern's `MuxBackend` interface.
- Business logic must not depend directly on `smux`, `yamux`, or other backend-specific types.
- Gate 3 requires dependency and license review for `smux`, `yamux`, or any mux backend.
- No GPL, AGPL, or other copyleft mux dependency may be added without explicit review.

## Security Boundaries

- Legacy MD5 exists only in `internal/gateway/legacy_npc` or a narrowly scoped legacy vkey helper.
- No raw `vkey`, raw wire token, raw `md5(vkey)`, or secret material in logs.
- KAPv1 auth must not use MD5.
- TLS configuration must not default to `InsecureSkipVerify`.
- Any insecure TLS option must be dev-only, explicit, and documented as unsafe.
- `device_secret` must never be transmitted in plaintext.
- `session_id` alone is not a sufficient bearer credential.
- Data carriers cannot attach to unauthenticated, expired, disabled, or replaced sessions.
- Parsers must enforce size, frame, and timeout limits.
- Disabled devices cannot establish sessions.
- Disabled tunnels cannot accept traffic.
- Tunnel target addresses come from server-side configuration.
- No arbitrary client-supplied target for legacy `npc`.
- Business logic must not import legacy protocol packages.

## Real npc Integration Test Plan

Legacy integration tests must follow this contract:

- Normal `go test ./...` must not require internet or `NPC_BIN`.
- Tests live under `tests/legacy_npc`.
- Tests use a build tag such as `legacy_npc_integration`.
- When the build tag is enabled, `NPC_BIN` is required.
- If `NPC_BIN` is missing, tests fail clearly and do not silently skip.
- Fake npc compatibility tests are not sufficient for acceptance.
- Supported invocation is only `npc -server=<host:port> -vkey=<vkey>`.
- Server-side config defines tunnel behavior.

Example command shape:

```sh
go test -tags=legacy_npc_integration ./tests/legacy_npc
NPC_BIN=/path/to/npc go test -tags=legacy_npc_integration ./tests/legacy_npc
```

The first command must fail clearly if `NPC_BIN` is unset. The second command may pass if the real stock `npc` binary is valid.

## Mux Benchmark Plan

Local loopback benchmarks may be implemented under `experiments/muxbench`. They compare mux behavior under controlled local conditions and must not claim production performance.

Backends to compare:

- `smux`
- `yamux`
- `kavernmux`
- Optional QUIC carrier

Metrics:

- Throughput.
- Latency.
- p95 and p99 latency.
- CPU.
- Memory.
- Goroutines.
- File descriptors.
- Stream open failures.
- Backpressure behavior.
- Behavior under `max_streams`, `max_inflight`, and `max_buffer`.

Full WAN/server benchmark requires human deployment and is not an autonomous acceptance gate.

## MVP Milestone Sequence

1. Gate 0, Spec Review.
2. Gate 1, Core Skeleton Review.
3. Gate 2, AgentV1 Review.
4. Gate 3, Carrier Pool / Mux Review.
5. Gate 4, `kavern-agent` TCP Echo Review.
6. Gate 5, Real npc Connect Review.
7. Gate 6, Real npc TCP Echo Review.
8. Gate 7, Benchmark Harness Review.
9. Gate 8, Security Review.

After Gate 0 and every implementation gate, generated files, diffs, and test output must be reviewed before proceeding.
