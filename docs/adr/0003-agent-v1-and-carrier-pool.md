# ADR 0003: Agent v1 and Carrier Pool

## Status

Accepted for MVP Spec v1.

## Context

Kavern needs a first-party agent protocol that is independent of legacy `npc`. The data plane must support multiple streams while avoiding a single unlimited mux connection.

## Decision

Kavern will define Kavern Agent Protocol v1, KAPv1, served by:

```text
internal/gateway/agent_v1
```

KAPv1 will be handled by `AgentV1Gateway`. Legacy stock `npc` will be handled separately by `LegacyNpcGateway` in:

```text
internal/gateway/legacy_npc
```

Both gateways adapt into the same internal `AgentSession` interface. Business logic only sees `Device`, `Tunnel`, `AgentSession`, and `TunnelRouter`.

In the MVP, one `Device` has at most one active `AgentSession` at a time. A newly authenticated session for the same `Device` replaces the old active session. Historical sessions may be stored later for observability or audit, but routing uses only the current active session. Multi-active sessions, HA sessions, and per-device session pools are out of scope until a later ADR. The carrier pool belongs inside an `AgentSession` and must not be represented as multiple `AgentSession` records.

## KAPv1 Requirements

- Must not use MD5.
- Must not speak the `nps` protocol.
- Must not use `nps_mux`.
- Must include explicit auth.
- Must use a `session_id`.
- Must separate control and data.
- Must not default to `InsecureSkipVerify`.
- Any insecure TLS option must be dev-only, explicit, and documented as unsafe.
- `device_secret` must never be transmitted in plaintext.
- `session_id` alone is not a sufficient bearer credential.
- Data carriers must bind to the authenticated control session using `session_id` plus `carrier_nonce`/HMAC or an equivalent binding.
- Data carriers cannot attach to unauthenticated, expired, disabled, or replaced sessions.

Minimum KAPv1 auth flow:

1. Agent sends `device_id` and `client_nonce`.
2. Server returns `server_nonce` and `auth_challenge_id`.
3. Agent returns `HMAC-SHA256(device_secret, canonical(device_id, client_nonce, server_nonce, protocol_version, transport_role))`.
4. Server verifies without receiving `device_secret`.
5. Server issues `session_id`.

## Carrier Pool Requirements

The data plane must use a bounded data carrier pool.

Each carrier must enforce:

- `max_streams`.
- `max_streams_per_carrier`.
- `max_inflight`.
- `max_buffer`.

The design must not use one unlimited TCP mux connection. Infinite queues are forbidden. Backpressure must be explicit through bounded waits, context cancellation, or clear errors.

## Mux Backend Strategy

Mux backend must be replaceable through an interface. First implementation may use `smux` or `yamux` behind that interface.

Third-party mux packages must be hidden behind Kavern's `MuxBackend` interface. Business logic must not depend directly on `smux`, `yamux`, or other backend-specific types. Gate 3 must include dependency and license review for `smux`, `yamux`, or any mux backend. No GPL, AGPL, or other copyleft dependency may be added without explicit review.

Future comparison targets:

- `smux`
- `yamux`
- `kavernmux`
- Optional QUIC carrier

## Consequences

- `kavern-agent` evolves independently from legacy `npc`.
- Business logic remains protocol-neutral.
- Carrier limits are part of correctness, not just performance tuning.
- Local benchmarks can compare mux implementations without redefining core architecture.
