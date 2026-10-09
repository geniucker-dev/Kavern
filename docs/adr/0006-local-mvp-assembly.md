# ADR 0006: Local MVP assembly and native directional EOF

## Status

Accepted after independent r2 assembly review on 2026-10-09; committed as `2b814ec`. Extends the accepted Gate 2/3/4 interfaces without changing the canonical package layout.

## Decision

The MVP commands use strict JSON configuration and an exclusively locked, atomically replaced local state file. Domain records and legacy HMAC lookup keys are stored in the private state file; native device secrets use AES-256-GCM with an external 32-byte master key and device-bound associated data. Configuration contains environment variable names, not credentials. Administration is offline and requires a daemon restart. Existing TLS certificate/key/CA files are supplied explicitly; native transport always verifies certificates.

KAPv1 control and data use separate verified TLS TCP connections. The first bounded JSON frame declares version and transport role. Authentication uses the existing canonical HMAC bytes and nonce challenge. Each carrier independently proves binding to the current session. The control owner retires its session on disconnect, replacement, expiry or shutdown. Session ID alone remains insufficient. Server-confirmed carrier readiness precedes agent-ready output.

Carrier limits cover streams, owned pending synchronous write payload, and the combined backend receive/write payload budget. Native defaults are 64 streams, 1 MiB inflight, 8 MiB combined buffer, two agent carriers and four maximum carriers. Buffer accounting reserves the maximum 16-bit backend wire frame size, including peers that ignore the outbound frame setting. Pending writes are bounded and cancellable. Canceling an in-progress backend write retires its carrier to unblock transport I/O, then joins the callback; other streams on that carrier may end, and application bytes are never replayed. This payload budget excludes runtime, TLS and kernel object overhead.

Native mux streams use four-byte big-endian record lengths with payloads of at most 16 KiB; a zero-length record marks directional EOF. Invalid lengths and incomplete records fail. Readers consume payload directly into caller buffers without allocating full records. CloseWrite sends logical EOF while preserving the opposite read direction; full Close is independent and idempotent.

This framing is implemented inside Kavern's mux adapter. It is independent Kavern code, uses no legacy wire protocol, and exposes no third-party types to business logic. Future mux implementations must preserve this stream contract or use the same adapter. The pinned smux dependency and MIT license remain unchanged.

## Evidence and consequences

An actual race-built server/agent process test with an EOF-dependent 262 KiB response exposed truncation when the native adapter forwarded CloseWrite directly to smux v1.5.57: only 261,120 response bytes arrived. The same exact byte assertion passes using directional EOF records. A stronger delayed-reader regression retains a 280,010-byte response until the writer closes: all 20 raw-FIN baseline runs lose the entire response, while 20 framed runs preserve every byte. Two additional actual-process baseline runs passed, confirming that the process-level symptom is timing-dependent; the delayed-reader regression supplies deterministic causal evidence. The dependency's bidirectional FIN cleanup can reclaim unread buffered data, so its raw CloseWrite is not the Kavern EOF contract. No dependency source is copied, modified or vendored.

The local state lock implementation supports Linux and explicitly rejects other platforms. CLI/state mutations refuse an active daemon. No management API, Web UI, public deployment, KCP bridge, QUIC carrier or extra mux dependency is introduced. Normal tests remain offline and NPC_BIN-free; real npc integration retains its separate tagged contract.

## Gate 8 security supplement (independent review passed: 2026-10-09)

Session history is a process-wide bounded sequence of at most 1,024 recently attached session facts, replacing the unbounded per-device slices. Oldest facts are evicted even for a still-current device; current routing indexes remain independent. Historical facts are observability only, not a durable audit log. This requires no package or protocol change. Standalone LegacyNpcGateway.Serve has a 256-handler bound and lifecycle-bound cancellation/connection closure with worker joins; the daemon's shared admission limit remains unchanged. Native stream metadata uses the same duplicate/unknown/UTF-8/trailing/depth JSON rejection rules as control frames and validates canonical bounded tunnel IDs.
