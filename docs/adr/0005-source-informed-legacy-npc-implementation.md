# ADR 0005: Source-Informed Legacy npc Implementation

## Status

Accepted.

## Context

Kavern supports a narrow compatibility boundary for pinned stock `npc v0.26.34`. The owner approved use of a documented protocol specification informed by the corresponding upstream source, while retaining an independent implementation and strict GPL boundary.

## Decision

Kavern will implement only the documented v0.26.34 server-side TCP compatibility contract for:

```sh
npc -server=<host:port> -vkey=<vkey>
```

This is a source-informed independent compatibility implementation, not a clean-room claim. Wire-required protocol facts may be independently implemented, including `TST`, `sucs`, `vkey`, `main`, `chan`, mux flag numbers, and required Link JSON keys. Kavern must not import `ehang.io/nps`, `github.com/yisier/nps`, or `github.com/yisier/nps-mux`; it must not copy, vendor, or reuse GPL source-level implementation material: source files, functions, comments, tests, identifiers, queue implementations, window implementations, or other implementation structure.

The protocol contract lives in `docs/protocol/legacy-npc-v0.26.34.md`. It defines one outer bridge handshake, three mux frame layouts, and nine mux flags. Future mux work must use bounded queues and aggregate limits for streams, buffered bytes, and queued frames.

Receiving logical-stream close `0x07` will be treated as a stream close, not TCP half-close: it rejects new local writes, wakes blocked writers, drains already queued inbound bytes before EOF, and allows at most one local close response. Duplicate close is ignored.

Legacy online signal and tunnel-mux ownership are independent fields of a
Kavern-owned, device-scoped runtime. The runtime records the newest
authenticated legacy main candidate, the exact legacy main confirmed current
by `SessionManager`, and at most one mux generation. Legacy-main replacement
does not inherently close the current mux or already returned logical streams;
chan replacement closes only the prior mux. A chan may wait boundedly for a
legacy main even when another protocol is currently registered for the device.

Runtime storage is refcounted by explicit main-transition, main-session, and
chan-handler leases. Entries are removed only after every owner has completed
state cleanup, so repeated replacements do not create permanent per-device
state.

Pending authenticated main transitions are counted separately from runtime
leases. A pending transition is device main interest even while queued behind
another transition or while `SessionManager.Attach` is closing a replaced
session. Failed, canceled, superseded, and successful transitions decrement the
count exactly once before deciding whether an orphaned mux should close.
Manager consistency queries and detaches each receive a fresh bounded cleanup
context.

Main runtime acquisition atomically reserves the transition lease, session
lease, and pending-transition interest under the runtime-map-to-device-runtime
lock order. A single post-handshake monitor owns subsequent reads from each
main connection and binds EOF and parent cancellation to session lifecycle.
Candidate publication, stream admission, liveness checks, and attachment commit
all reject a canceled lifecycle.

## Consequences

Gate 6S-4 is split into independently reviewed phases. Gate 6S-4A tests the
existing implementation with deterministic Go peers and permits only
regression-backed correctness fixes. Gate 6S-4B remains plan-only until that
review passes; real binary acceptance remains the compatibility oracle.

Mux transport failures must be normalized at the mux/stream boundary, including
after streams have been returned to Router. Safe protocol/resource/context
sentinels remain distinguishable; raw network addresses are not returned.
This does not change the shared proxy's half-close behavior or add a legacy
half-close capability. Resource tests measure explicit ownership and completion,
not heap-size or goroutine-count heuristics.

- Compatibility remains limited to server-configured TCP tunnels.
- No upstream package enters Kavern's import graph.
- Real pinned-binary integration remains the acceptance oracle.
- A separate legal/license/compliance review is required before closed-source commercial distribution.
