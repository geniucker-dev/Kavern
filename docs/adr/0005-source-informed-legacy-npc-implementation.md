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

## Consequences

- Compatibility remains limited to server-configured TCP tunnels.
- No upstream package enters Kavern's import graph.
- Real pinned-binary integration remains the acceptance oracle.
- A separate legal/license/compliance review is required before closed-source commercial distribution.
