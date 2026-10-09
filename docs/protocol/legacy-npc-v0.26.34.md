# Legacy npc v0.26.34 Protocol Contract

## Status and Boundary

This is the source-informed protocol contract for Kavern's independent compatibility implementation of pinned stock `npc v0.26.34`. It is not a clean-room claim. Wire-required protocol facts may be independently implemented, including `TST`, `sucs`, `vkey`, `main`, `chan`, mux flag numbers, and required Link JSON keys. Kavern must not import, vendor, copy, or reuse `yisier/nps` GPL source-level implementation material: source files, functions, comments, tests, identifiers, queue implementations, window implementations, or other implementation structure. Separate license/compliance review is required before closed-source commercial distribution.

Supported client invocation:

```sh
npc -server=<host:port> -vkey=<vkey>
```

Only server-configured TCP tunnels are in scope. Configuration/file/p2p/secret/register modes, UDP, HTTP routing, the NPS Web UI/API, TLS bridge, and KCP bridge are out of scope.

## Outer Bridge Handshake

The client sends raw `TST`, then signed little-endian int32 length-prefixed core version `0.26.0`, then signed little-endian int32 length-prefixed client version `0.26.34`.

The server writes exactly 32 raw lowercase ASCII hex bytes equal to `md5("0.26.0")`:

```text
89a4f3fc3c89257d6f712de6964bda8e
```

The client sends exactly 32 lowercase ASCII hex bytes for `md5(vkey)`. The server validates this strict raw format before lookup. On authentication failure it writes exactly `vkey`, terminates the handshake, and does not read a role. On success it writes exactly `sucs`; the client then sends exactly four raw bytes, `main` or `chan`.

The wire token is a legacy bearer boundary. Kavern derives its stored lookup key with HMAC-SHA256 and never logs or persists the raw token, raw `md5(vkey)`, or `vkey`.

## Mux Frames

The mux has three frame layouts and nine flags. Every integer is little-endian.

### Content Frame

Flags: `0x00` ping, `0x03` final data, `0x04` continuation data, `0x08` ping response.

```text
uint8 flag
int32 stream_id
uint16 content_length
content
```

`content_length` is valid from zero through the fixed protocol maximum of 4085 bytes. Ping and ping response use stream ID `-1`; data uses a positive stream ID.

### Window Frame

Flag: `0x05` receive-window update.

```text
uint8 flag
int32 stream_id
uint64 window_state
```

Window frames use positive logical stream IDs.

### Fixed Control Frame

Flags: `0x01` stream accepted, `0x02` stream rejected, `0x06` open logical stream, `0x07` close logical stream.

```text
uint8 flag
int32 stream_id
```

Control frames use positive logical stream IDs.

## Ping Contract

Both mux peers independently send `0x00` ping content frames using stream ID `-1`. The ping body is bounded opaque data; its length is variable and implementations must not require a 29-byte or 30-byte body.

On receiving `0x00`, a peer must immediately send `0x08` with stream ID `-1` and the exact same body. Both directions may ping concurrently, and stream opening does not wait for bilateral ping completion.

Pinned v0.26.34 behavior sends an initial ping and repeats approximately every five seconds. Kavern's reviewed mux implements this independently; its liveness interval starts after the complete local ping is transmitted, not when queued.

## Implemented Mux Constraints and Deterministic Review

Gate 6S-2 implements the mux and Gate 6S-3 integrates it into device-scoped runtime ownership. Gate 6S-4A tests these constraints using Go peers only; it does not establish the future 6S-4B real-binary robustness matrix.

- `0x07` is a logical-stream close signal, not a TCP half-close. Receiving it enters closing state, rejects new local writes, wakes blocked writers, drains queued inbound bytes before EOF, and permits at most one local `0x07` cleanup response. Duplicate closes are ignored.
- The mux bounds per-stream and aggregate resources using `MaxStreams`, `MaxBufferedBytesTotal`, and `MaxQueuedFramesTotal`. It reserves global and per-stream capacity before buffering data, and releases ownership on reads, local close/removal, and shutdown. Remote close preserves already buffered bytes until drained or locally discarded.
- Initial peer allowance is 122550. Sending admits a segment only if both queue capacity and outstanding-byte allowance are available; a valid 0x05 reduces outstanding by consumed delta and updates peer max. The wait bit does not control admission. Generated receive credit advertises the fixed local max, with wait and reserved bits clear; receipt of 0x05 does not itself require a response.
- Default local soft/hard receive limits are 122550/126635 bytes. Retained nonempty receive blocks are bounded by ceil(buffered/4085)+1, and an empty queue retains no block slice. The codec may still allocate temporary bounded content bodies.
- Default frame accounting includes queued and in-flight frames: ping/pong cap 16, open/reject cap 72, window cap 64, total control reserve/cap 160, data/close cap 1888, overall cap 2048. The class caps sum to 152; the unused control reserve is not available to data.
- Local close discards unread bytes and orders one cleanup 0x07 after accepted data. Remote close rejects new writes and drains inbound bytes before EOF. Unknown positive closes are ignored without allocation; valid late data for closed/tombstoned streams is discarded locally. Data for a never-existing stream and duplicate accept/reject outside pending/tombstoned state are protocol failures.
- The content limit remains fixed at 4085. Deterministic segmentation tests above the initial allowance explicitly advertise a larger valid peer max; a different test proves stall/recovery through 262144 bytes with the original initial allowance. Neither test is a real-NPC payload acceptance claim.
