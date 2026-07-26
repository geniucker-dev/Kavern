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

Pinned v0.26.34 behavior sends an initial ping and repeats approximately every five seconds. Ping scheduling is documented here only and is not implemented in Gate 6S-1.

## Future Mux Constraints

Phase 6S-2 will implement these semantics; this document does not add a mux implementation.

- `0x07` is a logical-stream close signal, not a TCP half-close. Receiving it enters closing state, rejects new local writes, wakes blocked writers, drains queued inbound bytes before EOF, and permits at most one local `0x07` cleanup response. Duplicate closes are ignored.
- The mux will bound per-stream and aggregate resources using `MaxStreams`, `MaxBufferedBytesTotal`, and `MaxQueuedFramesTotal`. It must reserve global and per-stream capacity before accepting data/metadata and release both budgets on application reads, stream closure/removal, and mux shutdown.
- Future flow control, ping scheduling, stream lifecycle, and data forwarding are outside Gate 6S-1.
