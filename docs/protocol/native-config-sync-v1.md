# Native configuration synchronization: Slice B core checkpoint

Review draft, 2026-10-12. Base is independently reviewed Slice A commit `4f7ef2272e868f0eb68c8629f24a403c401e5ecb`. This checkpoint implements opt-in protocol primitives and Go-peer control loops. The current command `ServeTransport`/`RunAgent`, agent JSON bootstrap, stream metadata, public routing/listeners and mux remain unchanged. It does not complete production rollout or the full [acceptance contract](../NATIVE_CONFIG_ACCEPTANCE.md).

## Authentication boundary

`BeginSyncAuth` and `CompleteSyncAuth` select only schema 1. Selection is stored with the one-use challenge and authenticated session. Sync auth appends the exact ASCII line `config_sync_version=1\n` to the existing canonical KAPv1 control HMAC input. `BindSyncCarrier` appends the same line to the existing canonical carrier-binding input, which already includes session/device/nonces/version/transport role. Old and sync signatures cannot authenticate in the opposite mode. Session IDs remain insufficient for carrier authentication.

These are opt-in APIs; no auth wire handshake is deployed by this checkpoint. A future transport adapter must require the selected schema before session attachment and echo/verify it in the challenge. `ConfigServer.Run` requires the verified TLS control connection that produced its SyncAuthResult. Tests exercise these APIs with synthetic fixture credentials and net.Pipe; this is not a new cleartext listener or TLS setting.

The server validates enabled device, current authenticated session, selected schema, closure and expiry before protocol-state publication. Replacement interrupts and closes blocked control I/O and joins workers. Sync sessions remain explicitly unroutable through AgentSession.OpenStream, including after protocol ACK, until the later reviewed stream-metadata/routing rollout. Existing schema-0 native command sessions retain their previous behavior.

## Transfer codec

Frames retain the existing four-byte unsigned big-endian payload-length prefix and maximum 4,096-byte JSON payload. UTF-8, duplicate/case-alias keys, unknown fields, trailing JSON and nesting use the existing strict decoder. Message schemas additionally require exact canonical lowercase keys, required fields and non-null values, including policy/tunnel objects. Fields valid for another message type are rejected.

Every message has `version=kapv1`, `config_sync_version=1`, `type`, `device_id` and `session_id`. Configuration messages additionally have nonzero canonical decimal-string `revision` and `transfer_id`. Transfer IDs are session-local counters, not credentials. Fresh sessions begin with no installed/applied configuration and receive a full transfer even at the previous durable revision.

| Type | Additional required fields |
| --- | --- |
| config_begin | count, total_bytes, policy |
| config_tunnel | index, tunnel |
| config_end | count, total_bytes |
| config_ack | none |
| config_reject | code |
| ping / pong | no revision/transfer fields |

`policy` contains exactly `carriers`, `max_streams`, `max_inflight`, `max_buffer`; Slice A bounds apply. `tunnel` contains exactly `tunnel_id`, `protocol=tcp`, `target_addr`; IDs and native targets retain the 128/512-byte bounds. Count may be zero and is at most 1,024. Indices start at zero and are contiguous. Tunnel IDs must be unique and sorted. Reject codes are limited to `invalid_config`, `capacity`, `unsupported`; the core retires a rejected/malformed session and does not transmit arbitrary error text.

The sender computes total_bytes from the complete encoded begin/entry/end JSON payloads, including scope/envelope overhead; four-byte prefixes and interleaved heartbeats are excluded. The self-referential total is resolved before sending. Limit is 1 MiB and at most 1,026 transfer frames. A valid domain projection may exceed the wire budget once envelopes are added and must then fail before sending. Receiver counts actual received payload bytes and requires exact count/total agreement at end.

## State, scheduling and cleanup

One receiver staging transfer and one immutable installed snapshot are allowed per control session. Installation occurs under one lock after complete validation, before ACK. Caller snapshots are copies. Omission replaces the full set; empty sets are valid. The core never dials targets or probes reachability. Installation/ACK are protocol application facts, not routing, carrier or listener readiness.

The default process-shared staging budget is 16 MiB. An injected budget must be shared across all peers using that budget; tests use shared instances. Sender plans and receiver staging reserve their declared payload and release exactly once on success, rejection, timeout, replacement, disconnect or cancellation. Begin must declare enough bytes for its count and minimum envelopes before allocating the staging slice; a tiny declaration cannot allocate a large map. These are payload bounds, not a process RSS promise.

One control reader feeds at most eight queued frames; the coordinator is the only writer/state dispatcher and generates one outgoing entry at a time. Queued heartbeat/ACK events are serviced between entries. Queue backpressure has the five-second write budget and retires the connection if exhausted. A coalesced one-slot desired wakeup re-reads the owned snapshot source; notifications are not desired-state truth.

Receive/validation/ACK uses a fixed ten-second absolute transfer budget. The receiver starts it at the first byte of begin, not delayed dispatcher processing. Partial frames have a five-second progress budget separate from thirty-second idle waiting. Each control write is bounded by five seconds and the remaining transfer deadline. Heartbeats and partial progress never extend a transfer; expiry during a blocked write is reported as transfer expiry. Native session expiry remains the existing one-hour absolute cap.

The server accepts ACK only for the exact device/session/revision/transfer tuple after all transfer frames were sent. An identical last ACK is harmless; it cannot advance state or reset a deadline. Old/future/wrong-scope ACKs fail closed. If desired revision advances in flight, its old ACK records only that old application fact; the latest source is fetched and transferred next. Wakeups do not accumulate snapshots. Changing policy requires reconnect; this core does not resize carriers in place.

Control exit cancels connection I/O and joins the reader/lifecycle monitor; it releases reservations and clears volatile installed/applied state. Replacement can interrupt a blocked write immediately. No application bytes are replayed. The server's public applied-revision getter revalidates current-session authority and does not expose raw session/HMAC/nonce values as operator status.

## Evidence and remaining work

Tests use own Go peers/net.Pipe and injected short timings/clock boundaries. They cover schema/HMAC separation and nonce replay; malformed, fragmented, truncated, oversized and noncanonical frames; exact wire accounting; scoped order/count/byte validation; empty/reconnected/replaced sessions; atomic installation and copied results; sixteen-MiB aggregate exhaustion; queue saturation; coalesced updates, duplicate/wrong ACKs; heartbeat interleaving without extending expiry; partial-read timeout; blocked-write replacement and joined cleanup.

The frozen patch/manifest and exact validation commands are in the task's Slice B review handoff. Production auth handshake/command rollout, actual carrier/readiness integration, revision-bearing stream metadata, authoritative routing/revocation, listener reconciliation and administration/UI require subsequent implementation and independent review. Five-minute public TCP routes and deliberate session-lifetime followthrough remain unchanged. No upstream NPC/NPS source/binary, deployment, real credentials or network security-setting change is part of this checkpoint.
