# Verified TLS/bootstrap control checkpoint

Review draft, 2026-10-12. Base is reviewed protocol-core commit `0b6b457f036dfbeb230375dcea206a054a556b9d`. This opt-in checkpoint connects verified TLS authentication to the [schema-1 control core](native-config-sync-v1.md). It creates no production listener, changes no current command config/dispatch, and opens no synchronized data stream.

## Bootstrap and entry points

`config.NativeBootstrap` / `LoadNativeBootstrap` accept only `server`, `device_id`, `secret_env`, `ca_file`, and optional `server_name`. Strict JSON rejects local target/carrier/resource overrides and insecure options. The existing `config.Agent`/commands remain unchanged until later rollout.

`OpenBootstrapControl` resolves the referenced test/operator credential environment and explicit CA file, uses the existing verified TLS defaults, and authenticates one control connection. It returns a fresh receiver plus an owned connection; the caller runs `receiver.Run` once to drive full snapshot installation and ACK. It does not construct a TargetMap, select business targets or create carriers. This API is one session; command/reconnect orchestration follows after review.

`AuthenticateSyncControl` also supports an already constructed TLS client connection. It requires TLS >=1.2 and a verified certificate chain, checks challenge device/schema before sending proof, and validates the result before creating the receiver. An insecure/custom unverified handshake is rejected rather than used as fallback.

`AuthService.ServeSyncControl` owns one TLS server connection and a NativeSnapshotSource. ConfigOwner implements both the read-only device credential view and NativeSnapshotSource, so authentication and configuration can read the same exclusively owned state. Returned secrets remain copies; disabled, closed and uncertain owner state remains fail-closed.

## Schema and handshake

TLS plus authentication uses one five-second absolute deadline, with parent cancellation aborting the underlying connection. All frames retain the existing 4 KiB length-prefixed strict JSON boundary. Canonical lowercase keys, exact per-type field sets, duplicate/unknown/null/case-alias fields, trailing/invalid JSON and unsupported role are rejected.

Each authentication frame carries `version=kapv1`, `role=control`, `type`, and `config_sync_version=1`:

| Type | Additional required fields |
| --- | --- |
| auth_start | device_id, client_nonce |
| auth_challenge | device_id, server_nonce, auth_challenge_id |
| auth_finish | device_id, auth_challenge_id, response_hmac |
| auth_ok | device_id, session_id |
| auth_reject | code |

The server requires schema 1 before BeginSyncAuth or session attachment. Missing/unsupported schema produces only the bounded `upgrade_required` rejection. It echoes schema/device in the challenge. The client verifies those values and signs the reviewed schema-bound canonical input. The server validates finish type/device/challenge/schema and HMAC before issuing/attaching a session. Rejected attempts discard their pending challenge and cannot evict the previous current session.

After auth_ok, the authentication socket deadline is cleared and the reviewed control core becomes the sole reader/writer owner. Its fixed transfer, frame, queue, staging, write and session limits remain in effect. Server-owned desired state is fetched and transferred; exact ACK remains a protocol application fact. Synchronized OpenStream stays unconditionally fail-closed until separately reviewed carrier readiness and revision-bearing metadata integration.

On handshake/control failure or cancellation, an idempotent owned wrapper closes the underlying TLS transport immediately. It avoids blocking on close_notify when the peer stopped reading, and joins cancellation callbacks. No plaintext credential, derived bearer/HMAC value or raw session material is emitted in operator logs.

## Validation boundary

Ephemeral certificate, credential and private-state fixtures test a bootstrap-only client over a temporary loopback TLS connection through exact ACK and ConfigOwner source re-read. Other tests use TLS/net.Pipe to prove missing/unsupported schemas, wrong roles, legacy proofs and missing finish schema do not replace a current session; challenge schema/device mismatch prevents proof; untrusted roots, wrong names, expiry, insecure verification and old TLS fail; a new client rejects the old schema-0 server without fallback. Handshake framing bounds/fragmentation and idempotent cleanup are covered.

The integration patch remains uncommitted for independent review. No real credentials, upstream NPC/NPS code/binary, new performance experiment, deployment or network security-setting change is included. Actual carriers/readiness, revision-bearing stream metadata, authoritative routing/revocation, listener reconciliation, management/UI and deliberate TCP/session-lifetime changes remain later checkpoints.
