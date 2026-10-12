# Authenticated carriers, scoped readiness and stream metadata

Review draft, 2026-10-12. Base is reviewed TLS/bootstrap commit `1cdf58d5a17bfb00a534829534c70171cb3e8136`. This opt-in checkpoint adds data-plane admission to synchronized sessions; current command configuration/dispatch and public Router remain unchanged. Production rollout, active-route revocation, listener reconciliation and administration/UI remain later reviewed work.

## Carrier authority

`ServeSyncTransport` dispatches schema-1 control and data roles on one verified TLS endpoint. `ServeSyncControl` retains its control-only behavior. Data binding carries device/session/revision/transfer plus carrier nonce and the reviewed schema-bound HMAC. TLS protects the tuple; nonce/HMAC proves binding to the authenticated device/control session, and nonce replay remains rejected. Schema-0 native and legacy NPC paths are unchanged.

A data carrier must match the current enabled, unexpired authenticated session and its desired/applied tuple. Binding can wait at most two seconds for that exact configuration ACK, then revalidates current authority. Old/future/wrong-scope bindings fail; they cannot attach to a different snapshot/session. No caller-supplied carrier limits are accepted. Both endpoints use the installed/server snapshot policy for max_streams, max_inflight, max_buffer, backend receive/frame bounds and required carrier count. The pool is capped at that policy's count and the existing four-carrier ceiling. Policy changes require a fresh control session.

The carrier_ok response echoes exact scope and policy. An agent verifies both against its installed snapshot before creating the backend/carrier, then rechecks receiver state before registering. Failed proof, stale scope, invalid backend budget, capacity rejection, cancellation or disconnect closes owned transport/backend resources. Mux remains behind the existing interface and retains bounded payload accounting and directional EOF records.

## Exact readiness

Control `ready` and `ready_ok` require the complete device/session/revision/transfer tuple and carrier_count in addition to the existing version/schema/type fields. Count is between one and four and must equal the snapshot policy. Requests are bounded to one pending client request with a two-second budget; the same reviewed control reader/coordinator writes these frames.

The server requires its exact accepted configuration ACK, then waits for actual live attached carriers, re-reads desired state, rechecks current session/tuple/count and publishes scoped readiness. A notification or client assertion is insufficient. The agent accepts ready_ok only for its pending exact request, installed tuple and actual registered live carrier count. A new config_begin, lost carrier, closure or stale message closes new-stream admission. Installed/applied/readiness facts remain volatile.

Readiness here is session/carrier readiness, not public listener or target health. Carrier loss blocks new streams; this checkpoint does not implement active-route revocation. Existing streams on another intact carrier can follow their already captured target until their ordinary lifecycle ends.

## Revision-bearing streams and target isolation

Schema-1 stream metadata retains the four-byte length prefix and 4 KiB strict JSON cap. It contains exactly `version`, `config_sync_version`, `type=open_stream`, `device_id`, `session_id`, canonical nonzero decimal-string `revision`, `transfer_id`, `tunnel_id`, and `protocol=tcp`. No target address or caller-selected endpoint is accepted. Unknown/duplicate/aliased/noncanonical/truncated/oversized metadata fails before target dialing.

The internal StreamOpenRequest now has a domain revision. A synchronized session requires that revision, exact ready tuple, current enabled/authenticated session, unchanged desired snapshot, enabled projected tunnel and actual policy carrier count. It repeats those checks after mux stream acquisition, which may wait, before emitting metadata. Failure releases the lease and emits no stale metadata. Schema-0 native/legacy requests retain their prior behavior.

The receiving handler resolves only from the ready installed snapshot for the exact device/session/revision/transfer. It rejects stale/cross-device/session/transfer/unknown-tunnel metadata before dialing, captures the configured target once, and never reads an address from application bytes or metadata. Bounds, metadata/dial timeouts, handler slots, proxy cleanup and directional EOF retain their existing behavior.

ConfigReceiver owns at most the policy carrier count. Its control shutdown closes carriers outside the receiver state lock and joins control/data worker cleanup. The opt-in SyncClientCarrier data loop uses the shared bounded AgentDataLoop with a schema-1 handler; the old handler and local TargetMap path are unchanged for existing command sessions.

## Acceptance evidence and next boundary

Own TLS/control/mux/carrier fixtures prove actual TCP echo through an acknowledged server-owned snapshot, two live policy carriers, exact ready exchange and scoped stream metadata. Request TargetAddr is ignored. Negative metadata fixtures verify zero target dials for stale revision/transfer, wrong device/session, unknown tunnel and unsupported protocol. Controlled mux-opening races prove revision change or session replacement after a pool wait emits no metadata and releases resources. Policy cap, nonce replay, stale binding, invalid backend receive budget, missing ACK/carriers, wrong count and stale desired state fail closed and close rejected resources.

No current Router derives/passes revision yet: synchronized production routing remains unavailable until separately reviewed rollout. No active/pending-route revocation registry, dynamic public listeners, management transport/UI, lifetime-policy change, real credential provisioning, upstream code/binary experiment, deployment or performance comparison is included. Five-minute public routes and the one-hour native session limit remain explicit later followthrough.
