# ADR 0008: Local online management and minimal WebUI adapter

Status: proposed design for review, 2026-10-12. Baseline:
`b139c498d3174550673ac3f19d7e13ca29bd0867`. M1 mutation-core work is authorized for a separate review checkpoint. Administrator
socket, CLI/WebUI adapters, lifecycle code, operational credentials, security-setting
changes and deployment remain outside M1.

## Requirements and boundary

User requirements: devices belong to users through `User -> Project -> Device ->
Tunnel`; one user can own many devices, credentials belong to devices, and tunnel
business configuration belongs to the server. The native agent keeps transport,
identity and trust bootstrap only. Management must support a small WebUI, durable
configuration, honest readiness/errors and safe hot updates. Preserve independent
legacy NPC boundaries, frame/carrier limits, one current session per device and
existing compatibility/performance evidence. No organizations, enterprise RBAC,
SSO, billing, hosted control plane or remote administrator exposure is proposed.

The interface, authentication/bootstrap, deletion and lifecycle choices below are
proposals, not recovered historical user decisions. Existing C1-C3 core APIs are
implementation evidence; they are not yet a complete online management surface.

## Smallest interface and authority

Propose bounded HTTP/1.1 JSON over one Unix-domain socket, implemented using the
standard library. HTTP here is administration only, never the tunneling data plane.
The daemon's existing ConfigOwner remains the only mutation actor, state-file lock
owner, authentication authority and desired-state publisher. Neither CLI nor WebUI
writes the file, starts a second owner, or shells out to offline commands.

Enable the socket only through an explicit `admin_socket` server bootstrap field;
no TCP admin listener and no implicit enablement. Require a private 0700 runtime
directory owned by the daemon effective UID, a 0600 socket and verified Unix peer
UID matching that UID. Reject symlinked/unowned directories and existing unrelated
files. Safely handle a stale same-owner socket only after proving no server owns it;
never unlink an active or unrelated endpoint. Verify path/owner/peer on CLI connect.
Unsupported platforms fail explicitly until a reviewed equivalent is available.
The local OS owner is the administrator; domain User records are ownership data,
not shell identities or hidden authentication bypasses.

Place mutation/authorization orchestration inside existing `internal/store` and
management adapters in existing command/config packages; keep gateway types out of
business operations. No new package layout without an ADR amendment. Start with
CLI and local API, then add the minimal WebUI against exactly these operations.

Proposed endpoints (version `/admin/v1`, fixed routes, strict JSON):

| Operation | Contract |
| --- | --- |
| GET `/users`, `/projects?user_id=…`, `/devices?project_id=…` | Bounded/paginated secret-free inventory; always return stored ownership. |
| POST `/users`, `/projects`, `/devices` | Create minimal records; project owner must exist. Device creation supplies project and credential kind, not a caller-selected credential. |
| GET `/devices/{id}/configuration` | Complete desired Device/Tunnel/policy set and canonical decimal-string revision. |
| PUT `/devices/{id}/configuration` | Replace that device's complete desired configuration with expected revision and operation ID; ownership/project/device IDs are immutable. Enable/disable, tunnel create/update/delete and policy updates use this one CAS operation. |
| POST `/devices/{id}/rotate-credential` | Kind plus expected revision/operation ID; server generates credential, durably replaces it and revokes old authentication/session/work. |
| DELETE `/devices/{id}` | Expected revision/operation ID and explicit cascade acknowledgement if tunnels exist; one durable transaction deletes tunnels, credentials and device and retires all runtime interest. |
| GET `/status`, `/devices/{id}/status` | Process health and secret-free desired/applied/current/listener/carrier/error facts. |
| GET `/operations/{id}` | Bounded redacted receipt/result for uncertain response resolution. |
| POST `/recover` | Explicit validated directory-durability recovery after commit uncertainty; never infer success from a notification. |

All creation is insert-only. An existing user/project/device ID returns conflict,
including identical content under a new operation. Only an exact retained creation
receipt verifies an identical retry. In particular, project creation must never
reparent an existing project. User/project updates, reparenting and deletion are deferred; do not invent reassignment or recursive tenant
cleanup. No tunnel move between devices, multi-active sessions or credential import
is proposed. DTOs whitelist fields and validate ownership in the service; never
accept a caller's enabled/owner/target claims as runtime admission facts.

CLI examples: `kavernctl online --socket PATH status`, `get-device ID`,
`put-device ID --if-revision R --file FILE`, `create-device --project P`,
`rotate-device ID --if-revision R`, `delete-device ID --if-revision R --cascade`.
CLI reads current revision for display; a mutation always submits an explicit CAS
revision. Do not automatically overwrite a concurrent update after conflict.
Keep existing offline commands explicitly separate and locked out while the daemon
runs. One semantic mutation service must validate online and future offline edits;
do not make live mutations bypass validation used by synchronization.

## Durability, concurrency and response loss

Bound request/response bodies to the existing 1 MiB JSON ceiling, including encoded
bytes; retain 1,024 enabled public listeners, 1,024 native tunnels/device and complete
projection validation. Reject duplicate/unknown keys, invalid UTF-8/depth/trailing
JSON and noncanonical/zero/overflow revisions. Use canonical deterministic order,
validate the complete candidate/global listener index and enforce immutable owning
project/device before persistence. A nonempty effective change advances the device
revision once, including credential rotation; no-op preserves revision.

Propose 32 concurrent admin connections, the existing eight-entry mutation queue,
five-second header/body/write bounds and bounded status pagination (128 records).
Reject saturation; do not create unbounded waiters, body buffers or broadcast
queues. Accepted mutations preserve the owner's definitive durability semantics:
client disconnect/timeouts are not proof of rollback after rename. No raw body,
credential, HMAC/token material or session ID is logged.

M1 adds schema v3 with an opaque random state-lineage ID, a monotonic management
epoch, a FIFO ledger of at most 256 receipts and at most 2,048 deletion tombstones.
Each mutation supplies the observed lineage/epoch plus operation ID. The epoch
advances once on every accepted mutation, including no-ops that keep the desired
device revision unchanged. Existing actor commits that change configuration and
stopped-owner offline rewrites also advance it. Retained exact operation retries
return a redacted receipt before stale-window rejection. Reusing a retained operation
ID with different content fails; a missing receipt with a stale request window returns
`operation_expired_or_unknown` and never reapplies the old request. Obtaining a fresh
window authorizes a new operation, not automatic replay of an unresolved old request.
The operation-ID deduplication promise is bounded by the retained ledger in its
state lineage; it is not unlimited historical deduplication.

A receipt contains the original request window, operation ID, nonsecret request
digest, kind, affected record ID, resulting device revision where applicable and
result epoch. Migration from v1/v2 happens atomically with the first successful M1
mutation; its original empty bootstrap window is recorded so an exact response-loss
retry survives migration and restart. Configuration, credential replacement,
tombstones and receipt share one atomic rename/fsync persistence transaction.
No newly issued raw credential is included in the digest or receipt. Requests have
strict ownership, expected-device-revision and global-window checks; no caller may
infer a successful save, rollback or readiness from an event notification.

Later accepted mutations can evict a receipt, including no-ops without desired
revision changes. Missing receipts return explicit expired/unknown outcomes; inspect
current desired state and deliberately choose a fresh operation. While the owner is
commit-uncertain, operation lookup and window retrieval also return uncertainty.
Neither an absent in-memory receipt nor the old view proves rollback before recovery.

| Result | API/CLI meaning |
| --- | --- |
| Validation/conflict/capacity before persistence | 422/409/429; no change, include safe error code/current revision where known. |
| Saved, runtime not applied/bound/ready | 200/201 desired revision with runtime facts; no claim that saving made a usable tunnel. |
| Saved, revoked work cleanup pending | Desired revision plus explicit `cleanup_pending`; never label it rollback. |
| Rename succeeded but durability not confirmed | 503 `commit_uncertain`; block further mutation/auth/admission as today, revoke runtime work, allow redacted health and recovery; operation lookup/window retrieval remain uncertain. |
| Response lost after definite commit | Retained exact retry obtains redacted receipt; evicted requests return expired/unknown. Never issue another rotation/delete implicitly. |

Recovery validates the actual file and directory fsync, reconstructs the authoritative
view/receipt, and publishes it with readiness cleared as appropriate. If outcome
cannot be established, continue to report uncertainty. Persist no runtime applied,
bound or ready facts. A saved bind failure stays saved, visible and retryable; the
old changed listener must not continue serving.

Credential creation/rotation returns raw native secret or legacy vkey exactly once
in its successful issuance response, encrypted/persisted only through existing
credential storage rules. List/get/status/retry receipts never recover it. If the
response is lost or commit uncertain, report that delivery is unconfirmed; after
recovery rotate again explicitly to obtain a new once-only value. Show credentials
only on explicit issuance output, never diagnostics/history. Provide explicit
protected output-file selection; no default writing to shell profiles or agent
configuration. Native secrets never use MD5; legacy vkey replacement invalidates its
old HMAC lookup key without persisting the wire token.

## Revocation and ownership

Extend ConfigOwner's actor transaction to credential creation/rotation and device
delete; do not mutate its published MemoryStore directly. Publication under the
admission guard must collect affected pending/active work and invalidate listener
bindings; cancel/close/join outside guards. Target/listener/tunnel disable/delete
revokes affected work; device disable/delete and credential rotation retire all its
sessions/carriers/work immediately, not after ACK. Late dial/open results close.
Unchanged devices/tunnels survive subject to documented carrier retirement.

Native final proof/session publication already shares this guard. Before exposing
live legacy credential/device mutation, compose legacy final auth/runtime attachment
with the same enabled/current-credential publication boundary and add deterministic
races using only our Go peers. Legacy main/chan device ownership must retain reviewed
independent main-generation/current-mux semantics; do not introduce a second active
AgentSession or close unaffected devices. Historical real-NPC evidence remains
historical; any fresh binary acceptance needs a separate authorized black-box gate.

Hard delete is an explicit one-device cascade, not a global cleanup. Proposed ID
policy: do not reuse deleted device/tunnel IDs within the state lineage; keep bounded
redacted tombstones/receipts and return conflict when replay would otherwise recreate
an old identity. Do not prune tombstones in M1. A mutation requiring additional tombstones rejects
at capacity (or the encoded state-byte limit); unaffected operations may continue.
The existing complete-device actor also retains removed tunnel IDs after migration. No deletion of TLS/bootstrap/master-key files is implied.

## Status for a minimal WebUI

Each device reports owning user/project, desired revision/enabled state, current
presence/protocol, applied revision, acknowledged ready tuple as a boolean/revision,
actual live carrier count/required policy, and safe latest error code. Do not expose
session IDs, nonces, HMACs, raw credential material or sealed secret ciphertext.
Each tunnel reports desired address/target/enabled, actual bound address, listener
state/generation, retry state and admission/readiness explanation. A tunnel is ready
only when enabled, bound to its current generation, and current native session has
exact desired/applied/ready revision and required live carriers. Legacy readiness
uses its actual reviewed runtime conditions, not an invented native ACK.

Target reachability is unknown until an attempt/probe result; ACK is not proof of
reachability. After restart, applied/ready is empty; after failed bind, `listener_failed`
is distinct from saved desired state. Status must capture consistent tuples/version
checks or return an explicit changing/unknown state, not combine separately sampled
facts into false readiness. Poll at most once/second in the small UI; no event bus or
persistent observability framework is needed. Show saved/applying/ready/failed and
safe last-error/cleanup uncertainty clearly, with conflict refresh instead of
silently overwriting a newer form revision.

## Browser bootstrap proposal, after local API review

Do not expose the daemon's privileged UDS endpoint directly to a browser. Propose
an explicit `kavernctl ui --socket PATH` local bridge on an ephemeral 127.0.0.1 port,
with static assets and the same API DTOs forwarded through the authenticated UDS.
Require exact Host/Origin checks, no CORS, CSRF validation for every mutation,
HttpOnly SameSite=Strict session cookie and idle expiry. Fail closed for other
origins/hosts to prevent rebinding/cross-site local requests. The bridge acts as the
local administrator; the minimal UI is single-operator, not multi-user login/RBAC.

Bootstrap one short-lived one-use cryptographically random code held only in bridge
memory, delivered in the explicit launch URL fragment, exchanged once for the
session cookie and removed from browser history. Never place it in query/access
logs, state or API status. This proposal uses loopback HTTP only for the opt-in local
bridge; no insecure native TLS changes and no default remote exposure. Its concrete
browser cookie/CSRF behavior needs security review/test before UI implementation.
Remote access, persistent admin passwords, TLS termination changes, reverse-proxy
publishing and network ACL/firewall changes are separate explicit authorization.

## Deliberate lifecycle proposal

The existing five-minute absolute public-route and one-hour native-session limits
remain during M1/M2 only. A separate lifecycle gate is **required before sustained-use
acceptance**. Report both clearly as actual limits, including
that active traffic currently does not extend them. Do not silently promise an
indefinite tunnel when native expiry still closes its carriers.

That separately reviewed lifecycle gate removes both the absolute route context
timeout and the absolute socket deadline. Use no default maximum route age or
application-idle eviction for ordinary TCP, while retaining bounded open/dial/header/
control-liveness/write/backpressure operations, resource caps and immediate shutdown/
revocation. Add optional server-owned maximum-age/idle policy only if required by
operators. Replace disruptive one-hour expiry with nonce/HMAC renewal on the same
verified control session. Replace the fixed authenticated-session expiration and
its fixed control-context deadline together. Renewal must be bounded, nonce/HMAC
protected and replay resistant, and recheck current credential, enabled state,
revocation and current-session identity. Renewal failure expires that session and
closes its work; extending a timestamp alone is insufficient.
Do not add parallel active sessions, pools of sessions or application replay.
Acceptance must use injected clocks to prove active traffic crosses former age/
expiry boundaries, silent/blocked work stays bounded, and revoke/shutdown still joins.
This is a required subsequent gate with its own review, not an M1 runtime change.

## Concrete implementation/review sequence and acceptance

1. Review this design; then implement the domain actor operations/receipts, validation,
   revocation and uncertainty recovery with deterministic durability/auth/open/dial/
   legacy attachment races. Test receipt loss/retry, one-time secret delivery, CAS,
   deletion cascade, ID reuse and quota saturation. Stop for core review.
2. Implement explicit private UDS HTTP adapter and online CLI, same business service,
   peer/path authorization, parser/resource limits and safe output. Test symlinks,
   stale/active socket ownership, unauthorized peer where supported, disconnect
   before/after rename, malformed/body/deadline/capacity failure and cleanup. Stop
   for transport/CLI security review.
3. Actual own-built daemon+agent+CLI subprocess tests on temporary loopback/socket
   fixtures: hot target and listener changes, occupied-port recovery, port-zero
   addresses, device/tunnel create/enable/disable/delete, native credential rotation
   old-proof/old-session rejection and explicit agent bootstrap restart, policy
   reconnect/full sync, EOF byte exactness, confirmed old-target receipt/no replay,
   optimistic conflict, commit-uncertain recovery, daemon restart with durable
   desired state/readiness reset, joined shutdown and exclusive lock/socket release.
   No test-only production backdoors; all changes use the real reviewed management
   interface. Add Go-peer legacy revocation/attachment coverage; no NPC binary here.
4. Only after API/CLI review, implement the minimal local WebUI forms/status and
   bridge bootstrap/CSRF/origin acceptance. No enterprise scope or deployment.

Normal code, unit/process test design and ephemeral fixture credentials/sockets are
within an approved implementation scope once reviewed. Creating/rotating a real
persistent device/admin credential, enabling an admin socket/bridge on the user's
running installation, changing its TLS/trust/permissions/network settings, deleting
real records or deploying/publishing are separate concrete actions needing explicit
user authorization. This design step performs none of them. Offline tests remain
NPC_BIN-free and network-independent apart from own loopback fixtures; no upstream
source, external NPC binary, real provisioning or push is part of this proposal.


## M1 review acceptance contract

M1 exposes only in-process ConfigOwner operations, not an administrator endpoint.
It includes insert-only user/project/device creation, a device's complete CAS update,
rotation of an existing credential kind and explicit device cascade deletion.
It keeps the existing eight-entry actor queue and validates the complete resulting
state, listener index and native projection within current limits. User/project
updates, reparenting, credential-kind conversion and broader tenant operations wait.

A successful or retained replay result explicitly confirms saved desired state.
Fresh results distinguish complete/pending revocation cleanup; retained results
report cleanup unknown. Applied ACK, bound listener, current carrier readiness and
current runtime cleanup status remain separate observations, not persisted promises.
Generated credentials are delivery-only and excluded from generic result JSON;
M2 must use an explicit once-only issuance DTO and protected output path. Receipt
replay, lookup, failed or uncertain persistence never return raw credentials.

Acceptance requires deterministic tests for insert conflicts/ownership, complete
CAS and no-op, retained retries across migration/restart, no-op receipt eviction,
explicit expired/unknown results, tombstone saturation/ID reuse, malformed metadata
and bounded input. Inject each file-write/rename/directory fault to prove receipt
and state atomicity, fail-closed uncertainty and explicit recovery. Exercise native
rotation on both sides of final proof publication, legacy credential changes before
role admission and final main/chan attachment, pending main serialization, active
main/chan rotation and device deletion. Cleanup joins and late-attachment rejection
must pass race/stress checks using only our Go peers. Normal offline tests remain
NPC_BIN-free; historical binary evidence is regression context, not a fresh claim.

Stop after a frozen patch, exact file manifest and test output for independent M1
review. A commit requires GO; M2 administration transport/CLI and the mandatory
lifecycle gate require separate handoffs and reviews.
