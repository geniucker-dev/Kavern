# ADR 0009: Bounded renewable native lifetime

Status: proposed for independent design review, 2026-10-12. Implementation is paused.
Baseline: `e442fac00ed33ddfe13370c0e1552f8c08f2e83c` (accepted M2).

## Requirements and current evidence

User requirements: ordinary first-party TCP flows must survive the existing
five-minute age cap and native sessions the fixed one-hour cap. Preserve bounded
open/dial, control liveness, parsing, stream/inflight/buffer/handler limits, device
and tunnel isolation, immediate revocation and joined cleanup. Renewal must be
bounded, replay resistant and recheck current credentials/session/revocation.
No automatic application-byte replay, multi-active session, security-setting change,
WebUI, deployment or fresh external NPC acceptance is authorized. Proposed constants,
wire extension and sequencing below are decisions for review, not prior user choices.

Current code applies both an absolute route context and inbound socket deadline in
`internal/router/listeners.go:173`/`:182`, with another helper in
`cmd/kavernd/main.go:102`/`:111`. Native session expiry is assigned one hour in
`internal/gateway/agent_v1/auth.go:184`; session/open/carrier/data checks read it,
and `sync_control.go:132` also creates a fixed control-context timeout. Extending
only that timestamp cannot repair the independently expiring control context.
Current synchronized control has an eight-entry reader queue, 10-second heartbeat,
30-second idle read, five-second frame/write operations, 10-second snapshot transfer
and two-second readiness wait. Those bounded operations remain meaningful.

## Native route lifecycle

For negotiated renewable native sessions, remove **both** absolute application-route
context and socket age deadlines, including the command helper. Route lifetime is
owned by listener/service cancellation, authoritative admission/revocation, current
session lifetime, peer EOF or hard I/O error. No default application-read-idle limit:
a quiet database connection may remain open while its authenticated control lease
and resource reservation remain valid. EOF/half-close retains existing byte-exact
behavior; no reopening/replay of a terminated application flow.

Use independent five-second budgets for server carrier reservation/open/metadata
write, and agent metadata read/target dial. Current stream opening returns after
metadata write; there is no target-connected acknowledgment. This gate must not
claim an end-to-end five-second target-establishment guarantee. Each timeout closes
late results and joins its own operation; allocate ownership from the parent
route/session context and apply the child budget only to that phase, so successful
streams do not inherit an expiring open context. A target-connected acknowledgment
would require a separate explicit protocol decision.

Retain carrier backpressure/resource caps. Add a native-only 30-second **blocked
write** bound for writes to local TCP and mux streams: a pending write must complete
or fail within that budget; a new successful write starts a new budget. Control ping,
renewal or unrelated traffic cannot reset it. This does not evict idle reads or impose
an age cap. Deadline support must be an explicit mux-interface/wrapper contract,
implemented behind MuxBackend; do not silently ignore unsupported deadlines or spawn
unbounded goroutines to emulate them. A stalled write or failed/stalled CloseWrite is fatal and must cancel both
directions and join the route; never preserve a half-open peer after a bounded
native write failure. Legacy/nonrenewable proxy behavior stays unchanged.

Preserve legacy public-route five-minute age, legacy handshake/mux liveness, independent
main/mux ownership and all legacy wire behavior. Experimental non-sync native APIs
also retain old limits. Remove protocol-agnostic listener age wrappers, then obtain
an accepted session's gateway-neutral maximum-route-age capability (zero only for
negotiated renewable native sessions; conservative five-minute fallback). Retain the
original acceptance instant for age-limited sessions. Routing must not inspect mux
or wire internals, and session replacement must not change an already admitted
flow's lifetime policy. Deterministic legacy peers verify unchanged age semantics;
this is not a fresh stock-NPC compatibility claim.

## Negotiation and compatibility

Propose `lifecycle_version=1`, required by upgraded native command transports, alongside
KAPv1 `protocol_version=1` and unchanged `config_sync_version=1`. Snapshot format
stays schema 1. Auth start/challenge/finish/success and data-carrier negotiation bind
the selected lifecycle version; add it to canonical auth and carrier HMAC domains.
Every negotiated control frame includes it and uses exact per-type keys. New fields count toward
existing encoded frame/transfer/staging limits; do not raise limits. Upgrade preflight
must reject a previously stored projection that cannot fit the negotiated envelopes,
without trimming or silently modifying durable state. It is not
an optional post-auth hint, and session ID alone remains insufficient for carriers.

New server commands reject old/missing/unknown lifecycle versions before challenge
attachment with bounded `upgrade_required`. New agents reject missing/mismatched
selection and never downgrade after rejection or a generic disconnect. Old servers
may reject the new auth field without a recognized code; new agents still fail
explicitly and do not fall back. Mixed old/new native binaries require coordinated
upgrade. Old experimental library paths remain explicitly nonrenewable, outside
upgraded command dispatch. Legacy NPC remains separate and unchanged. No bootstrap
secret/trust weakening, client business policy or TLS-insecure mode is added.

## Lease and wire proposal

Initial authenticated grant: generation `1`, maximum remaining lease **90 seconds**.
Server initiates the next generation's challenge **30 seconds after the last grant**;
proof/confirmation budget is **15 seconds** from challenge issuance. Server may resend its identical challenge twice, after two and five seconds; client
may resend its identical proof at those delays from first proof send. Limit total
proof sends to three per generation, including duplicate-challenge-triggered sends,
within the original budget.
Constants are fixed, reviewed defaults here, not runtime test flags. Every generation
uses a fresh 32-byte random challenge nonce and a canonical positive decimal-string
uint64 counter; overflow closes the session rather than wrapping.

Add bounded `renew_challenge`, `renew_response`, `renew_ok` frames (at most 1024 encoded
bytes each). Common scope: device ID, authenticated session ID, protocol/sync/lifecycle
versions and control role. Challenge includes next generation, nonce, fixed lease
budget and proof budget. Response HMAC uses a distinct `kapv1/control/renew-proof`
domain and binds that entire scope/generation/nonce/budgets. Success includes the
same scope/generation/nonce and bounded remaining milliseconds, HMAC signed under a
distinct `kapv1/control/renew-grant` domain. No device secret is transmitted. No nonce,
HMAC, session ID or bearer-derived material is logged or persisted.

Server stores one pending challenge and one latest successful replay receipt per
session, plus bounded counters/timers. First valid proof atomically changes expiry
to `server_now + 90s`; it never adds time to the old expiry or accepts unsolicited
early extension. The receipt records that fixed expiry. Identical proof retransmits
revalidate current authority and return that same grant with freshly bounded remaining
milliseconds; they **never extend** expiry again. Replacing the receipt after the next
successful generation makes older generations stale, not historical recoverable
credentials. Bound response/proof/replay traffic to four proof frames per challenge
window, plus at most two stale frames per 30-second renewal window; overflow closes the peer without growing
storage or response queues. No catch-up loop sends accumulated challenges.

Client computes a conservative local deadline using its monotonic **first proof-send
instant** plus signed remaining duration (initial grant anchors to auth-finish send).
This subtracts round-trip delay conservatively without wall-clock synchronization.
Duplicates of an already accepted grant are ignored and cannot reset the local timer.
A delayed grant past the existing local deadline cannot resurrect the client. Server
is final authority and rejects all activity at `now >= expiry`, independent of client
belief. Remaining duration must be positive and no more than 90 seconds.

## Loss, ordering, scheduling and liveness

TCP delivers ordered bytes or breaks; the sequence rules cover application retries,
delayed dispatch and malformed/replayed frames, not an invented lossy data plane.
A lost/unconfirmed challenge or grant can be retried only through the same bounded
challenge/proof/receipt state. EOF, truncated frame, parse failure or write timeout
closes the control session; do not reuse a broken TLS connection. Missing proof by
its deadline, missing confirmed grant at the client, or lease expiry fails closed.
A latest-receipt duplicate is idempotent. For generations older than the retained
receipt, validate exact syntax and scope,
then drop under the two-stale-frame quota; do not retain forgotten nonce/HMAC history.
Nonce/HMAC matching applies to pending and retained generations. Future/unissued
generations or pending/retained nonce/scope/HMAC mismatches fail.
Client duplicate challenges resend the same proof; it does not allocate another
pending operation. Stale grants never replace newer accepted state.

Renewal is serviced by the existing single control dispatcher between bounded
snapshot entries; it remains available before application ACK/readiness and during
transfer. Include challenge/proof/lease deadlines in earliest-deadline scheduling,
with bounded renewal priority and fair snapshot/heartbeat progress. Keep reader
queue eight, coalesced configuration wakeup one and existing staging budget. Ordinary
ping/pong, successful data writes, ACK or ready never extend the lease. A missing
control peer still fails the existing 30-second idle bound even before lease expiry.

Replace the fixed one-hour control context with service/session cancellation plus a
single owned, dynamically reset lease timer. Session/open/carrier/readiness/status
checks use one synchronized lease authority; remove direct unlocked expiry reads.
Stale timer callbacks carry their observed generation and cannot expire a newer
successful grant. At equality with expiry no proof is accepted. Expiry/revocation
becomes terminal once; it closes control, carriers, streams and pending work and
joins them through existing bounded ownership cleanup.

## Revocation and concurrent state

Renewal publication is memory-only under the existing ordering: authentication
registration guard, ConfigOwner admission guard, current-manager check, then lease
state guard. Recheck enabled/existing device, current credential proof, current
session ID and the live unrevoked owner interest before extension. Credential-change
publication marks that interest revoked before asynchronous close, so renewal cannot
slip into the cleanup interval. No filesystem/socket close or worker join occurs
under those guards. Expiry timer marks terminal under its lease guard, releases it,
then cancels/closes/joins; it must not acquire outer guards while holding the lease
lock. All shared expiry reads/reset/terminal transitions are race checked.

Rotation, deletion, disable, replacement, policy retirement and commit uncertainty
retire authority regardless of a just-issued grant; recovery cannot resurrect it.
A renewal linearized before revocation may succeed, then is immediately retired.
One after publication fails. Target/listener/tunnel changes preserve existing scoped
revocation and full snapshot ACK/readiness rules; renewal is not configuration ACK
and carries no desired revision that could block it on unrelated transfer. Unchanged
flows survive permitted updates. Policy changes continue to retire the session and
reconnect; do not resize/migrate carrier pools here.

Fresh reconnect performs verified TLS/authentication, gets a new session ID, grant,
nonces and counters, then full snapshot/ACK/carrier/ready synchronization. It never
resumes an expired lease, reattaches old carriers or replays old application bytes.
The existing bounded reconnect backoff stays. A redacted `renewal_count` status fact
may support process acceptance; it conveys no session identifier or readiness proof.

## Acceptance and coding slices after design GO

Inject an internal monotonic clock/timer dependency into lease/scheduler and route
phase/age tests through constructors; production uses the real clock. No environment,
CLI, bootstrap, HTTP knob, build-tagged production fault hook or process clock-fast-
forward backdoor. Keep real socket deadlines on real time; fake lease timers cancel
and close net.Pipe/Go-peer I/O deterministically. Tests must advance timers, not just
replace `Now` while real expiration contexts still run.

1. Codec/HMAC/negotiation and lease state machine: exact bounded parsing, downgrade,
   cross-device/session/role/version/nonce replay, duplicate proof without extension,
   reordered/stale/future messages, lost challenge/grant, counter exhaustion and
   equality expiry. Prove bounded one-challenge/one-receipt storage and quotas.
2. Guard/timer/control integration: clock-controlled renewal versus expiry, blocked
   predecessor close, rotation/delete/disable/replacement/policy/uncertainty/recovery,
   snapshot/heartbeat contention and stalled control writer. Exercise both publication
   orders and prove complete joins/zero leaked reservations, including stale timers.
3. Native route/open/write integration: one continuously active flow across virtual
   five minutes and one hour with repeated renewal on the same session; quiet reads
   survive with healthy control, open/dial late results close, blocked writes terminate,
   half-close is byte exact and termination never replays. Verify retained legacy and
   non-sync age limits with only our peers. Clock boundary advance must also cover
   the removed fixed control timeout, not only timestamp checks.
4. Actual daemon/CLI/agent smoke with default constants, approximately 100 seconds:
   one target-confirmed TCP connection survives the initial 90-second lease through
   multiple renewals, with renewal counter/readiness and byte receipts; then prove
   rotation, policy update, disable/delete or lost control closes it and fresh auth
   resync works. No hour-long process sleep. Injected-clock integration, not this
   shorter smoke, proves crossing the historical one-hour/five-minute limits.

First coding slice is only item 1 plus the clock/timer ownership contract, reviewed
before control/router adoption. Each later slice freezes its files/diff/test output
and stops for review. Full offline and race suites stay NPC_BIN-free; keep current
native performance evidence as baseline and run only local relevant regression
measurement if deadline/wrapper changes affect the data path. Minimal WebUI follows
accepted lifecycle implementation and sustained-use acceptance, not this design.


## L1 authorized implementation boundary

After independent architecture review, L1 is authorized only for standalone exact
negotiation/renewal/snapshot-envelope codecs, domain-separated canonical authenticated
transcripts (including frozen initial grants), client/server lease state machines,
a current credential/session/owner-interest authority adapter, internal clock/timer
ownership and deterministic tests. Commands, control dispatch, route deadlines,
proxy behavior and status adoption remain unchanged pending L1 review. All later
integration acceptance above remains mandatory, including quiet/continuous same-flow
crossing virtual historical limits and an approximately 100-second real-process smoke
on one target-confirmed connection, unchanged desired revision, multiple renewals,
revocation and fresh full synchronization. No production test clock/fault controls.
