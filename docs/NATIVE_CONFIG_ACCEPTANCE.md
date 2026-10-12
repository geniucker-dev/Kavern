# Server-owned native configuration: acceptance contract

Proposed on 2026-10-12 for [ADR 0007](adr/0007-server-owned-native-configuration.md), against `cc19acf4e8730a79db8885918eca070d6823f4a9`. This contract is not evidence that the feature already exists. Each slice stops for independent diff/test review before the next slice. Numeric bounds and the local administration adapter are proposed decisions requiring design acceptance.

## Observable success

An operator creates/changes an enabled TCP tunnel in server-owned durable state. A native agent with only server/device/credential-reference/trust bootstrap authenticates, receives the current Device's full snapshot, installs it, ACKs it, attaches bounded carriers and obtains scoped readiness. Public traffic reaches the stored target. No daemon restart or local target-map edit is needed for later tunnel changes. Reconnect/restart repeats synchronization; old-session messages cannot restore readiness. A saved mutation can report pending/failed application without losing the desired record.

The User/Project/Device relationships persist; one User with two Devices can have different targets and credentials. No device credential grants administrative authority. The eventual Web UI is supported by server-owned use cases, but frontend design and remote administration auth are outside these slices.

## Slice A: durable desired configuration (first handoff)

Implement domain snapshots/revisions and a staged commit boundary only. Keep existing agent protocol/commands operational until the later rollout slice.

| Case | Required assertion |
| --- | --- |
| v1 state read and v2 migration | Preserve every relationship, target, enabled bit, legacy lookup and encrypted native secret; initial per-device revision 1 and persisted native policy from documented defaults/explicit prior server limits; no applied readiness persists. Unknown/corrupt schemas fail. Existing private permissions and exclusive lock remain. |
| Mutation/CAS | A valid Device-scoped create/update/delete/enable transaction advances revision once; no-op leaves it unchanged; stale expected revision fails without writes. Concurrent same-device and different-device writes cannot lose updates to the single state file. Other devices' committed state/revisions remain intact. At most eight mutations queue; overload is busy, and shutdown joins the owner without claiming an uncommitted mutation succeeded. |
| Listener index | Changing or deleting a listener removes the old index; duplicates fail; authoritative GetTunnel/FindTunnel agree after commit and reload. Ownership cannot be reassigned by this API. |
| Candidate validation | Invalid IDs, unsupported protocol, unknown Device, native TCP target port zero or >512 bytes, duplicate tunnel/listener, >1,024 native device entries, >1,024 public listeners, oversized encoded native snapshot/state, and revision overflow fail before persistence/publication. Exact valid boundary passes. Disabled desired records remain valid but cannot route; legacy-only targets retain existing bounds. |
| Faults/crash boundary | Inject temp-create/write/sync/close/rename failure: before rename, old file/live state/revision remain. Inject directory-open and directory-sync failures after successful rename: report uncertain commit, do not publish ready/success or issue further writes; recover actual file and clear volatile readiness. Crash after rename/before runtime publication reloads the complete new candidate. Cancellation/shutdown before rename preserves the old state; cancellation during/after successful rename cannot label the new durable commit uncommitted. Test barriers on both sides of rename and directory fsync. |
| Snapshot projection | Stable sort, only the requested Device's enabled TCP targets plus policy; no secrets/other devices/public listener addresses; empty snapshot valid; stored targets determine output. Reject missing/over-limit stored targets; no local fallback. |

First review artifact: diff for domain/config/store plus exact unit/race results, with no protocol change, new dependency or real state rewrite. Existing MemoryStore test fixtures need not become real deployment data.

## Slice B: authentication-bound snapshot/ACK

| Case | Required assertion |
| --- | --- |
| Startup/reconnect | Fresh current session cannot OpenStream before exact configuration ACK and actual carriers. Same persisted revision on reconnect still transfers the complete snapshot; old staged/applied map is discarded. Empty configuration synchronizes successfully. |
| Full replacement | New-stream admission closes at config_begin; applying a second snapshot atomically replaces all entries and collects revocations; omitted/disabled targets disappear; no partial staged target is dialable. Cleanup occurs outside admission locks; matching ready_ok reopens admission. Validation failure does not partially mutate the active resolver. |
| Device/session scope | Cross-device/session messages, replaced/expired/disabled sessions, unsolicited ACKs, wrong transfer ID, older/future revision and wrong ready tuple cannot change current readiness or attach carriers. Identical duplicate last ACK is idempotent. Replacement racing ACK cannot publish the old session ready. |
| Revision race | Commit R+1 while R is in flight; R's ACK cannot admit new traffic, R+1 is eventually sent as a full snapshot, and rapid updates retain only the latest pending revision. No update queue grows with mutation count. |
| Wire bounds | Keep control/metadata frames <=4,096 bytes, 1,024 entries, 1,026 transfer frames and <=1 MiB snapshot payload. Test exact/one-over boundaries, contiguous indices/counts, duplicate IDs/JSON keys, unknown fields, invalid UTF-8/depth/trailing documents, oversized length prefix and truncated/fragmented frames. Zero/noncanonical/overflow revisions fail. |
| Aggregate capacity | One staging map/session plus one applied map; 16 MiB aggregate staged payload. Saturate reservation; the excess session fails promptly, existing sessions stay correct, and disconnect/reject/timeout releases the reservation. Sender queues stay bounded while a reader is slow. |
| Control ownership/liveness | One control reader and writer, at most eight queued control messages plus one generated snapshot entry. Inject concurrent snapshot/ping/replacement events: frame writes do not interleave, heartbeats have bounded service, and the 10-second transfer deadline never extends on partial progress. Slow writer/full queue has five-second bound. ACK loss/malformed transfer retires session and reconnect resends latest; all loops/reservations join/release. |
| Authentication separation | Sync schema selection is verified in challenge and HMAC canonical bytes, including carrier binding. Tampering/downgrade fails. Session ID alone never suffices. TLS verification, no MD5/native legacy wire, replay/capacity limits and nonce rules remain. |

Use Go peers/net.Pipe, deterministic barriers and injectable time/failure dependencies. Avoid sleep-only ordering tests. ACK asserts resolver installation, not target reachability; an unreachable target can be applied while its attempted route fails safely.

## Slice C: authoritative routing, revocation and listeners

| Case | Required assertion |
| --- | --- |
| Target authority/isolation | A bootstrap-only actual Kavern agent echoes through a server target. Caller-injected TargetAddr, stale Tunnel.Enabled/DeviceID, application payload addresses, another Device's tunnel ID and old stream revision cannot choose a target; rejected requests make zero target dials. |
| Open races | Pool-wait admission rechecks revision/current session. Revoke/change while a stream open or target dial is blocked: it cannot escape registration/cancellation or reach an obsolete target afterward. Metadata arriving after a snapshot swap is rejected. |
| Active routes | Target/listener change, disable/delete cancels affected active/pending routes and releases handler/stream slots; Device disable immediately closes its session/routes without ACK. Disable racing auth/session publication cannot attach a disabled Device. Unchanged established targets and another Device stay operational subject to existing carrier-retirement effects. Never reconnect/replay application bytes. |
| Dynamic listeners | Create/update/delete while daemon runs; handler resolves fresh state and rejects obsolete listener generations. Check actual bind addresses, including port zero, shutdown worker joins and shared 256 handler/1,024 listener caps. No stale index remains. |
| Bind/Accept failure | Occupy requested port: mutation is saved, desired revision survives restart, affected tunnel is listener_failed/unready and old changed address does not serve. Unrelated listeners remain usable. Release port: bounded reconciler eventually binds it. Public Accept failure is isolated to that listener. Supersession/shutdown cancels retries and joins loops. |
| Status/readiness | Show desired revision, current presence, applied revision, carrier availability and per-listener state separately. Missing ACK, stale session, missing carriers, failed bind or disabled record never reports a ready tunnel. Restart discards all runtime readiness. Agent-ready requires scoped ready_ok after exact ACK/carriers and does not claim every listener/target is healthy. No raw session token/nonce/HMAC is logged or exposed by operator status. |
| Cleanup | After every error/update/reconnect/shutdown, no retained public accept loop, control reader, writer, retry timer, staged byte reservation, route copy, target connection, handler slot or lease. Observe actual completion/state, not a notification as proof. |

Routing accepts only authoritative domain facts and AgentSession interfaces. No business package imports gateway wire types or smux types. Preserve 16 KiB directional EOF records, payload budgets, four maximum carriers and backend boundary.

## Slice D: operator adapter and safe rollout

- Propose local private Unix-socket mutation/status calls from kavernctl, using the same in-process server mutation service; do not shell out to offline CLI or concurrently edit the state file. Socket path/ownership/permission validation, strict bounded request decoding and shutdown cleanup must be tested. Keep offline administration fail-closed while the daemon holds its lock. Do not add remote HTTP authentication as an incidental CRUD wrapper.
- Cover matched new server/agent with bootstrap-only config; old agent/new server is rejected before session attachment, so it cannot evict a synchronized session. New agent/old server fails without local-target fallback. Rejected deprecated targets/carriers/limits identify migration steps without printing credential values.
- Keep old MVP operation available until the coordinated native transition slice is reviewed. New synchronized mode may not silently serve an old agent. Real deployment/migration of user state and credentials requires a separate authorized operation.
- Actual Kavern process tests use temporary loopback endpoints and test-owned fixtures only; verify server restart, agent reconnect, live target change and exact EOF-dependent response bytes. No upstream binary execution is added by this gate.

## Deliberate lifecycle contract

This configuration gate retains the current five-minute absolute public-route limit and one-hour native session expiry. Regression tests with short injected durations prove route opening and silent opposite-direction copy are bounded, leases/handler slots return, and daemon context remains alive. Existing native half-close/hard-error behavior must pass.

Before a later lifecycle implementation, accept a separate decision for maximum route age versus progress idle time, bounded open/dial/write deadlines, and session renewal versus expiry/draining. Tests must prove active traffic crosses an injected former five-minute boundary if the cap is removed; idle/blocked routes still obey selected policy; shutdown/revocation/replacement still close; native one-hour expiry is addressed explicitly. A liveness heartbeat alone is not application progress. Do not claim indefinite routes while session expiry still truncates them.

## Validation and regression limits

For each implemented slice, run its focused unit/race tests and the existing offline suite with GOPROXY/GOSUMDB disabled and local toolchain selection. Ordinary `go test ./...` remains NPC_BIN/NPS_BIN-free and offline. Preserve unrelated untracked experiment files; do not overwrite/run them merely to claim validation. For this checkout, the tracked-package equivalent is:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test ./internal/... ./cmd/... ./tests/legacy_npc ./experiments/muxbench -count=1 -timeout=3m
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race ./internal/store ./internal/config ./internal/router ./internal/session ./internal/gateway/agent_v1 ./cmd/kavernd -count=1 -timeout=3m
```

Current native performance is a frozen comparison baseline, not a new benchmark assignment. Preserve legacy NPC gateway/mux/state/target behavior and its existing offline tests. Existing real-NPC evidence remains limited to its recorded runs; do not claim current binary regression coverage from Go peers. If shared router/store/listener changes need a fresh real pinned-NPC run for final acceptance, request a separate authorized handoff to the existing black-box harness; it is blocked by this gate's no-external-binary-test constraint. Never read/copy/build/decompile upstream source.

## Design-pass evidence and remaining gates

Repository baseline, draft validation and sandbox/test outcomes will be recorded in the handoff. The design itself implements no behavior. Slice A was authorized after independent design review on 2026-10-12. Its uncommitted implementation must pass independent diff/test review before any subsequent slice begins. No deployment, real credential provisioning, security-setting change, commit, push or force push is authorized by this design pass.

## Slice C1: admission and revocation checkpoint

This checkpoint covers authoritative admission and cancellation, before dynamic
listeners or production command rollout. It does not complete all of Slice C.

- `RouteView` reads stored Tunnel, owning Device and revision in one generation.
  RouteTCP ignores caller ownership, enabled, protocol and target fields. The
  owner rechecks that revision and registers work before asynchronous opening.
  Native direct opens use the authenticated service's owner, including when a
  snapshot-source decorator does not expose admission methods. Router-owned
  opens share their registration; independently returned streams own theirs.
- Desired publication uses the same guard as admission and final native proof /
  session publication. It swaps the view and collects affected work under that
  guard; cancellation, connection closure and worker joins happen afterward.
  A target/listener/protocol change, omission or disable revokes affected routes.
  Device disable revokes its session and all device work before Commit completes,
  without waiting for ACK. Carrier-policy change deliberately retires the native
  session and all device work; this checkpoint does not resize live pools.
- Work is bounded to 4,608 server registrations (shared by native session owners
  and routes/opens) and 4,096 receiver registrations. Saturation fails admission;
  it never creates an unlimited waiter queue. Closing/replacing a session also
  cancels independently admitted pending opens and returned streams. Unchanged
  established tunnels survive unrelated edits while their carrier remains live.
- The receiver captures its target and registers pending dial/active proxy work
  under its snapshot guard. Completed replacement collects affected work in that
  same critical section. It cancels/joins outside the lock before ACK, using the
  remaining original transfer deadline. A late successful dial after cancellation
  is closed before proxying; stale metadata cannot register against a new map.
- Owner change signals are coalesced wakeups. Control re-reads the authoritative
  latest snapshot, including after ACK, rather than retaining mutation events.
  Restart/reconnect still starts with a full snapshot and empty readiness.
- Durable publication and cleanup are separate outcomes. Commit returns committed
  revisions plus `session.ErrWorkCleanupPending` if revoked work does not join
  within five seconds. The saved generation remains current and on disk; this
  error is not a rollback. Persistence uncertainty still blocks admission and
  revokes existing work; recovery cannot resurrect canceled connections. An
  uncooperative injected dial/close/backend may remain pending after the cleanup
  bound; no claim of forcible termination of arbitrary Go code is made.

Acceptance adds deterministic barriers for authentication/disable ordering,
registered pool waits, late returned mux streams and target connections, snapshot
publication before metadata admission, automatic source wakeups, unchanged active
traffic, capacity reuse and durable cleanup timeout. Tests assert completion,
closed late resources, no obsolete metadata, and released registrations. Existing
normal tests remain offline and NPC_BIN-free. This checkpoint neither runs a real
NPC binary nor extends existing black-box compatibility/performance evidence.

Public listener generation checks/reconciliation, runtime status/operator adapter,
coordinated native command rollout, and route/session lifetime policy remain later
reviewed checkpoints. Five-minute public routes and one-hour native sessions are
unchanged here.
