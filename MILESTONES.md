# Kavern Milestones

This milestone plan is part of Gate 0 specification review. It does not approve implementation. After Gate 0 and after every implementation gate, generated files, diffs, and test output must be reviewed before proceeding to the next gate.

## Gate 0: Spec Review

Review:

- `AGENTS.md`
- `docs/SPEC.md`
- `docs/TESTING.md`
- `docs/BENCHMARK_PLAN.md`
- `docs/adr/*.md`
- `MILESTONES.md`

Exit criteria:

- Project names are consistent: `kavern`, Kavern, `kavernd`, `kavern-agent`, `kavernctl`, KAPv1, `kavernmux`.
- Specification states that no implementation is approved yet.
- Legacy `npc` support is narrow and real-binary tested.
- Review gates are explicit.

## Gate 1: Core Skeleton Review

Scope:

- Domain.
- Store.
- Legacy vkey helpers.
- `SessionManager`.
- `TunnelRouter` skeleton.
- Fake `AgentSession` tests.
- Legacy npc integration test harness.

Exit criteria:

- `User -> Project -> Device -> Tunnel` is represented.
- `vkey` belongs to `Device`.
- One `Device` has at most one active `AgentSession`, and routing uses `CurrentForDevice`.
- Carrier pool belongs inside an `AgentSession`, not multiple `AgentSession` records.
- Legacy storage helper stores `HMAC-SHA256(server_secret, wire_token)`, not raw wire token or raw MD5.
- Legacy `vkey` generation uses at least 32 bytes of cryptographic randomness, safe encoding, show-once lifecycle, and rotation invalidation.
- Normal `go test ./...` requires no internet and no `NPC_BIN`.
- Legacy integration harness is build-tagged and opt-in.

## Gate 2: AgentV1 Review

Scope:

- KAPv1 auth.
- `session_id`.
- Control/data separation.
- No MD5.
- No `InsecureSkipVerify` default.
- Fake data carrier tests.

Exit criteria:

- `internal/gateway/agent_v1` does not import or depend on legacy `npc` protocol code.
- KAPv1 uses non-MD5 authentication.
- Minimum KAPv1 auth flow covers `device_id`, `client_nonce`, `server_nonce`, `auth_challenge_id`, HMAC challenge response, and `session_id` issuance.
- `device_secret` is never transmitted in plaintext.
- `session_id` alone is not a sufficient bearer credential.
- Data carriers bind to the authenticated control session and cannot attach to unauthenticated, expired, disabled, or replaced sessions.
- Control and data paths are separated.
- Tests cover auth failure and session lifecycle.

## Gate 3: Carrier Pool / Mux Review

Scope:

- `MuxBackend` interface.
- `smux`/`yamux` backend.
- `max_streams_per_carrier`.
- No infinite queue.
- Basic backpressure.
- Tests.
- Dependency/license review for `smux`, `yamux`, or any mux backend.
- No GPL, AGPL, or other copyleft dependency without explicit review.

Exit criteria:

- Mux backend is replaceable.
- Third-party mux packages are hidden behind Kavern's `MuxBackend` interface.
- Business logic does not depend directly on `smux` or `yamux` types.
- Carrier limits are enforced.
- Backpressure behavior is tested.
- No design relies on one unlimited TCP mux connection.

## Gate 4: `kavern-agent` TCP Echo Review

Scope:

- New `kavern-agent` end-to-end TCP echo.
- No npc involved.
- Local integration test.

Exit criteria:

- TCP echo works with `kavernd` and `kavern-agent`.
- Test does not use stock `npc`.
- Normal tests remain offline.

## Gate 5: Real npc Connect Review

Scope:

- Real stock `npc` binary test.
- `NPC_BIN` test contract.
- Device online/offline.
- No fake compatibility.

Exit criteria:

- Test executes real stock `npc` from `yisier/nps`.
- Test uses `NPC_BIN`.
- Missing `NPC_BIN` with `legacy_npc_integration` tag fails clearly.
- No silent skip.
- No fake npc compatibility acceptance.
- Before this gate starts, a pinned `yisier/nps` tag/version is selected and documented.
- Stock npc fetch/build scripts do not use `master` or `latest` and do not vendor source into the Kavern repository.
- Device online/offline state is verified.

## Gate 6: Real npc TCP Echo Review

Scope:

- Stock `npc` end-to-end TCP echo.
- `target_addr` safety.
- Legacy mux boundary.
- Timeouts.
- Source-informed independent v0.26.34 protocol compatibility, with GPL/compliance review before closed-source commercial distribution.

Exit criteria:

- TCP echo passes through real stock `npc`.
- `target_addr` is server-side and constrained.
- Legacy mux details remain inside `internal/gateway/legacy_npc`.
- Timeouts and cleanup are tested.

## Gate 6S-1: Protocol Contract Review

Scope:

- Source-informed independent protocol documentation and GPL boundary.
- Pinned outer bridge handshake.
- Frame value types, parser/writer, and golden tests.

Exit criteria:

- The pinned handshake and three mux frame layouts are documented and tested.
- No production mux, stream, session data-plane, router, or forwarding work is included.
- Diff and test output are reviewed before Gate 6S-2 begins.

## Gate 6S-2: Independent LegacyMux Review

Scope:

- Independent bounded legacy mux, stream lifecycle, ping, fixed window, and close behavior.
- Unit and race tests only; no gateway/session integration.

Exit criteria:

- Mux resource limits and protocol behavior are reviewed before session integration begins.

## Gate 6S-3: Session/Gateway Integration Review

Scope:

- Legacy mux chan lifecycle, `LegacyNpcSession.OpenStream`, server-side Link metadata, and real `NPC_BIN` TCP echo.

Exit criteria:

- One refcounted device runtime independently owns the current legacy main candidate, manager-confirmed attached main, and current mux generation.
- Legacy-main replacement preserves the device mux and already returned streams; chan replacement closes only the old mux and is generation-safe.
- Chan-before-main and cross-protocol-to-legacy overlap rendezvous are event-driven, bounded by the handshake timeout, and cannot publish a superseded main as ready.
- Pending authenticated main transitions retain the device mux across queued, blocked, failed, canceled, and superseded attachment races; the last failed interest owner performs orphan cleanup.
- Manager-current verification and detach cleanup use separate fresh timeout-bounded contexts and cannot retain the transition lock or runtime leases indefinitely.
- Main runtime leases and transition interest are acquired atomically, and one lifecycle-bound reader detects queued or in-progress main disconnection before publication or stream admission.
- `LegacyNpcSession.OpenStream` validates stored enabled TCP tunnel/device state and writes deterministic Link metadata using only stored `Tunnel.TargetAddr`.
- A real pinned `NPC_BIN` TCP echo traverses public Router, legacy session, LegacyMux, stock npc, and the configured local target without `NPS_BIN`.
- A real pinned `NPC_BIN` duplicate-main replacement leaves the final current legacy session with a usable mux and successful Router echo.
- Gateway/session integration and real stock NPC TCP echo are reviewed before robustness work begins.

## Gate 6S-4A: Deterministic Robustness Review

Status: independently reviewed and accepted on 2026-10-09; local commit e69c133.

Scope:

- Go-peer/net.Pipe tests for transport fragmentation, stream concurrency, close/replacement, malformed frames, flow-control stall/recovery, race, and explicit worker completion.
- Only deterministic-regression-backed correctness fixes in legacy gateway, router, or session code. No real-binary matrix or production instrumentation.

Exit criteria:

- Pure segmentation and byte-stream reconstruction cover 0 through the listed 262144-byte Go-peer cases; the independent flow proof uses the unmodified initial allowance of 122550 bytes.
- With 64 live Go-peer streams, the 65th open is locally rejected by MaxStreams without a wire 0x06; the first 64 remain usable.
- Frame-count fairness, bounded resource ownership, device isolation, and explicit worker/lease cleanup pass normal and repeated race/shuffle validation.
- Post-return legacy stream errors are sanitized while safe sentinels remain distinguishable. Stored target selection and metadata-only RemoteAddr remain unchanged.
- Review the 4A diff, regressions, and validation output before starting 4B in a separate goal. The implementation is not self-approved by passing tests.

## Gate 6S-4B: Real Pinned Compatibility Review (Implementation / Review Pending)

Scope:

- Separately implement the pinned NPC_BIN payload, sequential/concurrent stream, close, idle, main-replacement, and two-device matrices.
- Keep canonical Router acceptance under tests/legacy_npc. Private resource checks live only in same-package legacy_npc_integration *_test.go companions; no production or tagged non-test inspection API is approved.

Exit criteria:

- Real pinned v0.26.34 evidence, not Go-peer simulations, establishes the tested TCP compatibility limits.
- Record full results, binary provenance, flow-credit evidence, cleanup, stored-target safety, and unsupported close semantics.
- No TCP half-close, arbitrary NPS compatibility, throughput, or indefinite-soak claim. No NPS_BIN or upstream implementation material.

Every Gate 6S subphase requires a separate review. No later Gate 6S subphase may begin before the immediately preceding subphase passes review.

## Gate 7: Benchmark Harness Review

Scope:

- `experiments/muxbench`.
- Local benchmarks only.
- WAN benchmark explicitly manual.
- `smux`/`yamux`/`kavernmux` comparison plan.

Exit criteria:

- Local loopback benchmarks are reproducible.
- Optional QUIC carrier is represented in the future comparison plan.
- No production performance claims are made from local-only benchmarks.
- Full WAN/server benchmark requires human deployment and is not an autonomous acceptance gate.

## Gate 8: Security Review

Scope:

- Parser limits.
- Auth.
- Token handling.
- No secret logs.
- No arbitrary target.
- Disabled tunnel/device semantics.

Exit criteria:

- Secrets and bearer materials are not logged.
- `kavern-agent` does not use MD5, `nps` protocol, or `nps_mux`.
- TLS does not default to `InsecureSkipVerify`.
- Disabled devices and tunnels are enforced.
- Legacy `npc` cannot request arbitrary targets.

## Global Rule

Do not proceed from one gate to the next until generated files, diffs, and test output for the current gate have been reviewed.
