# Kavern

Kavern is a native TCP tunneling MVP with server-owned configuration. A `kavernd`
server owns `User → Project → Device → Tunnel` records; each `kavern-agent` receives
its device's authenticated configuration snapshots. `kavernctl` provides a private
local management CLI and a loopback WebUI.

The implemented local product can create native devices, synchronize server targets
without editing/restarting the agent, route TCP through bounded TLS data carriers,
edit or disable affected routing, reconnect after a daemon restart, and distinguish
saved configuration from sampled applied/ready/listener state. Native sessions and
streams use the reviewed bounded renewable lifecycle. Existing legacy compatibility
is a separate, narrowly scoped boundary; this quick start and CI make no new NPC or
performance claims.

## Build and check

The validated execution platform is Linux amd64. Local administration requires Linux
private Unix sockets and the supported state-lock/socket-publication primitives.
Other mapped Linux architectures need their own execution evidence. The CI toolchain
is pinned to Go 1.26.4; `go.mod` retains its existing language version and dependency.
The local example additionally needs Python 3, GNU Make and installed OpenSSL with
`req -addext` support. No browser, `NPC_BIN` or external service is needed for normal
checks or the noninteractive example.

From the repository root, with the checksum-pinned Go dependency already cached:

```sh
make build
make check
make smoke
make example-tests
```

Builds appear in `build/bin/`. Make targets use the installed Go toolchain and keep
build/tests offline. On a fresh machine, explicitly prime and verify the module cache
first with `go mod download` and `go mod verify`; downloading dependencies is separate
from the offline test contract. CI does that preparation once, then executes the same
build, ordinary tests, race tests, vet and synthetic example checks. The full suites
include actual native processes and take several minutes. Hosted CI execution is not
claimed until this workflow is actually run after a separately authorized push.

## Runnable local server, agent and WebUI

```sh
make demo
```

This explicitly launches a **temporary synthetic fixture**, not a deployment. It
builds the three binaries, creates a private temporary directory, a one-day local TLS
certificate and random fixture credentials, initializes ownership state, starts the
server and agent, configures a server-owned TCP tunnel, verifies target-confirmed TCP,
and demonstrates an online target edit, stale CAS rejection, disable/enable and daemon
restart/reconnect. Every network endpoint is loopback. It then prints a one-use WebUI
URL for the local operator; open it within two minutes. Press Enter or Ctrl-C to stop.
All processes/workers are joined before temporary state, trust and credential files
are removed. Nothing is installed as a service or written to an existing Kavern state.
The tiny echo targets have their own five-second idle bound; they are test fixtures,
not a native stream lifetime benchmark.

In the WebUI, choose the synthetic device, inspect desired/applied revision, then edit
its name/enabled state or its TCP tunnel. The printed first/second target addresses
both belong to the temporary demo device. Native issuance writes a once-only credential
to a new protected file in the bridge's configured private directory; the browser
receives only a delivery fact and path. The demo agent is bootstrapped outside the
browser from that private issuance file. Creating another device in the UI does not
magically launch another agent or distribute its secret.

`make smoke` exercises this fixture noninteractively, including bridge bootstrap,
cookie/token-authenticated status and logout. It does not render a browser. The
existing opt-in Chromium tests provide separate rendered/security/workflow evidence:

```sh
UI_BROWSER_BIN=/absolute/path/to/installed/chromium \
  go test -race -tags ui_browser_acceptance ./cmd/kavernctl ./cmd/kavernd \
  -run 'TestUIActualBrowser|TestActualBrowserDaemonAgentConfigurationFlow' \
  -count=1 -v -timeout=120s
```

That tag requires installed Chromium and Node and fails clearly if prerequisites are
missing. It never downloads a browser or disables its sandbox. Ordinary `go test ./...`
remains browser-free, offline and independent of NPC binaries.

## Bootstrap and configuration ownership

[The example](examples/native-local/README.md) shows the exact commands and JSON shapes.
The agent bootstrap has only `server`, `device_id`, `secret_env`, `ca_file` and optional
`server_name`. `secret_env` names the environment variable holding the device secret; the secret
is never a plaintext bootstrap JSON field or browser value. Certificate trust is verified; there is no insecure TLS default.
Targets, tunnel enablement and carrier policy belong in server state and arrive through
native synchronization. The server bootstrap contains transport/certificate/state
paths, the external master-key environment reference and optional private admin socket;
per-device business policy is not a bootstrap override.

Initial empty state is an offline operation before the daemon starts. Later edits use
the running owner's online actor or WebUI. Each configuration update submits the complete
device configuration, original revision and management window/operation ID. Identity,
ownership, disabled/unshown tunnels and policy survive scoped edits. The agent automatically
resynchronizes; no manual target map or agent configuration rewrite is required.

## Readiness, recovery and current limits

**Saved** confirms durable desired state. **Applied revision** is the current agent's
acknowledgement. **Ready** is a sampled server fact combining current revision, carriers
and listeners; it never certifies target reachability. Bind failure can coexist with a
saved/applied revision. Offline and stale/unavailable observations do not imply a
specific authentication error. Only actual successful traffic confirms a target.

A failed/lost response leaves the outcome unconfirmed. Retain the exact original request,
window and ID; look up its exact-content receipt. Stale CAS keeps the draft and requires
explicit current-state review/reload. Missing or evicted receipts remain unknown; matching
configuration is not proof. A rejected later retry does not resolve the original unknown
outcome. WebUI issuance retries are read-only receipt resolution and never execute a
fresh creation/rotation or recover a lost secret. Explicit state recovery handles commit
uncertainty; it does not recover credentials. Lost credentials require an explicitly
new rotation with a new protected destination. Auth expiry retains nonsecret recovery
requests for export/import into a fresh local session.

The UI is local, same-UID, single-operator administration; domain User records are
business ownership, not browser login accounts. It edits the first 50 displayed tunnel
rows while preserving the complete set. Ownership moves, deletion/policy controls,
legacy issuance, hosted/remote administration, HA and enterprise login/RBAC are outside
this UI slice. Native credential rotation/template widgets exist; a new browser-rotation
end-to-end claim and full keyboard-only creation/accessibility audit are not made.

This is a local MVP with scoped review/test evidence, not production deployment or
security readiness, WAN performance, indefinite-soak or arbitrary-version NPC acceptance.
Closed-source commercial distribution requires the separate license/compliance review
specified by the project instructions.

- [Current local WebUI contracts](docs/LOCAL_WEBUI.md)
- [Private management API and CLI](docs/ONLINE_ADMIN.md)
- [Reviewed native lifecycle](docs/adr/0009-bounded-lifecycle.md)
- [Server-owned configuration architecture](docs/adr/0007-server-owned-native-configuration.md)
- [Testing and explicitly scoped historical compatibility evidence](docs/TESTING.md)
- [Historical operator/security baseline](docs/OPERATIONS.md)
