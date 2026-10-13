# Temporary native local example

Run from the repository root:

```sh
make smoke          # Noninteractive: assert native TCP and bridge auth/status/logout.
make demo           # Explicitly hold a temporary fixture for local WebUI exploration.
make example-tests  # Templates, actual smoke, startup-fault cleanup and interactive exit.
```

Requirements: supported Linux, installed Go, cached checksum-verified dependency,
GNU Make, Python 3 and installed OpenSSL supporting `req -addext`. The runner downloads
nothing. It uses its own new `/tmp/kavern-demo-*` directory and loopback ports; it never
reads an existing Kavern configuration, credential or state. Every generated value is
synthetic and temporary. The one-day self-signed fixture certificate is explicitly
trusted by the temporary agent and contains the actual loopback IP SAN. There is no
`InsecureSkipVerify` or system trust-store change.

The two `.template.json` files are secret-free templates. The runner substitutes its
private root and the actual `server_ready.control` address; the resulting files are
validated by the built CLI. Do not pass unsubstituted templates directly to commands.
The helper's actual command sequence is:

```sh
# All paths refer to the helper's private temporary directory, not a real installation.
kavernctl validate -kind server -config <temporary-server.json>
kavernctl init-state -state <temporary-state.json> \
  -master-key-env KAVERN_DEMO_MASTER -user demo-owner -project demo-project
kavernd -config <temporary-server.json>
kavernctl online --socket <temporary-admin.sock> window
kavernctl online --socket <temporary-admin.sock> create-device \
  --file <temporary-original-request.json> --credential-output <private-new-device.json>
kavernctl online --socket <temporary-admin.sock> get-device --id demo-device
kavernctl online --socket <temporary-admin.sock> put-device --file <temporary-full-CAS.json>
kavernctl validate -kind agent -config <temporary-agent.json>
kavern-agent -config <temporary-agent.json>
kavernctl online --socket <temporary-admin.sock> device-status --id demo-device
kavernctl ui --socket <temporary-admin.sock> --credential-dir <temporary-private-directory>
```

These angle-bracket paths describe generated inputs; copy/paste the runnable Make
commands above instead. `KAVERN_DEMO_MASTER` is random fixture master-key material in
child environments. `KAVERN_DEMO_DEVICE` comes from the protected 0600 once-only issuance
file and is set only for the temporary agent. Neither secret is printed, embedded in
bootstrap JSON, sent to the browser, or retained after exit. The interactive output
contains a deliberate one-use browser launch URL for the local operator; keep that
launch material private. Noninteractive output contains only assertion results.

A native creation request has this shape; its window comes from the owner at save time:

```json
{
  "window": {"lineage": "RETURNED_LINEAGE", "epoch": "RETURNED_EPOCH"},
  "operation_id": "new-original-operation-id",
  "kind": "create_device",
  "device": {"ID": "demo-device", "ProjectID": "demo-project", "Name": "Demo", "Enabled": true},
  "credential_kind": "kapv1_device_secret"
}
```

A complete tunnel update comes from `get-device`. Preserve `Device` identity/project,
its positive decimal-string `Revision`, complete `Tunnels` array and `Policy`. Set the
request's `expected_revision` to that original revision. A tunnel carries `ID`,
`DeviceID`, `Protocol: tcp`, server `Listener`, device `TargetAddr` and `Enabled`. The
runner adds a loopback listener and an actual echo-target address on the synthetic
agent's host. These targets never enter the agent bootstrap file.

The runner verifies the target's byte receipt and EOF, an online target change without
agent restart, stale CAS rejection, disable/enable, durable daemon restart/reconnect,
and the WebUI bridge's cookie-plus-token authorization and sampled ready revision.
Its assertion is for a temporary single-device functional flow; it is not a performance,
real-NPC, long-lived stream or rendered browser acceptance claim. Existing separate
Chromium acceptance covers two devices and real rendering; see the root README.

To explore the UI, open the printed launch URL within two minutes. User/project records
express business ownership. **Saved**, **applied revision**, **ready** and bind failure are
separate facts. Creating another device saves a credential outside the browser but does
not start its agent; bootstrap and secret distribution remain explicit operator work.
The helper prints its temporary first/second target addresses for scoped tunnel edits.
Its echo targets cap 16 simultaneous handlers and close idle peers after five seconds.

Press Enter or Ctrl-C to stop. Processes and readers join, echo sockets/workers close,
and then the entire temporary directory is deleted. No `--keep`, external state path,
remote listener or persistent provisioning option is provided. If the process is killed
with SIGKILL or the machine crashes, graceful cleanup cannot run; any leftover fixture
must be handled as private synthetic material by its owner, not automatically adopted
as production state.
