# Local administration UI

Launch explicitly against an existing private management socket:

```sh
kavernctl ui --socket /absolute/private/admin.sock
# Native creation/rotation additionally needs an existing owned 0700 directory:
kavernctl ui --socket /absolute/private/admin.sock --credential-dir /absolute/private/credentials
```

Open the printed local URL within two minutes. The one-use fragment is removed after
bootstrap. Authentication requires an HttpOnly SameSite cookie and a separate tab token;
idle expiry is ten minutes, absolute expiry one hour. Polling does not extend idle time.
The endpoint binds IPv4 loopback only. Ending the UI session or process does not stop
the daemon, agent or established tunnels. Do not expose this bridge remotely.

Create user/project records, then a native device in its owning project. Creation saves
the once-only credential to a new 0600 file in the configured private directory; the
browser receives no secret. Delivery `protected_file` confirms that write/fsync/path
verification succeeded. `unconfirmed` means delivery failed or its result was lost.
Receipts/retries never recover a credential: explicitly rotate if it was lost. Rotation
retires the old session/credential and requires a new agent bootstrap secret. Legacy
issuance stays in the existing online CLI. Offline native eligibility comes from stored
credential kinds, never inferred connection status.

The secret-free bootstrap template contains only server address, device ID, secret
environment variable name, trusted CA path and optional TLS server name. Populate trust
and the secret separately using the existing protected provisioning workflow; generating
a template does not create files, change trust or launch an agent.

Edit the device name/enabled state or add/edit/enable TCP tunnels. A public listener is
on the server; a target is on that device. Changes save the complete configuration with
its original revision, preserving all disabled/unshown tunnels, ownership and carrier
policy. Disabling or editing affected routing closes affected traffic. Save confirms
durable desired state; applied revision, carriers, readiness and listener errors are
separate fresh server observations. Ready does not certify target reachability.

A revision conflict keeps the draft. Review current configuration and explicitly reload
the editor before making a new save; there is no automatic merge, overwrite or retry.
Each save retains its exact operation ID/window/content before dispatch. At most four
requests and 2 MiB total are retained per tab; resolve/discard terminal requests to make
space. If recovery storage is unavailable, saving is blocked before dispatch.

For a lost response, use **Look up original receipt**. The read-only lookup checks the
complete request digest. An altered imported request is rejected; missing/expired
receipts leave the previous outcome unknown. Matching configuration cannot prove that
an operation succeeded. **Retry exact original request** is explicit, retains the
original window/ID/content and may submit the still-unexecuted operation; credential-issuing requests are read-only receipt resolution and cannot execute a never-sent original or
reissue credentials. No retry is automatic. A new save for the same action/record is blocked while its original outcome is unresolved; resolve it or explicitly discard its recovery request first. The interface labels unknown outcomes
separately from a definite rejection of the attempted write. A rejected later retry
does not resolve the original unknown outcome.

During commit uncertainty, readiness clears and ordinary forms are disabled. Use
**Recover daemon state** explicitly, then resolve the original request. Recovery checks
durable state; it does not recover a secret. Browser auth expiry retains the nonsecret
request and draft. Export an original request from the old tab and import it for lookup
in a freshly launched bridge if the process/origin changed. Treat this request as private
operator data. Imports do not automatically submit operations.

Deletion controls, ownership editing/moves, carrier-policy editing, legacy issuance,
remote/hosted administration and enterprise login/RBAC are outside this UI slice.

Normal offline tests require neither a browser nor `NPC_BIN`. Synthetic actual-browser
acceptance uses the explicit `ui_browser_acceptance` tag, installed `UI_BROWSER_BIN`
and Node; it fails clearly when those prerequisites are missing. All credential, trust,
process and listener fixtures are temporary and local. No external NPC binary evidence
is claimed by these tests.
