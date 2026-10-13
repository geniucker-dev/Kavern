# Local online administration (M2 review candidate)

> The M2 scope/lifetime introduction below is historical: the reviewed local WebUI and renewable native lifecycle now exist. See [the root quick start](../README.md), [current WebUI contracts](LOCAL_WEBUI.md) and [ADR 0009](adr/0009-bounded-lifecycle.md). Current W2 adds stored credential-kind metadata and bounded exact-content receipt lookup; original CLI contracts below remain in place.

The running daemon owns business state. Online commands call its bounded mutation
actor; they do not write the state file or invoke offline commands. The native agent
keeps server address, identity credentials and verified trust bootstrap only.

This gate provides a local Unix-domain API and CLI. It does not provide a WebUI,
remote administrator listener, user/project updates, reparenting, credential import,
or new tunnel/session lifetime policy. The separate renewal/lifecycle gate remains
mandatory before sustained-use acceptance.

## Bootstrap and ownership

Set `admin_socket` explicitly in server bootstrap to an absolute path of at most
100 bytes. The runtime directory must already exist, belong to the daemon effective
UID and have mode 0700. The socket is published with mode 0600. Its endpoint must not
be an unrelated existing file/socket or have a symlinked directory component.
No endpoint is enabled when the field is absent. Native control TLS is unchanged.

The current implementation requires Linux and `renameat2(RENAME_NOREPLACE)` on
amd64, arm64, riscv64 or loong64. Runtime acceptance here exercises Linux amd64;
other mapped architectures need their own platform execution evidence. Other
platforms and unsupported server architectures fail explicitly.

The daemon pins directory/socket descriptors and holds a private per-endpoint
ownership sidecar lock for the server lifetime. New sidecars are initialized and
locked before atomic publication; existing ones require the recognized ownership
marker, so unrelated private regular files are preserved. A bounded inode/ctime marker records
its published socket. Active endpoints and unrelated stale sockets are never adopted.
Automatic stale cleanup requires a matching marker, exclusive ownership lock and a
refused connection probe. Removal atomically captures the name, checks the pinned
inode, and restores a racing replacement without overwriting another name. Unknown
captured replacements are preserved and reported. Closing a listener does not blindly
unlink its pathname. The ownership sidecar remains after normal shutdown to prevent
lock-file replacement races among cooperating daemons.

Verified client dialing and stale probing use the short `/proc/self/fd/N` address
of the pinned socket inode, so the published path's long basename cannot overflow
Linux's Unix-address limit. The published absolute-path limit remains 100 bytes.

Client and server verify Linux `SO_PEERCRED` UID. The client also verifies private
path ownership/mode and pins the inode before/after connection. The local same-UID
OS owner is the administrator; domain User records are business ownership data.
No network-admin password or browser credential is introduced.
Legacy issuance/rotation requires the daemon's optional `server_secret_env` bootstrap
key to be configured; no management request can supply that lookup HMAC key.

## Commands and request contract

Examples below describe operator actions; they are not operational provisioning
performed by this gate. Use an explicitly selected private runtime/output directory.

```sh
kavernctl online --socket /private/runtime/admin.sock status
kavernctl online --socket /private/runtime/admin.sock window
kavernctl online --socket /private/runtime/admin.sock users
kavernctl online --socket /private/runtime/admin.sock projects --parent user-id
kavernctl online --socket /private/runtime/admin.sock devices --parent project-id
kavernctl online --socket /private/runtime/admin.sock get-device --id device-id
kavernctl online --socket /private/runtime/admin.sock device-status --id device-id
kavernctl online --socket /private/runtime/admin.sock put-device --file request.json
kavernctl online --socket /private/runtime/admin.sock rotate-device --file rotation.json \
  --credential-output /private/output/new-credential.json
kavernctl online --socket /private/runtime/admin.sock retry --file original-request.json
kavernctl online --socket /private/runtime/admin.sock operation --id original-op \
  --lineage original-lineage --epoch original-epoch
kavernctl online --socket /private/runtime/admin.sock recover
```

Mutation commands are `create-user`, `create-project`, `create-device`, `put-device`,
`rotate-device` and `delete-device`. They take a strict JSON request file. Keep the
original request unchanged until its result is resolved. Files must be regular,
nonsymlinked and at most 1 MiB; FIFOs/devices are rejected without a blocking read.
Use `window` to obtain the current lineage/epoch for a deliberately new operation.
Epoch is a canonical decimal string including the empty-lineage bootstrap epoch `0`.
Expected device revision is the canonical positive decimal string returned by
`get-device`. Nested domain records retain existing configuration field names.

A complete device update has this shape (fill actual returned window/configuration):

```json
{
  "window": {"lineage": "RETURNED_LINEAGE", "epoch": "RETURNED_EPOCH"},
  "operation_id": "unique-operation-id",
  "kind": "put_device",
  "device_id": "device-id",
  "expected_revision": "1",
  "configuration": {
    "Device": {"ID": "device-id", "ProjectID": "project-id", "Name": "", "Enabled": true},
    "Revision": "1",
    "Policy": {"Carriers": 2, "MaxStreams": 64, "MaxInflight": 1048576, "MaxBuffer": 8388608},
    "Tunnels": []
  }
}
```

Kind values are `create_user`, `create_project`, `create_device`, `put_device`,
`rotate_credential` and `delete_device`. Creation supplies `user`, `project` or
`device`; device issuance also specifies `credential_kind` as
`kapv1_device_secret` or `legacy_npc`. Rotation supplies device ID, expected revision
and an existing credential kind. Delete supplies device ID and expected revision;
set `cascade: true` explicitly when tunnels exist. Creating an existing ID conflicts;
only an exact retained creation retry recovers its previous redacted result.

Fresh device issuance/rotation requires `--credential-output`: a new file in an
existing private same-UID 0700 directory. It is reserved before sending a mutation,
never overwrites an existing name, is mode 0600 and is synced. After writing, the
client verifies that the selected private pathname still identifies its pinned
file; replacement or directory movement reports delivery unconfirmed. Its original marker
is `delivery: unconfirmed`; a definite issuance replaces it with the once-only
credential. Failures/lost responses may leave that marker. A retained replay writes
`delivery: not_reissued`, never recovers a credential. No credential is printed on
stdout or included in status/history/receipt diagnostics. Protect this explicit file
as device bootstrap material; no shell/agent configuration is automatically changed.

`retry` first looks up the exact **original request** lineage/epoch/operation ID,
then resubmits the unchanged request to verify its digest. It neither creates a new
window nor issues credentials. A receipt evicted between lookup/resubmission causes
explicit expired/unknown; it cannot replay at the newer epoch. Lookup does not accept
the returned result epoch or arbitrary current epoch as the original request epoch.
After uncertain credential delivery, resolve/recover desired state, then deliberately
rotate with a new operation/window and a new protected destination.

## API and resources

HTTP/1.1 runs exclusively over the private socket. Host must be `kavern-admin`; Origin
and Upgrade requests are rejected. Responses are JSON with `Cache-Control: no-store`
and `nosniff`. No access/request-body log is emitted. Requests use exact
`Content-Type: application/json`; duplicate/unknown keys, malformed UTF-8, excessive
depth, trailing JSON, malformed/duplicate query parameters and oversized bodies fail.

| Method/path | Meaning |
| --- | --- |
| GET `/admin/v1/status` | Redacted owner health and global cleanup pending; remains available during uncertainty. |
| GET `/admin/v1/window` | Current lineage/epoch; unavailable during commit uncertainty. |
| GET `/admin/v1/users`, `/projects`, `/devices` | At most 128 records, lexical `after` cursor; user_id/project_id filters as applicable. |
| GET `/admin/v1/devices/{id}/configuration` | Complete desired state and expected device revision. |
| GET `/admin/v1/devices/{id}/status` | Owning user/project, desired revision, sampled current/applied/carrier/readiness facts and listener states. |
| POST `/admin/v1/users`, `/projects`, `/devices` | Insert-only creation through the actor. |
| PUT `/admin/v1/devices/{id}/configuration` | Complete device CAS update. |
| POST `/admin/v1/devices/{id}/rotate-credential` | Existing-kind rotation and immediate revocation. |
| DELETE `/admin/v1/devices/{id}` | Explicit cascade deletion. |
| GET `/admin/v1/operations/{id}?lineage=…&epoch=…` | Exact original-window redacted receipt lookup. |
| POST `/admin/v1/recover` with `{}` | Existing validated state/directory-durability recovery. |

Admin connection/worker count is bounded to 32, mutation queue remains eight, request
and encoded response bodies remain at most 1 MiB, configured header limit is 8192
bytes, and header/body/write/idle operations have five-second bounds. Capacity is
rejected rather than queued without limit. Native frame/carrier/public-listener caps
are unchanged. Shutdown closes slow/idle sockets immediately and joins actual HTTP
workers and accepted actor results before unlinking only its owned endpoint and
releasing the state lock. A client disconnect is never proof of rollback.

## Saved, applied, ready and uncertainty

A mutation response confirms `saved` desired state and reports fresh revocation
`cleanup` as complete/pending. A receipt reports cleanup unknown. This does not claim
that a native agent has ACKed, a public listener bound, or carriers are ready.
Device status combines sampled applied/carrier facts with current desired revision
and listener generations; it is an observation, never an admission proof. No session
IDs, nonces, challenges, HMACs or encrypted credential records are exposed.
Legacy session presence is shown without inventing native ACK/carrier readiness.

A failed bind remains saved and reports `bind_failed` with retry timing; the old
changed listener cannot keep serving. Recovery from a freed address needs no desired
rewrite. Disabled/deleted devices and credential rotation retire owned runtime work
before claiming cleanup completion. Stale CAS never auto-refreshes or overwrites.

Commit uncertainty returns 503 `commit_uncertain` for mutation, window, configuration,
inventory, device status and receipt lookup. Redacted health/recovery remain available.
Missing receipts do not establish rollback. Lookup/retry only recover retained
bounded receipts; expired/unknown requires inspecting current desired state and a
new deliberate operation. Applied/readiness/cleanup runtime state is not persisted.

The current five-minute absolute route and one-hour session/control-context limits
still apply. M2 does not make sustained lifetime claims or change those limits.
