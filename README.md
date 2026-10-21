# omada-change-management (omadawrite)

Change control with automatic rollback for a **TP-Link Omada** controller running as a
**Proxmox** VM.

An AI (or any script) **proposes** a change as a list of raw HTTP requests. A person
**approves** it in a web page. The box **snapshots the controller VM**, sends the requests,
then **watches the internet**. If the internet goes down after the change and stays down, it
**rolls the controller VM back by itself**.

There is no AI inside the box. It stores proposals, shows them to a person, and replays
the approved requests.

> [!NOTE]
> This was built for one homelab: one controller VM on Proxmox (ZFS storage) and the box in an
> LXC container **on the same node and bridge**. Every address and timing is a setting, but expect
> to read the code before running it somewhere else. Not affiliated with or endorsed by TP-Link.

```
AI ──POST /api/proposals──▶ omadawrite (LXC on the controller VM's node)
                               │  a person signs in with an Omada admin login (kept only in an encrypted cookie)
                               │  reviews every request → Approve
                               ├─▶ Proxmox API: snapshot the controller VM  (ow-<id>-<utc>)
                               ├─▶ internet must answer every second for 5 s, or nothing is sent (→ failed)
                               ├─▶ Omada API: run the requests in order, stop on the first error
                               └─▶ watchdog: ping 8.8.8.8 / 1.0.0.1 every 5 s (see Watchdog)
```

## Watchdog

```
apply ─┬─ settle 1 min ─┬──────── watch 5 min ────────┬─▶ completed once also up 4 min in a row
       │ (not judged)   │                              │
       │                └─ down ─ retry 5 min ─┬─ back → disarmed, 4-min streak starts over
       │                                       └─ still down → roll the VM back → reverted
```

| Setting | Default | Meaning |
|---|---|---|
| `PREFLIGHT_STABLE_SECONDS` | 5 | Right before the first write (after the snapshot), every 1-s check must pass |
| `SETTLE_SECONDS` | 60 | After the commands, outages are ignored while devices re-provision |
| `WATCH_MINUTES` | 5 | Earliest close is settle + this |
| `STABLE_MINUTES` | 4 | Also needed to close: internet up continuously this long |
| `REVERT_AFTER_DOWN_MINUTES` | 5 | Down continuously this long after the settle → auto-revert |
| `TICK_SECONDS` | 5 | Check interval; one tick without a reply counts as down |
| `PROBE_TARGETS` | `8.8.8.8,1.0.0.1` | Up if either answers. Bare IP = ICMP, `IP:port` = TCP |

With no outage a change closes 6 min after apply. A connection that keeps dropping never
builds a 4-min streak and never stays down 5 min, so it stays `watching` until a person
chooses Keep or Revert now.

- **One proposal at a time.** Enforced by a unique index in SQLite. A new submit gets `409`
  until the open one is closed.
- **Approving is refused** if the watchdog isn't running, the internet is down at that
  moment, the Proxmox API can't be reached, or the Omada login fails.
- **Only the watchdog rolls back.** The web process only sets `status=reverting`, so a restart
  of either process never starts two rollbacks.
- **Machines talk by IP, people use DNS.** The box reaches Omada and Proxmox by IP and still
  verifies TLS against the hostname, sent as SNI (`OMADA_TLS_NAME` / `PVE_TLS_NAME`). Put the
  box on the same node and bridge as the controller VM, so a rollback needs no gateway and no DNS.
- **The reviewer can:** Approve · Reject · Keep change · Revert now · Hold auto-revert (for
  outages the change didn't cause, e.g. the ISP) · Retry / Close after a failed revert.

## Statuses

`pending` → `snapshotting` → `applying` → `watching` → `completed` | `reverting` → `reverted`

Other end states: `rejected`, `withdrawn`, `failed` (snapshot or pre-flight failed, nothing
applied), `rejected_by_omada` (Omada refused a write and only reads had succeeded, so nothing
changed; it closes at once and a corrected proposal can be submitted), `revert_failed` (still
holds the slot until retried or closed), `abandoned`.

## AI API

All calls need `Authorization: Bearer <AI_TOKEN>` (generated into `/etc/omadawrite/env` by
`install.sh`). The AI can submit, read and withdraw. It cannot approve.

| Call | Does |
|---|---|
| `POST /api/proposals` | submit → `201` with the proposal, `409` if one is open, `422` if invalid |
| `GET /api/proposals/current` | `{"open": proposal \| null}`, including per-command results and the event log |
| `GET /api/proposals/{id}` | one proposal |
| `POST /api/proposals/{id}/withdraw` | pending → withdrawn |
| `GET /api/proposals/{id}/files/{n}` | the capture file saved by command `n` (0-based), see *Capture downloads* |

Example: [examples/proposal-dhcp-reservation.json](examples/proposal-dhcp-reservation.json).

Rules for `commands`:

- `path` is relative to `/{omadacId}/api/v2` (the internal API the web UI uses). No query
  string in it (use `query`), and no `..`, `%` or `//`.
- A path `/openapi/v1|v2|v3/sites/…` goes to the documented Open API instead, site level only,
  with the UI header `Omada-Request-Source: web-local`. The box adds the omadacId.
- `method` is one of GET, POST, PUT, PATCH, DELETE. A GET can't have a body.
- 1–50 commands. They run in order and stop at the first reply that isn't HTTP 200 with
  `errorCode 0`.
- **Deny list:** login/logout, users/admins/roles/tenants,
  maintenance/backup/restore/upgrade/firmware, `/controller/*`, `/files/*`. Change it with
  `DENY_PATH_REGEX`. The one exception is the capture download below.
- Secret fields in a body (`privateKey`, `presharedKey`, `password`, `secret`) are never returned
  or shown, and are scrubbed from the database once the proposal closes.
- The internal API isn't documented. Use the Open API spec for required fields and enums
  (`tools/omada-apidoc`), a live GET for field names, and the browser devtools Network tab for
  the exact request the UI sends. Include a GET before and after the change so the reviewer can
  compare.

## Capture downloads

A proposal can fetch a packet capture after the usual capture `start` / `status` / `stop`
commands (`/sites/{siteId}/capture/device-type/{type}/{mac}/…`). The download is the only
`/files` call allowed, and only as:

```json
{ "method": "POST",
  "path": "/files/sites/0123456789abcdef01234567/capture/device-type/gateway/AA-BB-CC-DD-EE-FF/download",
  "body": { "requestId": "<GUID>", "stack": false } }
```

- Path: site id = 24 lowercase hex, type `ap` | `switch` | `gateway`, MAC upper-case with `-`.
- Body: `requestId` (1–128 chars of `A-Z a-z 0-9 . _ : -`, required) and optional boolean
  `stack`; nothing else, and no `query`. Otherwise `422`.
- The reply is streamed to `CAPTURE_DIR/<proposal id>-<command index>.pcap`. The command's result
  holds only `{"saved", "bytes", "sha256", "content_type", "http_status"}`.
- Over `CAPTURE_MAX_MB` (default 200) the download stops and the partial file is deleted.
- Fetch it with the AI token: `GET /api/proposals/{id}/files/{n}`. Files are not deleted automatically.
- It changes no config, so it counts as a read when deciding whether a refused proposal changed
  nothing. `CAPTURE_DOWNLOAD=false` turns it off.

## Deploy (Proxmox)

Requirements: the controller VM on ZFS (or other snapshot-capable) storage, a Debian 13 LXC
template, and `certbot` with the Cloudflare DNS plugin on the host if you use `omadawrite-cert`.

First edit the variables at the top of `deploy/host/*` (node name, CT id, IP, gateway, VLAN,
domain) and `deploy/ct/env.example` (controller and Proxmox addresses, VM id).

```bash
# on your workstation
tar czf /tmp/omadawrite.tar.gz app deploy
scp /tmp/omadawrite.tar.gz root@<proxmox-node>:/root/

# on the Proxmox node that runs the controller VM
tar xzf /root/omadawrite.tar.gz -C /root deploy
install -m 0755 /root/deploy/host/omadawrite-{create-ct,pve-token,cert,dns} /usr/local/sbin/
install -m 0644 /root/deploy/host/omadawrite-cert.{service,timer} /etc/systemd/system/

omadawrite-create-ct /root/omadawrite.tar.gz   # creates the CT and installs the app
omadawrite-pve-token                           # snapshot/rollback token for the controller VM only → CT env
omadawrite-dns apply                           # optional: Cloudflare A record → the CT's IP
omadawrite-cert deploy                         # optional: Let's Encrypt via DNS-01 → CT nginx
systemctl daemon-reload && systemctl enable --now omadawrite-cert.timer
pct exec <ctid> -- grep ^AI_TOKEN= /etc/omadawrite/env
```

To upgrade, push a new tarball, re-extract it in the CT and re-run
`bash /root/omadawrite-src/deploy/ct/install.sh`. The env file is kept.

### Credentials

| Secret | Where | Scope |
|---|---|---|
| AI bearer token | `/etc/omadawrite/env` (root 0600, systemd `EnvironmentFile`) | submit / read / withdraw only |
| Cookie key | same file | encrypts the reviewer's Omada login in the cookie |
| Proxmox token | same file, written by `omadawrite-pve-token` via `/run` + `pct push` | `VM.Audit, VM.Snapshot, VM.Snapshot.Rollback, VM.PowerMgmt` on the controller VM + `PVEAuditor` on the node |
| Cloudflare token | `/etc/pve/priv/cloudflare.env` on the host | never enters the CT |

## Tools

- `tools/omadawrite-wait <id> [--until-applied | --until-settled]` / `--free`: waits for a proposal
  and exits with a code per outcome (0 completed, 1 reverted/failed, 2 rejected_by_omada,
  3 rejected/withdrawn, 4 watching, 5 timeout, 6 box unreachable). Meant to run in the background
  of an AI session. Configure with `OMADAWRITE_IP`, `OMADAWRITE_NAME`, `OMADAWRITE_TOKEN`.
- `tools/omada-apidoc fetch | tags | search | op | schema`: downloads the controller's own OpenAPI
  spec (`/v3/api-docs`) into `docs/` and prints required fields and enums. Configure with
  `OMADA_IP`, `OMADA_NAME`. The spec itself is TP-Link's and isn't included here.

## Limits

- **A rollback restores the whole controller**, including undoing hand-made edits and new admin
  accounts made after Approve. Don't change Omada by hand while a proposal is open.
- **ZFS can only roll back to the newest snapshot.** Don't take manual snapshots of the controller
  VM while a proposal is open. Pruning keeps the newest `KEEP_SNAPSHOTS` `ow-*` snapshots and never
  touches others.
- **Rolling back the controller doesn't reach a gateway that's cut off from it.** For changes to the
  management VLAN, have local access ready.
- **"Internet up" is the only automatic health signal.** Use Revert now for anything else.

## Tests

```bash
python3 -m venv /tmp/owvenv && /tmp/owvenv/bin/pip install fastapi uvicorn httpx cryptography pytest
/tmp/owvenv/bin/python -m pytest -q tests
```

## License

MIT, see [LICENSE](LICENSE).
