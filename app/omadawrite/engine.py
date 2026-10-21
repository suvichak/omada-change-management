"""Proposal lifecycle.

                                           applying ──Omada refused a write, nothing changed──▶ rejected_by_omada
pending ──approve──▶ snapshotting ──▶ applying ──▶ watching ──(watch over + stable streak)──▶ completed
   │                     │                │          │  ▲
   ├─reject─▶ rejected   └─fail─▶ failed ◀┘ internet │  └─ internet back: auto-revert disarmed, streak restarts
   │                                   not stable 5 s│
   └─withdraw─▶ withdrawn                            ├─keep─▶ completed
                                                     ├─revert / auto-revert─▶ reverting ──▶ reverted
                                                     │                             └─▶ revert_failed ─retry─▶ reverting
                                                     └─hold: auto-revert off              └─abandon─▶ abandoned

Watch timeline, from the moment the last command ran (defaults):
  0 ─ settle 1 min (no judgement) ─ 1 min ─ watch 5 min ─ 6 min: close once the internet
  has also been up continuously for 4 min. Down for 5 min straight after the settle → revert.

Only the watchdog process performs rollbacks; the web process only asks for one
by setting status=reverting. So a restart of either process never runs two.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time

from . import db
from .config import CAPTURE_DOWNLOAD_RE
from .netcheck import internet_up
from .omada import OPENAPI_RE, Omada
from .proxmox import PVE, PVEError

log = logging.getLogger("omadawrite")

# No "%": a percent-encoded letter (/%75sers) would slip past the deny list and be decoded
# by the controller. \Z, not $: "$" also matches before a trailing newline.
PATH_RE = re.compile(r"^/[A-Za-z0-9._~\-/]*\Z")
MAX_REVERT_ATTEMPTS = 5
CAPTURE_RE = re.compile(CAPTURE_DOWNLOAD_RE)
# requestId of a capture download: "a GUID based on the timestamp" per the spec
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}\Z")


def capture_download(method: str, path) -> bool:
    """POST of the capture download path: its reply is a file, and it changes no Omada config."""
    return method == "POST" and isinstance(path, str) and bool(CAPTURE_RE.match(path))


def capture_path(cfg, pid: int, idx: int) -> str:
    # Built only from our own ids, never from anything in the proposal.
    return os.path.join(cfg.capture_dir, f"{pid}-{idx}.pcap")


def saved_capture(cfg, pid: int, result) -> str | None:
    """File saved by a capture download result, or None. The recorded path must be the
    one capture_path() gives for this proposal and command."""
    if not result or not capture_download(result["method"], result["path"]):
        return None
    try:
        saved = json.loads(result["response"] or "").get("saved")
    except (ValueError, AttributeError):
        return None
    path = capture_path(cfg, pid, result["idx"])
    return path if saved == path and os.path.isfile(path) else None


def untouched(commands: list, results: list) -> bool:
    """True when the result log proves Omada state was not changed.

    Every recorded command before the last was a read (a GET or a capture download)
    that succeeded, and the last one got an explicit refusal (HTTP 200 with
    errorCode != 0). A timeout or a missing reply proves nothing, so it never counts
    as untouched.
    """
    if not results or len(results) > len(commands):
        return False
    *before, last = sorted(results, key=lambda r: r["idx"])
    if any((r["method"] != "GET" and not capture_download(r["method"], r.get("path")))
           or r["http_status"] != 200 or r["error_code"] != 0 for r in before):
        return False
    return last["http_status"] == 200 and last["error_code"] not in (None, 0)


class Rejected(Exception):
    """Request is invalid or not allowed in the current state."""


class Busy(Exception):
    """Another proposal already holds the open slot."""


# Factories and probe are module-level so tests can swap them.
def make_pve(cfg) -> PVE:
    return PVE(cfg.pve_url, cfg.pve_token, cfg.vmid, cfg.pve_node, cfg.pve_verify_tls, tls_name=cfg.pve_tls_name)


def make_omada(cfg) -> Omada:
    return Omada(cfg.omada_url, cfg.omada_verify_tls, tls_name=cfg.omada_tls_name)


def probe(cfg) -> bool:
    return internet_up(cfg.probe_targets, cfg.probe_timeout)


sleep = time.sleep  # replaced in tests


def internet_stable(cfg) -> int | None:
    """Probe once a second for PREFLIGHT_STABLE_SECONDS. None if every check passed,
    otherwise the second at which a check failed."""
    for i in range(cfg.preflight_stable_seconds + 1):
        if i:
            sleep(1)
        if not probe(cfg):
            return i
    return None


def watch_fields(cfg, t: int) -> dict:
    settle = t + cfg.settle_seconds
    return {"applied_at": t, "settle_until": settle, "watch_until": settle + cfg.watch_minutes * 60,
            "up_since": None, "down_since": None, "revert_at": None}


def _hm(ts: int) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


# ── intake ────────────────────────────────────────────────────────────────────

def validate(cfg, payload: dict):
    title = str(payload.get("title") or "").strip()
    reason = str(payload.get("reason") or "").strip()
    if not title or len(title) > 200:
        raise Rejected("title is required (max 200 chars)")
    if not reason or len(reason) > 5000:
        raise Rejected("reason is required (max 5000 chars): say what changes and why")
    cmds = payload.get("commands")
    if not isinstance(cmds, list) or not 1 <= len(cmds) <= cfg.max_commands:
        raise Rejected(f"commands must be a list of 1..{cfg.max_commands} requests")

    out = []
    for i, c in enumerate(cmds):
        where = f"commands[{i}]"
        if not isinstance(c, dict):
            raise Rejected(f"{where} must be an object")
        method = str(c.get("method") or "").upper()
        if method not in cfg.allowed_methods:
            raise Rejected(f"{where}.method must be one of {', '.join(cfg.allowed_methods)}")
        path = c.get("path")
        if not isinstance(path, str) or not PATH_RE.match(path) or ".." in path or "//" in path:
            raise Rejected(f"{where}.path must be a plain path relative to /{{omadacId}}/api/v2 "
                           "(or /openapi/vN/sites/… for the Open API), "
                           "starting with / — put query parameters in 'query', not in the path")
        if path.lower().startswith("/openapi") and not OPENAPI_RE.match(path):
            raise Rejected(f"{where}.path: an Open API path must look like /openapi/v1|v2|v3/sites/… "
                           "(site level only; the box adds the omadacId)")
        download = capture_download(method, path)
        if not (download and cfg.capture_download) and re.search(cfg.deny_path_regex, path):
            raise Rejected(f"{where}.path {path} is on the deny list (accounts, login, controller-level settings)")
        query = c.get("query") or {}
        if not isinstance(query, dict) or any(
                not isinstance(v, (str, int, float, bool)) for v in query.values()):
            raise Rejected(f"{where}.query must be a flat object of scalar values")
        if "token" in query:
            raise Rejected(f"{where}.query must not carry a token")
        body = c.get("body")
        if method == "GET" and body is not None:
            raise Rejected(f"{where}: GET requests cannot have a body")
        if download and (query or not isinstance(body, dict) or not set(body) <= {"requestId", "stack"}
                         or not isinstance(body.get("requestId"), str)
                         or not REQUEST_ID_RE.match(body["requestId"])
                         or not isinstance(body.get("stack", False), bool)):
            raise Rejected(f"{where}: a capture download takes no query and exactly the body "
                           '{"requestId": "<1-128 chars of A-Z a-z 0-9 . _ : ->", "stack": true|false (optional)}')
        out.append({"method": method, "path": path, "query": query, "body": body,
                    "note": str(c.get("note") or "")[:500]})
    return title, reason, out


def submit(cfg, conn, payload: dict) -> int:
    title, reason, cmds = validate(cfg, payload)
    who = str(payload.get("submitted_by") or "ai")[:64]
    try:
        return db.insert(conn, title, reason, who, cmds)
    except sqlite3.IntegrityError:
        op = db.open_proposal(conn)
        raise Busy(f"proposal #{op['id']} is still open (status {op['status']}); "
                   "only one change set at a time") from None


# ── apply (runs in the web process, needs the reviewer's Omada login) ────────

def preflight(cfg, conn, username: str, password: str) -> None:
    tick = db.kv_get(conn, "watchdog_tick")
    if not tick or db.now() - int(tick) > max(60, cfg.tick_seconds * 4):
        raise Rejected("watchdog is not running — refusing to apply without auto-revert protection")
    if not probe(cfg):
        raise Rejected("internet is already down — applying now would trigger an auto-revert of an unrelated outage")
    try:
        make_pve(cfg).snapshots()
    except PVEError as e:
        raise Rejected(f"cannot reach the Proxmox API, so no snapshot is possible: {e}") from None
    om = make_omada(cfg)
    try:
        om.login(username, password)
    except Exception as e:
        om.close()
        raise Rejected(f"Omada login failed: {e}") from None
    om.logout()


def run_apply(cfg, pid: int, username: str, password: str) -> None:
    conn = db.connect(cfg.db_path)
    try:
        _run_apply(cfg, conn, pid, username, password)
    except Exception as e:  # never leave a proposal stuck without a record
        log.exception("apply crashed")
        db.event(conn, pid, "system", f"apply crashed: {e}")
    finally:
        conn.close()


def _run_apply(cfg, conn, pid, username, password):
    p = db.get(conn, pid)
    snap = f"{cfg.snapshot_prefix}{pid}-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(db.now()))}"
    db.event(conn, pid, "system", f"creating snapshot {snap} of VM {cfg.vmid}")
    try:
        pve = make_pve(cfg)
        pve.wait(pve.create_snapshot(snap, f"omadawrite #{pid}: {p['title']}"[:200]), timeout=900)
    except Exception as e:
        db.transition(conn, pid, ("snapshotting",), "failed", "system",
                      f"snapshot failed, nothing was applied: {e}", error=str(e))
        return
    db.transition(conn, pid, ("snapshotting",), "applying", "system", f"snapshot {snap} taken", snapshot=snap)

    # Right before the first write, not only at approve time: the snapshot can take minutes.
    failed_at = internet_stable(cfg)
    if failed_at is not None:
        db.transition(conn, pid, ("applying",), "failed", "system",
                      f"internet check failed {failed_at}s into the {cfg.preflight_stable_seconds}s "
                      "stability check before writing — nothing was applied", error="internet not stable before apply")
        prune(cfg, pid)
        return
    db.event(conn, pid, "system", f"internet stable for {cfg.preflight_stable_seconds}s — sending commands")

    error = None
    done = 0
    om = make_omada(cfg)
    try:
        om.login(username, password)
        for i, c in enumerate(p["commands"]):
            db.update(conn, pid)  # heartbeat for the stuck-apply check
            if capture_download(c["method"], c["path"]):
                # The file goes to CAPTURE_DIR; only its description goes into the database.
                os.makedirs(cfg.capture_dir, mode=0o750, exist_ok=True)
                status, j, text, saved = om.download(c["path"], c["body"], capture_path(cfg, pid, i),
                                                     cfg.capture_max_bytes)
                if saved:
                    j, text = {"errorCode": 0}, json.dumps(saved)
            else:
                status, j, text = om.call(c["method"], c["path"], c["query"], c["body"])
            code = j.get("errorCode") if isinstance(j, dict) else None
            db.add_result(conn, pid, i, c, status, code, text[:20000])
            if status != 200 or code != 0:
                msg = j.get("msg") if isinstance(j, dict) else text[:200]
                error = (f"command {i + 1}/{len(p['commands'])} {c['method']} {c['path']} failed: "
                         f"HTTP {status}, errorCode {code} {msg or ''}".strip())
                break
            done += 1
    except Exception as e:
        error = f"apply aborted after {done} command(s): {e}"
    finally:
        om.logout()

    t = db.now()
    if error and untouched(p["commands"], db.results(conn, pid)):
        # Nothing changed, so there is nothing to watch or revert. Free the slot so a
        # corrected proposal can be submitted.
        if db.transition(conn, pid, ("applying",), "rejected_by_omada", "system",
                         f"{error} — Omada refused it and nothing was changed (only reads succeeded). "
                         "Closed; submit a corrected proposal.", applied_at=t, error=error):
            prune(cfg, pid)
        return
    if error:
        msg = f"{error} — the remaining commands were NOT run. Consider Revert now."
    else:
        msg = f"all {done} command(s) applied"
    db.transition(conn, pid, ("applying",), "watching", "system",
                  f"{msg}; settling {cfg.settle_seconds}s, then watching the internet for {cfg.watch_minutes} min "
                  f"(needs {cfg.stable_minutes} min stable to close)",
                  error=error, **watch_fields(cfg, t))


# ── watchdog (separate process, no Omada credentials needed) ─────────────────

def tick(cfg, conn) -> None:
    t = db.now()
    up = probe(cfg)
    db.kv_set(conn, "watchdog_tick", t)
    db.kv_set(conn, "internet_up", 1 if up else 0)

    p = db.open_proposal(conn)
    if not p:
        return
    pid, st = p["id"], p["status"]

    if st in ("snapshotting", "applying") and t - p["updated_at"] > cfg.stuck_seconds:
        if st == "snapshotting":
            db.transition(conn, pid, (st,), "failed", "watchdog",
                          "snapshot step stalled (web process restarted?) — nothing applied; "
                          "check VM snapshots by hand", error="snapshot stalled")
        else:
            db.transition(conn, pid, (st,), "watching", "watchdog",
                          "apply step stalled — some commands may have run; now watching",
                          error="apply interrupted", **watch_fields(cfg, t))
        return

    if st == "watching" and p["error"] and untouched(p["commands"], db.results(conn, pid)):
        if db.transition(conn, pid, ("watching",), "rejected_by_omada", "watchdog",
                         "Omada refused the change and nothing was changed (only reads succeeded) — "
                         "closed so a corrected proposal can be submitted"):
            prune(cfg, pid)
        return
    if st == "watching":
        _watch(cfg, conn, p, up, t)
    elif st == "reverting":
        _revert(cfg, conn, p, t)


def _watch(cfg, conn, p, up: bool, t: int) -> None:
    pid = p["id"]
    settle_until = p["settle_until"] or p["applied_at"] or t
    if t < settle_until:
        return  # devices are still re-provisioning; a blip here means nothing

    if up:
        if p["down_since"]:
            db.update(conn, pid, down_since=None, revert_at=None, up_since=t)
            db.event(conn, pid, "watchdog",
                     f"internet is back after {t - p['down_since']}s" +
                     (" — auto-revert disarmed" if p["revert_at"] else "") +
                     f"; needs {cfg.stable_minutes} min stable before closing")
            return
        up_since = p["up_since"]
        if up_since is None:
            up_since = t
            db.update(conn, pid, up_since=t)
            db.event(conn, pid, "watchdog", "settle over, internet up — stable streak started")
        stable = t - up_since
        if t >= p["watch_until"] and stable >= cfg.stable_minutes * 60:
            if db.transition(conn, pid, ("watching",), "completed", "watchdog",
                             f"internet up through the watch and stable for {stable // 60} min {stable % 60}s — change kept"):
                prune(cfg, pid)
        return

    if not p["down_since"]:
        at = None if p["hold"] else t + cfg.revert_after_down_minutes * 60
        db.update(conn, pid, down_since=t, up_since=None, revert_at=at)
        db.event(conn, pid, "watchdog",
                 f"internet check failed ({' / '.join(cfg.probe_targets)} did not answer) — " +
                 ("auto-revert is on hold" if p["hold"] else
                  f"retrying for {cfg.revert_after_down_minutes} min; auto-revert to {p['snapshot']} "
                  f"at {_hm(at)} unless it comes back"))
        return
    if p["hold"] or p["revert_at"] is None:
        return
    if t >= p["revert_at"]:
        db.transition(conn, pid, ("watching",), "reverting", "watchdog",
                      f"internet down for {t - p['down_since']}s — rolling the controller VM back")


def _revert(cfg, conn, p, t: int) -> None:
    pid = p["id"]
    try:
        if not p["snapshot"]:
            raise PVEError("this proposal has no snapshot to roll back to")
        pve = make_pve(cfg)
        if not p["revert_upid"]:
            upid = pve.rollback(p["snapshot"])
            db.update(conn, pid, revert_upid=upid)
            db.event(conn, pid, "watchdog", f"rollback to {p['snapshot']} started ({upid})")
            return
        if not p["revert_task_done"]:
            task = pve.task(p["revert_upid"])
            if task.get("status") != "stopped":
                return
            if task.get("exitstatus") != "OK":
                db.transition(conn, pid, ("reverting",), "revert_failed", "watchdog",
                              f"rollback task ended with: {task.get('exitstatus')}",
                              error=str(task.get("exitstatus")))
                return
            db.update(conn, pid, revert_task_done=t)
            db.event(conn, pid, "watchdog", "VM rolled back and started — waiting for the controller")
            return
        if make_omada(cfg).alive():
            if db.transition(conn, pid, ("reverting",), "reverted", "watchdog",
                             f"controller is answering again on snapshot {p['snapshot']}. Devices get the "
                             "old config as they reconnect — use Force Provision on the gateway if it does not"):
                prune(cfg, pid)
        elif t - p["revert_task_done"] > 900:
            db.transition(conn, pid, ("reverting",), "revert_failed", "watchdog",
                          "VM was rolled back but the controller did not answer within 15 min",
                          error="controller not answering after rollback")
    except Exception as e:
        attempts = p["revert_attempts"] + 1
        if attempts < MAX_REVERT_ATTEMPTS:  # next tick re-polls the task, or re-posts if none started
            db.update(conn, pid, revert_attempts=attempts)
            db.event(conn, pid, "watchdog", f"rollback attempt {attempts} failed, retrying: {e}")
        else:
            db.transition(conn, pid, ("reverting",), "revert_failed", "watchdog",
                          f"rollback failed: {e}", error=str(e))


def prune(cfg, pid: int | None = None) -> None:
    """Delete our own old snapshots, keeping the newest KEEP_SNAPSHOTS. Never touches others."""
    conn = db.connect(cfg.db_path)
    try:
        pve = make_pve(cfg)
        ours = sorted((s for s in pve.snapshots() if s["name"].startswith(cfg.snapshot_prefix)),
                      key=lambda s: s.get("snaptime", 0))
        for s in ours[:-cfg.keep_snapshots]:
            pve.wait(pve.delete_snapshot(s["name"]), timeout=600)
            db.event(conn, pid, "system", f"pruned old snapshot {s['name']}")
    except Exception as e:
        db.event(conn, pid, "system", f"snapshot prune failed (harmless): {e}")
    finally:
        conn.close()
