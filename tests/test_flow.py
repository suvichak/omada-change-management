import hashlib
import json
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from omadawrite import db, engine, netcheck  # noqa: E402
from omadawrite.config import DEFAULT_DENY, Config  # noqa: E402
from omadawrite.omada import Omada  # noqa: E402
from omadawrite.proxmox import PVEError  # noqa: E402
from omadawrite.web import create_app  # noqa: E402

AI = {"Authorization": "Bearer " + "a" * 32}
CSRF = {"X-OW-CSRF": "1"}
PASSWORD = "s3cret-omada-pass"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000

    def __call__(self):
        return self.t


class FakePVE:
    def __init__(self):
        self.snaps = ["everythingwork"]
        self.rolled_back = None
        self.fail_snapshot = False
        self.task_state = {"status": "stopped", "exitstatus": "OK"}

    def snapshots(self):
        return [{"name": n, "snaptime": i} for i, n in enumerate(self.snaps)]

    def create_snapshot(self, name, description):
        if self.fail_snapshot:
            raise PVEError("zfs said no")
        self.snaps.append(name)
        return "UPID:pve1:snap"

    def rollback(self, name):
        self.rolled_back = name
        return "UPID:pve1:rollback"

    def delete_snapshot(self, name):
        self.snaps.remove(name)
        return "UPID:pve1:del"

    def task(self, upid):
        return self.task_state

    def wait(self, upid, timeout=0, poll=0):
        return self.task_state


class FakeOmada:
    calls = []
    up = True
    reply = None  # handler(request) -> httpx.Response for a capture download

    def login(self, u, p):
        if p != PASSWORD:
            raise Exception("Invalid username or password.")
        return self

    def call(self, method, path, query=None, body=None):
        FakeOmada.calls.append((method, path, query, body))
        if "fail" in path:
            return 200, {"errorCode": -1001, "msg": "Invalid request parameters."}, '{"errorCode":-1001}'
        return 200, {"errorCode": 0, "result": {}}, '{"errorCode":0,"result":{}}'

    def download(self, path, body, dest, max_bytes):
        # The real streaming code, against a mock transport
        FakeOmada.calls.append(("POST", path, None, body))
        om = Omada("https://192.0.2.1:8043")
        om.http = httpx.Client(transport=httpx.MockTransport(FakeOmada.reply))
        om.oid, om.token = "OID", "TOK"
        return om.download(path, body, dest, max_bytes)

    def alive(self):
        return FakeOmada.up

    def logout(self):
        pass

    def close(self):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(db, "clock", clock)
    pve = FakePVE()
    net = {"up": True}
    FakeOmada.calls = []
    FakeOmada.up = True
    monkeypatch.setattr(engine, "make_pve", lambda cfg: pve)
    monkeypatch.setattr(engine, "make_omada", lambda cfg: FakeOmada())
    monkeypatch.setattr(engine, "probe", lambda cfg: net["up"])
    monkeypatch.setattr(engine, "sleep", lambda s: None)

    cfg = Config(
        db_path=str(tmp_path / "ow.db"), ai_token="a" * 32, cookie_key=Fernet.generate_key().decode(),
        omada_url="https://omada.test:8043", omada_tls_name="", omada_verify_tls=True,
        pve_url="https://pve.test:8006", pve_tls_name="",
        pve_token="x", pve_verify_tls=True, pve_node="pve1", vmid=213, snapshot_prefix="ow-",
        keep_snapshots=2, preflight_stable_seconds=5, settle_seconds=60, watch_minutes=5, stable_minutes=4,
        revert_after_down_minutes=5, stuck_seconds=900, tick_seconds=5, probe_targets=["8.8.8.8", "1.0.0.1"],
        probe_timeout=1,
        session_hours=8, cookie_secure=False, max_commands=50, deny_path_regex=DEFAULT_DENY,
        allowed_methods=("GET", "POST", "PUT", "PATCH", "DELETE"),
        capture_download=True, capture_dir=str(tmp_path / "captures"), capture_max_bytes=1000)
    app = create_app(cfg, runner=lambda fn, *a: fn(*a))  # run apply inline
    client = TestClient(app)

    class E:
        pass
    e = E()
    e.cfg, e.client, e.clock, e.pve, e.net = cfg, client, clock, pve, net

    def tick(advance=0):
        clock.t += advance
        with db.connect(cfg.db_path) as c:
            engine.tick(cfg, c)
    e.tick = tick

    def status(pid):
        return client.get(f"/api/proposals/{pid}", headers=AI).json()["status"]
    e.status = status
    return e


def proposal(title="Add DHCP reservation", cmds=None):
    return {"title": title, "reason": "so the printer keeps its address", "submitted_by": "claude",
            "commands": cmds or [
                {"method": "GET", "path": "/sites/abc/setting/lan/networks", "query": {"currentPage": 1}},
                {"method": "PATCH", "path": "/sites/abc/setting/service/dhcp/xyz", "body": {"ip": "192.168.70.9"}},
            ]}


def login(e):
    r = e.client.post("/auth/login", json={"username": "alice", "password": PASSWORD}, headers=CSRF)
    assert r.status_code == 200, r.text


def submit_and_approve(e, **kw):
    pid = e.client.post("/api/proposals", json=proposal(**kw), headers=AI).json()["id"]
    login(e)
    e.tick()  # watchdog heartbeat
    r = e.client.post(f"/ui/api/proposals/{pid}/approve", headers=CSRF)
    assert r.status_code == 200, r.text
    return pid


def test_ai_token_required(env):
    assert env.client.post("/api/proposals", json=proposal()).status_code == 401
    assert env.client.post("/api/proposals", json=proposal(), headers={"Authorization": "Bearer nope"}).status_code == 401


def test_only_one_open_proposal(env):
    r1 = env.client.post("/api/proposals", json=proposal(), headers=AI)
    assert r1.status_code == 201
    r2 = env.client.post("/api/proposals", json=proposal("second"), headers=AI)
    assert r2.status_code == 409 and "#1" in r2.json()["detail"]
    assert env.client.post("/api/proposals/1/withdraw", headers=AI).status_code == 200
    assert env.client.post("/api/proposals", json=proposal("third"), headers=AI).status_code == 201


@pytest.mark.parametrize("cmd, msg", [
    ({"method": "POST", "path": "/users/new"}, "deny list"),
    ({"method": "POST", "path": "/login"}, "deny list"),
    ({"method": "PATCH", "path": "/controller/setting", "body": {}}, "deny list"),
    ({"method": "GET", "path": "/sites/a?token=x"}, "query parameters"),
    ({"method": "GET", "path": "/sites/../x"}, "plain path"),
    ({"method": "GET", "path": "/sites/a", "body": {"x": 1}}, "cannot have a body"),
    ({"method": "TRACE", "path": "/sites/a"}, "method"),
    ({"method": "POST", "path": "/openapi/v2/controller/x", "body": {}}, "Open API path"),
    ({"method": "GET", "path": "/%75sers"}, "plain path"),
    ({"method": "GET", "path": "/openapi/v2/sites/a/vpn/%75sers"}, "plain path"),
    ({"method": "GET", "path": "/sites/a\n"}, "plain path"),
    ({"method": "GET", "path": "/sites//a"}, "plain path"),
    ({"method": "DELETE", "path": "/openapi/v1/sites/a"}, "Open API path"),
    ({"method": "GET", "path": "/OpenAPI/v1/controller/x"}, "Open API path"),
    ({"method": "POST", "path": "/openapi/v9/sites/a/vpn", "body": {}}, "Open API path"),
    ({"method": "POST", "path": "/openapi/v2/sites/a/vpn/users", "body": {}}, "deny list"),
])
def test_validation(env, cmd, msg):
    r = env.client.post("/api/proposals", json=proposal(cmds=[cmd]), headers=AI)
    assert r.status_code == 422 and msg in r.json()["detail"]


def test_login_cookie_is_encrypted_and_csrf_enforced(env):
    assert env.client.post("/auth/login", json={"username": "alice", "password": "wrong"},
                           headers=CSRF).status_code == 401
    login(env)
    cookie = env.client.cookies.get("ow_session")
    assert cookie and PASSWORD not in cookie and "alice" not in cookie
    env.client.post("/api/proposals", json=proposal(), headers=AI)
    assert env.client.post("/ui/api/proposals/1/reject").status_code == 403
    assert env.client.post("/ui/api/proposals/1/reject", headers=CSRF).status_code == 200


def test_refuses_without_watchdog_or_internet(env):
    pid = env.client.post("/api/proposals", json=proposal(), headers=AI).json()["id"]
    login(env)
    r = env.client.post(f"/ui/api/proposals/{pid}/approve", headers=CSRF)
    assert r.status_code == 409 and "watchdog" in r.json()["detail"]
    env.net["up"] = False
    env.tick()
    r = env.client.post(f"/ui/api/proposals/{pid}/approve", headers=CSRF)
    assert r.status_code == 409 and "already down" in r.json()["detail"]
    assert env.status(pid) == "pending"


def test_happy_path_completes_and_prunes(env):
    for n in ("ow-old-1", "ow-old-2"):
        env.pve.snaps.append(n)
    pid = submit_and_approve(env)
    p = env.client.get(f"/api/proposals/{pid}", headers=AI).json()
    assert p["status"] == "watching" and p["snapshot"].startswith("ow-1-")
    assert p["settle_until"] == p["applied_at"] + 60 and p["watch_until"] == p["applied_at"] + 360
    assert [r["error_code"] for r in p["results"]] == [0, 0]
    assert FakeOmada.calls[1] == ("PATCH", "/sites/abc/setting/service/dhcp/xyz", {}, {"ip": "192.168.70.9"})

    env.tick(30)                       # settling
    assert env.client.get(f"/api/proposals/{pid}", headers=AI).json()["up_since"] is None
    env.tick(31)                       # settle over → streak starts
    env.tick(4 * 60)                   # stable 4 min, but the 5-min watch isn't over
    assert env.status(pid) == "watching"
    env.tick(60)                       # 6 min after apply, stable 5 min
    assert env.status(pid) == "completed"
    assert env.pve.snaps == ["everythingwork", "ow-old-2", p["snapshot"]]  # keep 2 of ours, never touch others
    assert env.client.post("/api/proposals", json=proposal("next"), headers=AI).status_code == 201


def test_unstable_internet_before_writing_applies_nothing(env, monkeypatch):
    checks = iter([True, True, True, False])          # fails 3 s into the 5 s check
    monkeypatch.setattr(engine, "probe", lambda cfg: next(checks, True))
    pid = env.client.post("/api/proposals", json=proposal(), headers=AI).json()["id"]
    login(env)
    env.tick()                         # heartbeat (uses the 1st probe)
    assert env.client.post(f"/ui/api/proposals/{pid}/approve", headers=CSRF).status_code == 200
    p = env.client.get(f"/api/proposals/{pid}", headers=AI).json()
    assert p["status"] == "failed" and p["error"] == "internet not stable before apply"
    assert any("stability check before writing" in e["message"] for e in p["events"])
    assert FakeOmada.calls == []
    assert env.client.post("/api/proposals", json=proposal("retry"), headers=AI).status_code == 201


def test_outage_during_settle_is_ignored(env):
    pid = submit_and_approve(env)
    env.net["up"] = False
    env.tick(20)
    env.tick(20)
    p = env.client.get(f"/api/proposals/{pid}", headers=AI).json()
    assert p["down_since"] is None and p["revert_at"] is None
    env.net["up"] = True
    env.tick(25)                       # 65 s: settle over, up
    assert env.client.get(f"/api/proposals/{pid}", headers=AI).json()["up_since"] is not None


def test_internet_down_5_min_after_settle_reverts(env):
    pid = submit_and_approve(env)
    snap = env.client.get(f"/api/proposals/{pid}", headers=AI).json()["snapshot"]
    env.tick(61)                       # settle over, up
    env.net["up"] = False
    env.tick(5)                        # first failure
    p = env.client.get(f"/api/proposals/{pid}", headers=AI).json()
    assert p["revert_at"] == p["down_since"] + 5 * 60 and p["up_since"] is None
    env.tick(4 * 60 + 50)
    assert env.status(pid) == "watching"
    env.tick(10)                       # 5 min down
    assert env.status(pid) == "reverting"
    env.tick(5)                        # rollback posted
    assert env.pve.rolled_back == snap
    env.tick(5)                        # task finished
    env.tick(5)                        # controller answers
    assert env.status(pid) == "reverted"


def test_recovery_disarms_and_needs_4_min_stable(env):
    pid = submit_and_approve(env)
    env.tick(61)
    env.tick(4 * 60)                   # 5 min after apply, up
    env.net["up"] = False
    env.tick(5)
    env.tick(3 * 60)                   # down 3 min, still inside the retry window
    env.net["up"] = True
    env.tick(5)                        # back: disarmed, streak restarts
    p = env.client.get(f"/api/proposals/{pid}", headers=AI).json()
    assert p["status"] == "watching" and p["revert_at"] is None and p["down_since"] is None
    env.tick(3 * 60)                   # watch time long over, but only 3 min stable
    assert env.status(pid) == "watching"
    env.tick(60)                       # 4 min stable
    assert env.status(pid) == "completed" and env.pve.rolled_back is None


def test_hold_blocks_auto_revert_and_revert_now_works(env):
    pid = submit_and_approve(env)
    env.tick(61)
    assert env.client.post(f"/ui/api/proposals/{pid}/hold", headers=CSRF).status_code == 200
    env.net["up"] = False
    env.tick(5)
    env.tick(40 * 60)
    assert env.status(pid) == "watching" and env.pve.rolled_back is None
    assert env.client.post(f"/ui/api/proposals/{pid}/revert", headers=CSRF).status_code == 200
    env.tick(5)
    assert env.pve.rolled_back


def test_partial_failure_stops_and_still_watches(env):
    pid = submit_and_approve(env, cmds=[
        {"method": "POST", "path": "/sites/abc/ok"},
        {"method": "POST", "path": "/sites/abc/fail"},
        {"method": "POST", "path": "/sites/abc/never"},
    ])
    p = env.client.get(f"/api/proposals/{pid}", headers=AI).json()
    assert p["status"] == "watching"
    assert "command 2/3" in p["error"]
    assert [c[1] for c in FakeOmada.calls] == ["/sites/abc/ok", "/sites/abc/fail"]


def test_snapshot_failure_applies_nothing(env):
    env.pve.fail_snapshot = True
    pid = submit_and_approve(env)
    assert env.status(pid) == "failed"
    assert FakeOmada.calls == []


def test_failed_rollback_task_blocks_until_handled(env):
    pid = submit_and_approve(env)
    env.client.post(f"/ui/api/proposals/{pid}/revert", headers=CSRF)
    env.pve.task_state = {"status": "stopped", "exitstatus": "can't rollback, 'x' is not most recent snapshot"}
    env.tick(15)
    env.tick(15)
    assert env.status(pid) == "revert_failed"
    assert env.client.post("/api/proposals", json=proposal("next"), headers=AI).status_code == 409
    assert env.client.post(f"/ui/api/proposals/{pid}/abandon", headers=CSRF).status_code == 200


def test_ui_pages(env):
    assert env.client.get("/", follow_redirects=False).status_code == 303
    login(env)
    assert "omadawrite" in env.client.get("/").text
    assert env.client.get("/static/app.js").status_code == 200
    assert env.client.get("/static/../web.py").status_code == 404
    s = env.client.get("/ui/api/state").json()
    assert s["user"] == "alice" and s["open"] is None


def test_refused_write_with_nothing_changed_closes_and_frees_slot(env):
    pid = submit_and_approve(env, cmds=[
        {"method": "GET", "path": "/sites/abc/before"},
        {"method": "POST", "path": "/sites/abc/fail", "body": {"x": 1}},
        {"method": "GET", "path": "/sites/abc/after"},
    ])
    p = env.client.get(f"/api/proposals/{pid}", headers=AI).json()
    assert p["status"] == "rejected_by_omada" and "command 2/3" in p["error"]
    assert env.client.get("/api/proposals/current", headers=AI).json()["open"] is None
    assert env.client.post("/api/proposals", json=proposal("corrected"), headers=AI).status_code == 201


def test_failure_after_a_successful_write_keeps_watching(env):
    pid = submit_and_approve(env, cmds=[
        {"method": "POST", "path": "/sites/abc/ok"},
        {"method": "POST", "path": "/sites/abc/fail"},
    ])
    assert env.status(pid) == "watching"
    env.tick(15)
    assert env.status(pid) == "watching"


def test_watchdog_closes_an_already_watching_untouched_proposal(env, monkeypatch):
    # e.g. proposal #1 that failed before this rule existed
    monkeypatch.setattr(engine, "untouched", lambda c, r: False)
    pid = submit_and_approve(env, cmds=[
        {"method": "GET", "path": "/sites/abc/before"},
        {"method": "POST", "path": "/sites/abc/fail"},
    ])
    assert env.status(pid) == "watching"
    monkeypatch.undo()
    monkeypatch.setattr(db, "clock", env.clock)
    monkeypatch.setattr(engine, "make_pve", lambda cfg: env.pve)
    monkeypatch.setattr(engine, "probe", lambda cfg: env.net["up"])
    monkeypatch.setattr(engine, "sleep", lambda s: None)
    env.tick(15)
    assert env.status(pid) == "rejected_by_omada"


def test_untouched_rules():
    g = lambda i, code=0, st=200: {"idx": i, "method": "GET", "http_status": st, "error_code": code}
    w = lambda i, code, st=200: {"idx": i, "method": "POST", "http_status": st, "error_code": code}
    cmds = [{}] * 3
    assert engine.untouched(cmds, [g(0), w(1, -1001)])
    assert not engine.untouched(cmds, [g(0), w(1, 0), w(2, -1001)])     # a write succeeded
    assert not engine.untouched(cmds, [g(0), w(1, None, 502)])          # no clear refusal
    assert not engine.untouched(cmds, [])                               # nothing recorded (e.g. timeout)


def test_probe_targets_icmp_or_tcp(monkeypatch):
    seen = []
    monkeypatch.setattr(netcheck, "_icmp", lambda h, t: seen.append(("icmp", h)) or h == "1.0.0.1")
    monkeypatch.setattr(netcheck, "_tcp", lambda h, port, t: seen.append(("tcp", h, port)) or False)
    assert netcheck.internet_up(["8.8.8.8", "1.0.0.1"])          # one of two answering is enough
    assert not netcheck.internet_up(["8.8.8.8", "9.9.9.9:443"])
    assert ("tcp", "9.9.9.9", 443) in seen and ("icmp", "8.8.8.8") in seen


def test_openapi_paths_are_accepted_and_routed(env):
    r = env.client.post("/api/proposals", headers=AI, json=proposal(cmds=[
        {"method": "POST", "path": "/openapi/v2/sites/S1/vpn/client-to-site-vpn-clients", "body": {"name": "x"}}]))
    assert r.status_code in (200, 201), r.text

    import httpx
    from omadawrite.omada import Omada
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={"errorCode": 0, "result": {}})

    om = Omada("https://192.0.2.1:8043")
    om.http = httpx.Client(transport=httpx.MockTransport(handler))
    om.oid, om.token = "OID", "TOK"
    om.call("POST", "/openapi/v2/sites/S1/vpn/client-to-site-vpn-clients", {}, {"name": "x"})
    om.call("GET", "/sites/S1/setting/lan/networks", {"currentPage": 1})
    o, i = seen
    assert o.url.path == "/openapi/v2/OID/sites/S1/vpn/client-to-site-vpn-clients"
    assert o.headers["Omada-Request-Source"] == "web-local" and o.headers["Csrf-Token"] == "TOK"
    assert "token" not in o.url.params
    assert i.url.path == "/OID/api/v2/sites/S1/setting/lan/networks" and i.url.params["token"] == "TOK"
    assert "Omada-Request-Source" not in i.headers


def test_secrets_are_never_returned_and_are_scrubbed_on_close(env):
    key = "A" * 43 + "="
    cmds = [{"method": "POST", "path": "/sites/S1/setting/wireguard",
             "body": {"name": "x", "privateKey": key, "peer": {"presharedKey": key, "publicKey": "PUB"}}}]
    r = env.client.post("/api/proposals", json=proposal(cmds=cmds), headers=AI)
    assert r.status_code in (200, 201) and key not in r.text
    pid = r.json()["id"]
    assert r.json()["commands"][0]["body"]["peer"]["publicKey"] == "PUB"
    assert key not in env.client.get(f"/api/proposals/{pid}", headers=AI).text
    raw = lambda: db.connect(env.cfg.db_path).execute(
        "SELECT commands FROM proposals WHERE id=?", (pid,)).fetchone()[0]
    assert key in raw()                      # still needed to apply it
    assert env.client.post(f"/api/proposals/{pid}/withdraw", headers=AI).status_code == 200
    assert key not in raw() and db.REDACTED in raw()

    t = '{"result":{"privateKey":"%s","publicKey":"PUB","presharedKey":"","clientPassword":"p\\"w"}}' % key
    out = db.redact_text(t)
    assert key not in out and '"publicKey":"PUB"' in out and '"presharedKey":""' in out and 'p\\"w' not in out


SITE = "0123456789abcdef01234567"
DL = f"/files/sites/{SITE}/capture/device-type/gateway/AA-BB-CC-DD-EE-FF/download"
PCAP = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000") + bytes(range(256)) * 2


def capture(body=None, path=DL):
    return {"method": "POST", "path": path, "body": {"requestId": "1729245600000-ab12"} if body is None else body}


@pytest.mark.parametrize("cmd", [
    capture(),
    capture({"requestId": "8f14e45f-ceea-467f-a0e6-2b3c1d5e6f70", "stack": False}),
    capture(path=DL.replace("gateway", "ap")),
    capture(path=DL.replace("gateway", "switch")),
])
def test_capture_download_is_allowed(env, cmd):
    r = env.client.post("/api/proposals", json=proposal(cmds=[cmd]), headers=AI)
    assert r.status_code == 201, r.text


@pytest.mark.parametrize("cmd, msg", [
    ({"method": "GET", "path": DL}, "deny list"),
    ({"method": "PUT", "path": DL, "body": {"requestId": "x"}}, "deny list"),
    ({"method": "DELETE", "path": DL}, "deny list"),
    (capture(path=f"/files/sites/{SITE}/capture/device-type/gateway/AA-BB-CC-DD-EE-FF/upload"), "deny list"),
    (capture(path=f"/files/sites/{SITE}/backup/download"), "deny list"),
    (capture(path="/files/controller/backup"), "deny list"),
    (capture(path=DL.replace("gateway", "olt")), "deny list"),
    (capture(path=DL.replace("AA-BB", "aa-bb")), "deny list"),
    (capture(path=DL.replace(SITE, "Default")), "deny list"),
    (capture(path=DL + "/x"), "deny list"),
    (capture(path=DL.replace("/download", "/%64ownload")), "plain path"),
    (capture(path=DL.replace("/files/", "/files//")), "plain path"),
    (capture(path=DL + "\n"), "plain path"),
    (capture({}), "capture download"),
    (capture({"requestId": ""}), "capture download"),
    (capture({"requestId": 12}), "capture download"),
    (capture({"requestId": "a" * 129}), "capture download"),
    (capture({"requestId": "../x"}), "capture download"),
    (capture({"requestId": "x", "stack": "yes"}), "capture download"),
    (capture({"requestId": "x", "path": "/etc/passwd"}), "capture download"),
    ({**capture(), "body": None}, "capture download"),
    ({**capture(), "query": {"name": "x.pcap"}}, "capture download"),
])
def test_capture_download_validation(env, cmd, msg):
    r = env.client.post("/api/proposals", json=proposal(cmds=[cmd]), headers=AI)
    assert r.status_code == 422 and msg in r.json()["detail"], r.text


def test_capture_exception_can_be_switched_off(env):
    env.cfg.capture_download = False
    r = env.client.post("/api/proposals", json=proposal(cmds=[capture()]), headers=AI)
    assert r.status_code == 422 and "deny list" in r.json()["detail"]


def test_capture_download_saves_file_not_db(env):
    seen = []

    def reply(req):
        seen.append(req)
        return httpx.Response(200, content=PCAP, headers={"content-type": "application/octet-stream"})
    FakeOmada.reply = reply
    pid = submit_and_approve(env, cmds=[capture()])
    assert env.status(pid) == "watching" and env.client.get(f"/api/proposals/{pid}", headers=AI).json()["error"] is None
    req = seen[0]
    assert req.method == "POST" and req.url.path == f"/OID/api/v2{DL}" and req.url.params["token"] == "TOK"
    assert json.loads(req.content) == {"requestId": "1729245600000-ab12"}

    path = Path(env.cfg.capture_dir) / f"{pid}-0.pcap"
    assert path.read_bytes() == PCAP and not list(Path(env.cfg.capture_dir).glob("*.part"))
    res = env.client.get(f"/api/proposals/{pid}", headers=AI).json()["results"][0]
    info = json.loads(res["response"])
    assert info == {"saved": str(path), "bytes": len(PCAP), "sha256": hashlib.sha256(PCAP).hexdigest(),
                    "content_type": "application/octet-stream", "http_status": 200}
    assert res["error_code"] == 0
    stored = db.connect(env.cfg.db_path).execute("SELECT group_concat(response) FROM results").fetchone()[0]
    assert PCAP[24:40].decode("latin-1") not in stored and len(stored) < 400

    url = f"/api/proposals/{pid}/files/0"
    assert env.client.get(url).status_code == 401
    assert env.client.get(url, headers={"Authorization": "Bearer nope"}).status_code == 401
    login(env)                                   # a reviewer cookie is not the AI token
    assert env.client.get(url).status_code == 401
    r = env.client.get(url, headers=AI)
    assert r.status_code == 200 and r.content == PCAP
    assert r.headers["content-type"] == "application/octet-stream"
    assert f"omadawrite-{pid}-0.pcap" in r.headers["content-disposition"]
    assert env.client.get(f"/api/proposals/{pid}/files/1", headers=AI).status_code == 404
    assert env.client.get(f"/api/proposals/{pid + 1}/files/0", headers=AI).status_code == 404
    assert env.client.get(f"/api/proposals/{pid}/files/..%2F..%2Fow.db", headers=AI).status_code in (404, 422)

    env.tick(61)
    env.tick(5 * 60)
    assert env.status(pid) == "completed"        # a capture-only proposal closes like any other


def test_no_file_for_a_normal_command(env):
    pid = submit_and_approve(env)
    assert env.client.get(f"/api/proposals/{pid}/files/1", headers=AI).status_code == 404


def test_capture_download_over_the_cap_saves_nothing(env):
    big = PCAP * 10                              # cap is 1000 bytes in the fixture
    chunks = lambda: iter([big[i:i + 100] for i in range(0, len(big), 100)])   # no Content-Length
    for content in (big, None):
        FakeOmada.reply = lambda req, c=content: httpx.Response(
            200, content=c if c is not None else chunks(), headers={"content-type": "application/octet-stream"})
        pid = submit_and_approve(env, cmds=[capture(), {"method": "POST", "path": "/sites/abc/never"}])
        p = env.client.get(f"/api/proposals/{pid}", headers=AI).json()
        assert "larger than 1000 bytes" in p["error"] and "command 1/2" in p["error"]
        assert [c[1] for c in FakeOmada.calls][-1] == DL      # stopped before the next command
        assert not any(Path(env.cfg.capture_dir).iterdir())
        assert env.client.get(f"/api/proposals/{pid}/files/0", headers=AI).status_code == 404
        assert env.client.post(f"/ui/api/proposals/{pid}/keep", headers=CSRF).status_code == 200


def test_capture_download_json_error_is_a_refusal(env):
    FakeOmada.reply = lambda req: httpx.Response(200, json={"errorCode": -39001, "msg": "The capture file does not exist."})
    pid = submit_and_approve(env, cmds=[{"method": "GET", "path": "/sites/abc/before"}, capture()])
    p = env.client.get(f"/api/proposals/{pid}", headers=AI).json()
    assert p["status"] == "rejected_by_omada" and "-39001" in p["error"]
    assert p["results"][1]["error_code"] == -39001 and "does not exist" in p["results"][1]["response"]
    assert not Path(env.cfg.capture_dir).exists() or not any(Path(env.cfg.capture_dir).iterdir())
    assert env.client.get(f"/api/proposals/{pid}/files/1", headers=AI).status_code == 404


def test_capture_download_counts_as_a_read(env):
    # download, then a refused write: still nothing changed in Omada
    FakeOmada.reply = lambda req: httpx.Response(200, content=PCAP, headers={"content-type": "application/vnd.tcpdump.pcap"})
    pid = submit_and_approve(env, cmds=[capture(), {"method": "POST", "path": "/sites/abc/fail"}])
    assert env.status(pid) == "rejected_by_omada"
    assert env.client.get(f"/api/proposals/{pid}/files/0", headers=AI).content == PCAP
