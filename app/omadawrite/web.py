"""HTTP side.

  /api/*      AI intake — Authorization: Bearer <AI_TOKEN>. Submit, read, withdraw, fetch a
              downloaded capture file. Cannot approve.
  /ui/api/*   Reviewer — ow_session cookie (Omada username+password, Fernet-encrypted)
              plus X-OW-CSRF: 1 on every POST.
"""
from __future__ import annotations

import hmac
import json
import threading
import time
from contextlib import closing
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from . import db, engine
from .config import Config

STATIC = Path(__file__).parent / "static"
STATIC_FILES = {"app.js", "login.js", "style.css"}
COOKIE = "ow_session"


def _thread_runner(fn, *args):
    threading.Thread(target=fn, args=args, daemon=True).start()


def create_app(cfg: Config = None, runner=_thread_runner) -> FastAPI:
    cfg = cfg or Config.from_env()
    fernet = Fernet(cfg.cookie_key.encode())
    db.init(cfg.db_path)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def conn():
        return closing(db.connect(cfg.db_path))

    def session(request: Request):
        raw = request.cookies.get(COOKIE)
        if not raw:
            return None
        try:
            return json.loads(fernet.decrypt(raw.encode(), ttl=cfg.session_hours * 3600))
        except (InvalidToken, ValueError):
            return None

    def require_csrf(request: Request):
        if request.headers.get("x-ow-csrf") != "1":
            raise HTTPException(403, "missing X-OW-CSRF header")

    def require_user(request: Request, mutating: bool = False) -> dict:
        s = session(request)
        if not s:
            raise HTTPException(401, "login required")
        if mutating:
            require_csrf(request)
        return s

    def require_ai(request: Request):
        if not hmac.compare_digest(request.headers.get("authorization", "").encode(),
                                   f"Bearer {cfg.ai_token}".encode()):
            raise HTTPException(401, "missing or wrong AI bearer token")

    async def read_json(request: Request) -> dict:
        # Parse the body whatever Content-Type says — AI clients get that header wrong.
        try:
            payload = json.loads(await request.body() or b"null")
        except ValueError:
            raise HTTPException(400, "body must be JSON")
        if not isinstance(payload, dict):
            raise HTTPException(400, "body must be a JSON object")
        return payload

    def detail(c, pid: int) -> dict:
        p = db.get(c, pid)
        if not p:
            raise HTTPException(404, "no such proposal")
        # Secrets in a body (keys, passwords) never leave the box, not even to the reviewer.
        p["commands"] = db.redact(p["commands"])
        p["results"] = [dict(r, response=db.redact_text(r["response"])) for r in db.results(c, pid)]
        p["events"] = db.events(c, pid)
        return p

    # ── AI intake ──────────────────────────────────────────────────────────

    @app.post("/api/proposals", status_code=201)
    async def api_submit(request: Request):
        require_ai(request)
        payload = await read_json(request)
        return await run_in_threadpool(_submit, payload)

    def _submit(payload: dict):
        with conn() as c:
            try:
                pid = engine.submit(cfg, c, payload)
            except engine.Rejected as e:
                raise HTTPException(422, str(e))
            except engine.Busy as e:
                raise HTTPException(409, str(e))
            return detail(c, pid)

    @app.get("/api/proposals/current")
    def api_current(request: Request):
        require_ai(request)
        with conn() as c:
            op = db.open_proposal(c)
            return {"open": detail(c, op["id"]) if op else None}

    @app.get("/api/proposals/{pid}")
    def api_get(pid: int, request: Request):
        require_ai(request)
        with conn() as c:
            return detail(c, pid)

    @app.get("/api/proposals/{pid}/files/{idx}")
    def api_file(pid: int, idx: int, request: Request):
        require_ai(request)
        with conn() as c:
            r = next((r for r in db.results(c, pid) if r["idx"] == idx), None)
        path = engine.saved_capture(cfg, pid, r)
        if not path:
            raise HTTPException(404, "no saved file for this command")
        return FileResponse(path, media_type="application/octet-stream", filename=f"omadawrite-{pid}-{idx}.pcap")

    @app.post("/api/proposals/{pid}/withdraw")
    def api_withdraw(pid: int, request: Request):
        require_ai(request)
        with conn() as c:
            if not db.transition(c, pid, ("pending",), "withdrawn", "ai", "withdrawn by submitter"):
                raise HTTPException(409, "only a pending proposal can be withdrawn")
            return detail(c, pid)

    # ── reviewer UI ────────────────────────────────────────────────────────

    @app.get("/")
    def index(request: Request):
        if not session(request):
            return RedirectResponse("/login", status_code=303)
        return FileResponse(STATIC / "index.html")

    @app.get("/login")
    def login_page():
        return FileResponse(STATIC / "login.html")

    @app.get("/static/{name}")
    def static(name: str):
        if name not in STATIC_FILES:
            raise HTTPException(404)
        return FileResponse(STATIC / name)

    @app.get("/healthz")
    def healthz():
        with conn() as c:
            tick = int(db.kv_get(c, "watchdog_tick") or 0)
        ok = db.now() - tick <= max(60, cfg.tick_seconds * 4)
        return JSONResponse({"web": True, "watchdog": ok}, status_code=200 if ok else 503)

    @app.post("/auth/login")
    async def auth_login(request: Request):
        require_csrf(request)
        return await run_in_threadpool(_login, await read_json(request))

    def _login(payload: dict):
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")
        om = engine.make_omada(cfg)
        try:
            om.login(username, password)
        except Exception as e:
            om.close()
            time.sleep(1)
            raise HTTPException(401, f"Omada rejected the login: {e}")
        om.logout()
        token = fernet.encrypt(json.dumps({"u": username, "p": password}).encode()).decode()
        resp = JSONResponse({"ok": True, "user": username})
        resp.set_cookie(COOKIE, token, max_age=cfg.session_hours * 3600, httponly=True,
                        secure=cfg.cookie_secure, samesite="strict", path="/")
        with conn() as c:
            db.event(c, None, username, "signed in")
        return resp

    @app.post("/auth/logout")
    def auth_logout():
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE, path="/")
        return resp

    @app.get("/ui/api/state")
    def ui_state(request: Request):
        s = require_user(request)
        with conn() as c:
            op = db.open_proposal(c)
            tick = int(db.kv_get(c, "watchdog_tick") or 0)
            return {
                "user": s["u"],
                "now": db.now(),
                "internet_up": db.kv_get(c, "internet_up") == "1",
                "watchdog_tick": tick,
                "watchdog_ok": db.now() - tick <= max(60, cfg.tick_seconds * 4),
                "settings": {"preflight_stable_seconds": cfg.preflight_stable_seconds,
                             "settle_seconds": cfg.settle_seconds,
                             "watch_minutes": cfg.watch_minutes,
                             "stable_minutes": cfg.stable_minutes,
                             "revert_after_down_minutes": cfg.revert_after_down_minutes,
                             "probe_targets": cfg.probe_targets,
                             "vmid": cfg.vmid},
                "open": detail(c, op["id"]) if op else None,
                "history": db.history(c),
            }

    @app.get("/ui/api/proposals/{pid}")
    def ui_get(pid: int, request: Request):
        require_user(request)
        with conn() as c:
            return detail(c, pid)

    @app.post("/ui/api/proposals/{pid}/{action}")
    def ui_action(pid: int, action: str, request: Request):
        s = require_user(request, mutating=True)
        user = s["u"]
        with conn() as c:
            p = detail(c, pid)
            try:
                if action == "approve":
                    if p["status"] != "pending":
                        raise engine.Rejected(f"proposal is {p['status']}, not pending")
                    engine.preflight(cfg, c, s["u"], s["p"])
                    if not db.transition(c, pid, ("pending",), "snapshotting", user, f"approved by {user}",
                                         approved_by=user, approved_at=db.now()):
                        raise engine.Rejected("proposal changed while approving")
                    runner(engine.run_apply, cfg, pid, s["u"], s["p"])
                elif action == "reject":
                    ok = db.transition(c, pid, ("pending",), "rejected", user, f"rejected by {user}")
                    if not ok:
                        raise engine.Rejected("only a pending proposal can be rejected")
                elif action == "keep":
                    if not db.transition(c, pid, ("watching",), "completed", user, f"kept by {user}"):
                        raise engine.Rejected("only a change under watch can be kept")
                    runner(engine.prune, cfg, pid)
                elif action == "revert":
                    if not p["snapshot"]:
                        raise engine.Rejected("no snapshot recorded for this proposal")
                    if not db.transition(c, pid, ("watching", "revert_failed"), "reverting", user,
                                         f"revert requested by {user}", revert_upid=None,
                                         revert_task_done=None, revert_attempts=0):
                        raise engine.Rejected("revert is only possible while watching or after a failed revert")
                elif action == "hold":
                    if not db.transition(c, pid, ("watching",), "watching", user,
                                         f"auto-revert put on hold by {user}", hold=1, revert_at=None):
                        raise engine.Rejected("hold is only possible while watching")
                elif action == "abandon":
                    if not db.transition(c, pid, ("revert_failed",), "abandoned", user,
                                         f"closed by {user} after a failed revert — fix by hand"):
                        raise engine.Rejected("only a failed revert can be abandoned")
                else:
                    raise HTTPException(404, "unknown action")
            except engine.Rejected as e:
                raise HTTPException(409, str(e))
            return detail(c, pid)

    return app
