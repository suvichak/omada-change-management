from __future__ import annotations

import json
import re
import sqlite3
import time

# Secrets a proposal body may carry (e.g. a WireGuard private key). They are needed until
# the commands have run; after a proposal closes they are scrubbed from the database, and
# they are never returned by the API or shown in the UI.
REDACTED = "<redacted>"
_SECRET_KEY = re.compile(r"(?i)(private_?key|pre_?shared_?key|password|secret)")
_SECRET_IN_TEXT = re.compile(
    r'("[A-Za-z0-9_]*(?:[Pp]rivate_?[Kk]ey|[Pp]re_?[Ss]hared_?[Kk]ey|[Pp]assword|[Ss]ecret)[A-Za-z0-9_]*"\s*:\s*")'
    r'((?:[^"\\]|\\.)*)(")')


def redact(o):
    """Copy of a JSON value with the values of secret-looking keys replaced."""
    if isinstance(o, dict):
        return {k: (REDACTED if _SECRET_KEY.search(str(k)) and isinstance(v, (str, int, float)) and v != ""
                    else redact(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [redact(v) for v in o]
    return o


def redact_text(s):
    """Same for a raw JSON response text."""
    if not isinstance(s, str):
        return s
    return _SECRET_IN_TEXT.sub(lambda m: m.group(1) + (REDACTED if m.group(2) else "") + m.group(3), s)


def scrub(conn, pid: int | None = None) -> None:
    """Remove secrets from the stored commands and responses of closed proposals."""
    where, args = "active IS NULL", []
    if pid is not None:
        where, args = "active IS NULL AND id=?", [pid]
    for row in conn.execute(f"SELECT id, commands FROM proposals WHERE {where}", args).fetchall():
        clean = json.dumps(redact(json.loads(row["commands"])))
        if clean != row["commands"]:
            conn.execute("UPDATE proposals SET commands=? WHERE id=?", (clean, row["id"]))
        for r in conn.execute("SELECT id, response FROM results WHERE proposal_id=?", (row["id"],)).fetchall():
            t = redact_text(r["response"])
            if t != r["response"]:
                conn.execute("UPDATE results SET response=? WHERE id=?", (t, r["id"]))

# Any status in here holds the single "open" slot. The unique partial index on
# `active` is what enforces one proposal at a time — not application code.
OPEN_STATUSES = ("pending", "snapshotting", "applying", "watching", "reverting", "revert_failed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS proposals (
    id               INTEGER PRIMARY KEY,
    title            TEXT    NOT NULL,
    reason           TEXT    NOT NULL,
    submitted_by     TEXT    NOT NULL,
    commands         TEXT    NOT NULL,          -- JSON list
    status           TEXT    NOT NULL,
    active           INTEGER,                   -- 1 while open, NULL once closed
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,          -- doubles as the apply heartbeat
    approved_by      TEXT,
    approved_at      INTEGER,
    snapshot         TEXT,
    applied_at       INTEGER,
    settle_until     INTEGER,                   -- no internet judgement before this
    watch_until      INTEGER,                   -- earliest close
    up_since         INTEGER,                   -- start of the current stable streak
    down_since       INTEGER,
    revert_at        INTEGER,
    hold             INTEGER NOT NULL DEFAULT 0,
    revert_upid      TEXT,
    revert_task_done INTEGER,
    revert_attempts  INTEGER NOT NULL DEFAULT 0,
    error            TEXT,
    closed_at        INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS one_open_proposal ON proposals(active) WHERE active = 1;

CREATE TABLE IF NOT EXISTS results (
    id          INTEGER PRIMARY KEY,
    proposal_id INTEGER NOT NULL REFERENCES proposals(id),
    idx         INTEGER NOT NULL,
    method      TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    http_status INTEGER,
    error_code  INTEGER,
    response    TEXT,
    ran_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    proposal_id INTEGER REFERENCES proposals(id),
    at          INTEGER NOT NULL,
    actor       TEXT    NOT NULL,
    message     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

clock = time.time  # replaced in tests


def now() -> int:
    return int(clock())


# Columns added after the first deploy; CREATE TABLE IF NOT EXISTS won't add them.
MIGRATIONS = {"settle_until": "INTEGER", "up_since": "INTEGER"}


def init(path: str) -> None:
    conn = sqlite3.connect(path, timeout=10)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        have = {r[1] for r in conn.execute("PRAGMA table_info(proposals)")}
        for col, typ in MIGRATIONS.items():
            if col not in have:
                conn.execute(f"ALTER TABLE proposals ADD COLUMN {col} {typ}")
        conn.row_factory = sqlite3.Row
        scrub(conn)  # proposals closed before scrubbing existed
        conn.commit()
    finally:
        conn.close()


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def _proposal(row) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    d["commands"] = json.loads(d["commands"])
    return d


def get(conn, pid: int) -> dict | None:
    return _proposal(conn.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone())


def open_proposal(conn) -> dict | None:
    return _proposal(conn.execute("SELECT * FROM proposals WHERE active=1").fetchone())


def history(conn, limit: int = 50) -> list:
    rows = conn.execute(
        "SELECT id, title, status, submitted_by, created_at, approved_by, closed_at "
        "FROM proposals ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def results(conn, pid: int) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT idx, method, path, http_status, error_code, response, ran_at "
        "FROM results WHERE proposal_id=? ORDER BY idx", (pid,))]


def events(conn, pid: int) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT at, actor, message FROM events WHERE proposal_id=? ORDER BY id", (pid,))]


def event(conn, pid, actor: str, message: str) -> None:
    conn.execute("INSERT INTO events (proposal_id, at, actor, message) VALUES (?,?,?,?)",
                 (pid, now(), actor, message))


def insert(conn, title: str, reason: str, submitted_by: str, commands: list) -> int:
    t = now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "INSERT INTO proposals (title, reason, submitted_by, commands, status, active, created_at, updated_at) "
            "VALUES (?,?,?,?, 'pending', 1, ?, ?)",
            (title, reason, submitted_by, json.dumps(commands), t, t))
        pid = cur.lastrowid
        event(conn, pid, submitted_by, f"submitted {len(commands)} command(s)")
        conn.execute("COMMIT")
        return pid
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def transition(conn, pid: int, frm: tuple, to: str, actor: str, message: str | None, **fields) -> bool:
    """Move pid from one of `frm` to `to`. Returns False if someone else moved it first."""
    t = now()
    sets = {"status": to, "active": 1 if to in OPEN_STATUSES else None, "updated_at": t}
    if to not in OPEN_STATUSES:
        sets["closed_at"] = t
    sets.update(fields)
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            f"UPDATE proposals SET {', '.join(k + '=?' for k in sets)} "
            f"WHERE id=? AND status IN ({','.join('?' * len(frm))})",
            [*sets.values(), pid, *frm])
        ok = cur.rowcount == 1
        if ok and message:
            event(conn, pid, actor, message)
        if ok and to not in OPEN_STATUSES:
            scrub(conn, pid)
        conn.execute("COMMIT")
        return ok
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def update(conn, pid: int, **fields) -> None:
    fields["updated_at"] = now()
    conn.execute(f"UPDATE proposals SET {', '.join(k + '=?' for k in fields)} WHERE id=?",
                 [*fields.values(), pid])


def add_result(conn, pid: int, idx: int, cmd: dict, http_status, error_code, response: str) -> None:
    conn.execute(
        "INSERT INTO results (proposal_id, idx, method, path, http_status, error_code, response, ran_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (pid, idx, cmd["method"], cmd["path"], http_status, error_code, response, now()))


def kv_set(conn, key: str, value) -> None:
    conn.execute("INSERT INTO kv (key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def kv_get(conn, key: str):
    row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return row[0] if row else None
