from __future__ import annotations

import os
from dataclasses import dataclass

# Controller-level and account endpoints are never allowed from a proposal —
# a bad one cannot be undone by the watchdog, or would let the AI grant itself
# access. Override with DENY_PATH_REGEX if you really need one.
DEFAULT_DENY = (
    r"(?i)(^|/)(login|logout)(/|$)"
    r"|/(users|admins?|roles?|tenants?)(/|$)"
    r"|/(maintenance|backup|restore|upgrade|firmware)(/|$)"
    r"|^/controller(/|$)"
    r"|^/files(/|$)"
)

# The one exception to the deny list: POST of exactly this path downloads a packet
# capture (see README "Capture downloads"). It is checked before DENY_PATH_REGEX, so a
# custom deny list does not close it — CAPTURE_DOWNLOAD=false does.
CAPTURE_DOWNLOAD_RE = (
    r"^/files/sites/[0-9a-f]{24}/capture/device-type/(ap|switch|gateway)"
    r"/[0-9A-F]{2}(-[0-9A-F]{2}){5}/download\Z"
)


def _env(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return default if v is None or v.strip() == "" else v.strip()


def _bool(name: str, default: bool) -> bool:
    return _env(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    db_path: str
    ai_token: str
    cookie_key: str
    omada_url: str
    omada_tls_name: str
    omada_verify_tls: bool
    pve_url: str
    pve_tls_name: str
    pve_token: str
    pve_verify_tls: bool
    pve_node: str
    vmid: int
    snapshot_prefix: str
    keep_snapshots: int
    preflight_stable_seconds: int
    settle_seconds: int
    watch_minutes: int
    stable_minutes: int
    revert_after_down_minutes: int
    stuck_seconds: int
    tick_seconds: int
    probe_targets: list
    probe_timeout: float
    session_hours: int
    cookie_secure: bool
    max_commands: int
    deny_path_regex: str
    allowed_methods: tuple
    capture_download: bool
    capture_dir: str
    capture_max_bytes: int

    @classmethod
    def from_env(cls) -> "Config":
        ai_token = _env("AI_TOKEN")
        cookie_key = _env("COOKIE_KEY")
        if len(ai_token) < 24:
            raise SystemExit("AI_TOKEN missing or too short (see /etc/omadawrite/env)")
        if not cookie_key:
            raise SystemExit("COOKIE_KEY missing (see /etc/omadawrite/env)")
        db_path = _env("DB_PATH", "/var/lib/omadawrite/omadawrite.db")
        return cls(
            db_path=db_path,
            ai_token=ai_token,
            cookie_key=cookie_key,
            # Machines talk by IP only; the *_TLS_NAME is what the certificate is checked against.
            omada_url=_env("OMADA_URL", "https://192.168.0.213:8043"),
            omada_tls_name=_env("OMADA_TLS_NAME", "omada.example.com"),
            omada_verify_tls=_bool("OMADA_VERIFY_TLS", True),
            pve_url=_env("PVE_URL", "https://192.168.0.102:8006"),
            pve_tls_name=_env("PVE_TLS_NAME", "pve1.example.com"),
            pve_token=_env("PVE_TOKEN"),
            pve_verify_tls=_bool("PVE_VERIFY_TLS", True),
            pve_node=_env("PVE_NODE", "pve1"),
            vmid=int(_env("VMID", "213")),
            snapshot_prefix=_env("SNAPSHOT_PREFIX", "ow-"),
            keep_snapshots=max(1, int(_env("KEEP_SNAPSHOTS", "3"))),
            # Internet must answer every second for this long right before the first command
            preflight_stable_seconds=int(_env("PREFLIGHT_STABLE_SECONDS", "5")),
            # After the commands, give devices this long to re-provision before judging the internet
            settle_seconds=int(_env("SETTLE_SECONDS", "60")),
            # Then the internet must be up for this long, and continuously for STABLE_MINUTES, to close
            watch_minutes=int(_env("WATCH_MINUTES", "5")),
            stable_minutes=int(_env("STABLE_MINUTES", "4")),
            # Internet down continuously this long (after the settle) -> roll the controller VM back
            revert_after_down_minutes=int(_env("REVERT_AFTER_DOWN_MINUTES", "5")),
            stuck_seconds=int(_env("STUCK_SECONDS", "900")),
            tick_seconds=int(_env("TICK_SECONDS", "5")),
            # Bare IP = ICMP ping, IP:port = TCP connect. Up if any target answers.
            probe_targets=[t.strip() for t in _env(
                "PROBE_TARGETS", "8.8.8.8,1.0.0.1").split(",") if t.strip()],
            probe_timeout=float(_env("PROBE_TIMEOUT", "2")),
            session_hours=int(_env("SESSION_HOURS", "720")),  # 30 days
            cookie_secure=_bool("COOKIE_SECURE", True),
            max_commands=int(_env("MAX_COMMANDS", "50")),
            deny_path_regex=_env("DENY_PATH_REGEX", DEFAULT_DENY),
            allowed_methods=tuple(m.strip().upper() for m in _env(
                "ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE").split(",")),
            capture_download=_bool("CAPTURE_DOWNLOAD", True),
            # Downloaded capture files, named <proposal id>-<command index>.pcap
            capture_dir=_env("CAPTURE_DIR", os.path.join(os.path.dirname(db_path), "captures")),
            capture_max_bytes=int(_env("CAPTURE_MAX_MB", "200")) * 1024 * 1024,
        )
