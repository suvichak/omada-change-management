from __future__ import annotations

import hashlib
import json
import os
import re

import httpx

# A proposal path "/openapi/v2/sites/…" goes to the documented Open API instead of the
# internal one. The 6.3 web UI itself uses these paths for some screens (e.g. VPN),
# with the session token and this header, and has no internal path for them.
OPENAPI_RE = re.compile(r"^/openapi/(v[1-3])(/sites/[^/]+/.+)\Z")


class OmadaError(Exception):
    pass


class Omada:
    """Omada controller internal web API (/{omadacId}/api/v2), the one the UI uses.

    The token has to go out as a Csrf-Token header AND a ?token= query
    parameter — header-only makes some endpoints answer errorCode 0 with no
    data (see the note "Omada API access and data pulls").

    Paths matching OPENAPI_RE are sent to /openapi/vN/{omadacId}/sites/… with the
    UI's "Omada-Request-Source: web-local" header and no ?token=.
    """

    def __init__(self, base_url: str, verify: bool = True, timeout: float = 30.0, tls_name: str = ""):
        self.base = base_url.rstrip("/")
        self.http = httpx.Client(verify=verify, timeout=timeout)
        # Connect to the IP in base_url, but check the certificate against tls_name.
        self.ext = {"sni_hostname": tls_name} if tls_name else {}
        self.oid = None
        self.token = None

    def info(self) -> dict:
        r = self.http.get(f"{self.base}/api/info", extensions=self.ext)
        r.raise_for_status()
        return r.json()["result"]

    def alive(self) -> bool:
        try:
            return bool(self.info().get("omadacId"))
        except Exception:
            return False
        finally:
            self.close()

    def login(self, username: str, password: str) -> "Omada":
        self.oid = self.info()["omadacId"]
        r = self.http.post(f"{self.base}/{self.oid}/api/v2/login",
                           json={"username": username, "password": password}, extensions=self.ext)
        r.raise_for_status()
        j = r.json()
        if j.get("errorCode") != 0:
            raise OmadaError(j.get("msg") or f"errorCode {j.get('errorCode')}")
        self.token = j["result"]["token"]
        return self

    def call(self, method: str, path: str, query: dict | None = None, body=None):
        params = dict(query or {})
        headers = {"Csrf-Token": self.token}
        m = OPENAPI_RE.match(path)
        if m:
            url = f"{self.base}/openapi/{m.group(1)}/{self.oid}{m.group(2)}"
            headers["Omada-Request-Source"] = "web-local"
        else:
            url = f"{self.base}/{self.oid}/api/v2{path}"
            params["token"] = self.token
        r = self.http.request(
            method, url, params=params,
            json=None if method == "GET" else body,
            headers=headers, extensions=self.ext)
        try:
            j = r.json()
        except ValueError:
            j = None
        return r.status_code, j, r.text

    def download(self, path: str, body, dest: str, max_bytes: int):
        """POST an internal-API path whose reply is a file (a packet capture) and stream it to dest.

        Returns (http_status, json, text, saved). A non-200 or JSON reply (Omada's error
        envelope) is returned like call() and nothing is written; saved is None. Otherwise
        saved describes the file. Over max_bytes the partial file is deleted, saved is None.
        """
        url = f"{self.base}/{self.oid}/api/v2{path}"
        with self.http.stream("POST", url, params={"token": self.token}, json=body,
                              headers={"Csrf-Token": self.token}, extensions=self.ext) as r:
            ctype = r.headers.get("content-type", "")
            if r.status_code != 200 or "json" in ctype.lower():
                raw = b""
                for chunk in r.iter_bytes():  # an error reply is small; never hold more than 1 MB
                    raw += chunk
                    if len(raw) > 1_000_000:
                        break
                text = raw[:1_000_000].decode("utf-8", "replace")
                try:
                    j = json.loads(text)
                except ValueError:
                    j = None
                return r.status_code, j, text, None
            too_big = f"capture file is larger than {max_bytes} bytes — download aborted, nothing saved"
            size = r.headers.get("content-length", "")
            if size.isdigit() and int(size) > max_bytes:
                return r.status_code, None, too_big, None
            part, h, n = dest + ".part", hashlib.sha256(), 0
            try:
                with open(os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640), "wb") as f:
                    for chunk in r.iter_bytes():
                        n += len(chunk)
                        if n > max_bytes:
                            break
                        h.update(chunk)
                        f.write(chunk)
                if n > max_bytes:
                    os.unlink(part)
                    return r.status_code, None, too_big, None
                os.replace(part, dest)
            except BaseException:
                if os.path.exists(part):
                    os.unlink(part)
                raise
        return r.status_code, None, "", {"saved": dest, "bytes": n, "sha256": h.hexdigest(),
                                         "content_type": ctype, "http_status": r.status_code}

    def logout(self) -> None:
        try:
            if self.token:
                self.call("POST", "/logout")
        except Exception:
            pass
        finally:
            self.close()

    def close(self) -> None:
        self.http.close()
