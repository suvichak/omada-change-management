from __future__ import annotations

import time
import urllib.parse

import httpx


class PVEError(Exception):
    pass


class PVE:
    """Just enough of the Proxmox API to snapshot and roll back one VM.

    The token only holds VM.Audit / VM.Snapshot / VM.Snapshot.Rollback /
    VM.PowerMgmt on /vms/<vmid> (see deploy/host/omadawrite-pve-token).
    """

    def __init__(self, base_url: str, token: str, vmid: int, node: str,
                 verify: bool = True, timeout: float = 30.0, tls_name: str = ""):
        if not token:
            raise PVEError("PVE_TOKEN is not set — run omadawrite-pve-token on the Proxmox host")
        self.base = base_url.rstrip("/") + "/api2/json"
        self.vmid = int(vmid)
        self.node_hint = node
        self.ext = {"sni_hostname": tls_name} if tls_name else {}
        self.http = httpx.Client(verify=verify, timeout=timeout,
                                 headers={"Authorization": f"PVEAPIToken={token}"})

    def _req(self, method: str, path: str, **kw):
        try:
            r = self.http.request(method, self.base + path, extensions=self.ext, **kw)
        except httpx.HTTPError as e:
            raise PVEError(f"{method} {path}: {e}") from e
        if r.status_code >= 400:
            raise PVEError(f"{method} {path}: HTTP {r.status_code} {r.text[:300]}")
        return r.json().get("data")

    def node(self) -> str:
        # Follow the VM if it was migrated; fall back to the configured node.
        try:
            for v in self._req("GET", "/cluster/resources", params={"type": "vm"}) or []:
                if int(v.get("vmid", -1)) == self.vmid and v.get("node"):
                    return v["node"]
        except PVEError:
            pass
        return self.node_hint

    def _vm(self) -> str:
        return f"/nodes/{self.node()}/qemu/{self.vmid}"

    def snapshots(self) -> list:
        return [s for s in self._req("GET", self._vm() + "/snapshot") or [] if s.get("name") != "current"]

    def create_snapshot(self, name: str, description: str) -> str:
        # vmstate=0: disk only. The guest agent freezes the filesystem, MongoDB
        # replays its journal on the next boot. Saving 4.7 GB of RAM buys nothing.
        return self._req("POST", self._vm() + "/snapshot",
                         data={"snapname": name, "description": description, "vmstate": 0})

    def rollback(self, name: str) -> str:
        return self._req("POST", f"{self._vm()}/snapshot/{name}/rollback", data={"start": 1})

    def delete_snapshot(self, name: str) -> str:
        return self._req("DELETE", f"{self._vm()}/snapshot/{name}")

    def task(self, upid: str) -> dict:
        node = upid.split(":")[1]
        return self._req("GET", f"/nodes/{node}/tasks/{urllib.parse.quote(upid, safe='')}/status")

    def wait(self, upid: str, timeout: int = 600, poll: float = 2.0) -> dict:
        deadline = time.time() + timeout
        while True:
            t = self.task(upid)
            if t.get("status") == "stopped":
                if t.get("exitstatus") != "OK":
                    raise PVEError(f"task {upid} ended: {t.get('exitstatus')}")
                return t
            if time.time() > deadline:
                raise PVEError(f"task {upid} still running after {timeout}s")
            time.sleep(poll)
