from __future__ import annotations

import os
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor


def _checksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _icmp(host: str, timeout: float) -> bool:
    """One ICMP echo over an unprivileged ping socket (SOCK_DGRAM).

    Needs no capability, only the service group inside
    net.ipv4.ping_group_range (install.sh sets that). The kernel matches
    replies to this socket by echo id.
    """
    seq = os.getpid() & 0xFFFF
    payload = b"omadawrite" + struct.pack("!d", time.time())
    pkt = struct.pack("!BBHHH", 8, 0, 0, 0, seq) + payload
    pkt = pkt[:2] + struct.pack("!H", _checksum(pkt)) + pkt[4:]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (host, 0))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                data, addr = s.recvfrom(1024)
                if addr[0] == host and data[:1] == b"\x00" and data[8:] == payload:
                    return True
    except OSError:
        return False
    return False


def _tcp(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe(target: str, timeout: float) -> bool:
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return _tcp(host, int(port), timeout)
    return _icmp(target, timeout)


def internet_up(targets: list, timeout: float = 2.0) -> bool:
    """True if any target answers: a bare IP is pinged (ICMP), IP:port gets a TCP connect.

    Targets are bare IPs on purpose: a DNS failure must not look like — or
    hide — a WAN failure. Two providers (Google 8.8.8.8, Cloudflare 1.0.0.1)
    so one of them having a bad minute is not an outage.
    """
    if not targets:
        return True
    with ThreadPoolExecutor(max_workers=len(targets)) as ex:
        return any(ex.map(lambda t: _probe(t, timeout), targets))
