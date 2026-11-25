"""绕过 hosts 的 DNS 查询 —— 443 转发与代理上游都要用。

为什么不能用 `socket.getaddrinfo`：我们把 `ma75.update.netease.com` 写进了 hosts
指向 127.0.0.1，`getaddrinfo` 会返回 127.0.0.1，于是"转发到真实服务器"就变成
转发给自己，无限套娃。

所以这里自己发一条 UDP DNS 查询到公共 DNS，拿真实 A 记录。winpcap/dnspython
都不用装：A 记录的报文结构固定，解析这 40 行比引入一个依赖划算。
"""

from __future__ import annotations

import os
import random
import socket
import struct
import time

DEFAULT_SERVERS = ("223.5.5.5", "119.29.29.29", "114.114.114.114")

QTYPE_A = 1
QCLASS_IN = 1


class DnsError(RuntimeError):
    pass


def _encode_name(host: str) -> bytes:
    out = b""
    for label in host.rstrip(".").split("."):
        raw = label.encode("idna") if label.isascii() is False else label.encode("ascii")
        if not raw or len(raw) > 63:
            raise DnsError(f"非法域名标签: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _build_query(host: str, txid: int) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1
    return header + _encode_name(host) + struct.pack(">HH", QTYPE_A, QCLASS_IN)


def _skip_name(pkt: bytes, off: int) -> int:
    """跳过（可能带压缩指针的）域名，返回其后的偏移。"""
    while True:
        if off >= len(pkt):
            raise DnsError("报文截断（域名）")
        n = pkt[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:  # 压缩指针，占 2 字节
            return off + 2
        off += 1 + n


def _parse_response(pkt: bytes, txid: int) -> list[tuple[str, int]]:
    if len(pkt) < 12:
        raise DnsError("报文太短")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", pkt[:12])
    if rid != txid:
        raise DnsError("txid 不匹配")
    rcode = flags & 0x000F
    if rcode == 3:  # NXDOMAIN
        return []
    if rcode != 0:
        raise DnsError(f"DNS rcode={rcode}")

    off = 12
    for _ in range(qd):
        off = _skip_name(pkt, off) + 4
    out: list[tuple[str, int]] = []
    for _ in range(an):
        off = _skip_name(pkt, off)
        if off + 10 > len(pkt):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", pkt[off:off + 10])
        off += 10
        rdata = pkt[off:off + rdlen]
        off += rdlen
        if rtype == QTYPE_A and rdlen == 4:
            out.append((socket.inet_ntoa(rdata), ttl))
    return out


def query_a(host: str, servers: tuple[str, ...] = DEFAULT_SERVERS,
            timeout: float = 2.0) -> list[tuple[str, int]]:
    """查 A 记录，返回 [(ip, ttl)]。多个 DNS 按顺序试，第一个有答案的算数。"""
    txid = random.randrange(0, 0xFFFF)
    last_err: Exception | None = None
    for server in servers:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(_build_query(host, txid), (server, 53))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                pkt, _addr = sock.recvfrom(4096)
                try:
                    answers = _parse_response(pkt, txid)
                except DnsError as exc:
                    last_err = exc
                    continue
                if answers:
                    return answers
                return []
        except OSError as exc:
            last_err = exc
            continue
        finally:
            sock.close()
    raise DnsError(f"{host} 解析失败: {last_err}")


class RealResolver:
    """带缓存的真实地址解析（永远绕开 hosts）。"""

    def __init__(self, servers: tuple[str, ...] = DEFAULT_SERVERS, ttl_cap: float = 300.0) -> None:
        self.servers = servers
        self.ttl_cap = ttl_cap
        self._cache: dict[str, tuple[str, float]] = {}
        # 环境变量做逃生门：内网 DNS 或指定 IP 直连时不用改代码
        override = os.environ.get("SKYHUIYU_REAL_DNS", "")
        if override:
            self.servers = tuple(s.strip() for s in override.split(",") if s.strip())

    def resolve(self, host: str) -> str:
        now = time.monotonic()
        hit = self._cache.get(host)
        if hit and hit[1] > now:
            return hit[0]
        answers = query_a(host, self.servers)
        if not answers:
            self._cache.pop(host, None)
            raise DnsError(f"{host} 没有 A 记录")
        ip, ttl = answers[0]
        self._cache[host] = (ip, now + min(ttl or 60, self.ttl_cap))
        return ip
