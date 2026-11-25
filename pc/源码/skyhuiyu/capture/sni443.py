"""443 监听 —— ma75 的透传口。

做法：本机同时监听 443，对 `ma75.update.netease.com` 的 SNI 返回由本地 CA 签发的
`CN=ma75.update.netease.com`，然后把请求原样转发到真实 ma75。
实测 `GET https://127.0.0.1:443/`（Host: ma75）返回上游真实的 `403 Forbidden` ——
是**透传**，不是伪造响应。

作用只有一个：让启动器的更新检查在本地可控、不阻塞登录。伪造响应会改变游戏行为，
透传不会。

注意 `ma75` 已经被 hosts 指到 127.0.0.1，所以这里的"连真实服务器"必须用
`dnsx.RealResolver`（自己发 DNS 包），不能用 `getaddrinfo` —— 否则连回自己。
"""

from __future__ import annotations

import socket
import socketserver
import ssl
import threading
from typing import Callable

from .ca import CaptureError, LocalCA
from .dnsx import RealResolver
from .hostsfile import HOSTS_HOST
from .httpio import (HttpError, Reader, connect_tcp, read_request, read_response,
                     serialize_request, serialize_response)
from .pac import PAC_CONTENT_TYPE, build_pac, is_pac_path
from .rewrite import apply as apply_rewrite

LogFn = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


class Port443Listener:
    """SNI 决定用哪张叶子证书，然后把请求透传到真实服务器。

    顺带做一件关键的事：**把配置响应里的 `ACCOUNT_DOMAIN` 改成本机代理地址**
    （与代理那条路共用 `rewrite.apply`）。
    客户端取配置走的就是这个域名，改在这里等于把登录入口收到自己手里。
    """

    def __init__(self, ca: LocalCA, *, bind: str = "0.0.0.0", port: int = 443,
                 default_host: str = HOSTS_HOST, resolver: RealResolver | None = None,
                 proxy_port: int = 8887, log: LogFn = _noop) -> None:
        self.ca = ca
        self.bind = bind
        self.port = port
        self.default_host = default_host
        self.resolver = resolver or RealResolver()
        self.proxy_port = proxy_port
        self.log = log
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._leaf_dir = ca.dir / "leafs"
        self._leaf_dir.mkdir(parents=True, exist_ok=True)
        self.last_error = ""
        self.flows = 0
        self.config_rewrites = 0
        self.account_origin = ""

    @property
    def local_base(self) -> str:
        """改写后写进 ACCOUNT_DOMAIN 的地址（指向代理端口）。"""
        return f"http://127.0.0.1:{self.proxy_port}"

    @property
    def ready(self) -> bool:
        return self._server is not None

    def start(self) -> int:
        if self._server is not None:
            return self.port
        server = socketserver.ThreadingTCPServer((self.bind, self.port), _Handler)
        server.daemon_threads = True
        server.allow_reuse_address = True
        server.owner = self  # type: ignore[attr-defined]
        self.port = server.server_address[1]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="skyhuiyu-443",
                                        daemon=True)
        self._thread.start()
        self.log(f"443 透传已起 {self.bind}:{self.port}（{self.default_host}）")
        return self.port

    def stop(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        self._thread = None
        self.log("443 已停")

    # ------------------------------------------------------------------
    def base_context(self) -> ssl.SSLContext:
        """带 SNI 回调的入口 context。回调里换成对应域名的叶子证书。"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        leaf = self.ca.leaf(self.default_host)
        ctx.load_cert_chain(*self._leaf_files(self.default_host, leaf))
        ctx.set_alpn_protocols(["http/1.1"])

        def _sni(sslsock: ssl.SSLSocket, server_name: str | None, _ctx: ssl.SSLContext) -> None:
            if not server_name:
                return
            try:
                cert_ctx = self.context_for(server_name)
            except Exception as exc:  # noqa: BLE001
                self.last_error = f"SNI {server_name} 签证书失败: {exc}"
                self.log(f"! {self.last_error}")
                return
            sslsock.context = cert_ctx

        ctx.sni_callback = _sni
        return ctx

    def _leaf_files(self, host: str, leaf) -> tuple[str, str]:  # noqa: ANN001
        safe = host.replace(".", "_").replace(":", "_").replace("*", "star")
        crt = self._leaf_dir / f"{safe}.crt"
        key = self._leaf_dir / f"{safe}.key"
        if not crt.exists():
            crt.write_bytes(leaf.cert_pem)
        if not key.exists():
            key.write_bytes(leaf.key_pem)
        return str(crt), str(key)

    def context_for(self, host: str) -> ssl.SSLContext:
        hit = self._contexts.get(host)
        if hit is not None:
            return hit
        leaf = self.ca.leaf(host)
        crt, key = self._leaf_files(host, leaf)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        ctx.set_alpn_protocols(["http/1.1"])
        self._contexts[host] = ctx
        return ctx

    # ------------------------------------------------------------------
    def open_upstream(self, host: str) -> ssl.SSLSocket:
        ip = self.resolver.resolve(host)
        raw = connect_tcp(ip, 443, timeout=15.0)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)


class _Handler(socketserver.BaseRequestHandler):
    server: "socketserver.ThreadingTCPServer"

    def handle(self) -> None:
        owner: Port443Listener = getattr(self.server, "owner")
        sock: socket.socket = self.request
        sock.settimeout(30.0)
        try:
            tls = owner.base_context().wrap_socket(sock, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            owner.last_error = f"443 握手失败: {exc}"
            try:
                sock.close()
            except OSError:
                pass
            return
        try:
            tls.settimeout(30.0)
            rdr = Reader(tls)
            req = read_request(rdr)
            if req is None:
                return
            path = req.path()
            if is_pac_path(path):
                body = build_pac("127.0.0.1:8887").encode()
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: " + PAC_CONTENT_TYPE.encode() +
                    b"\r\nContent-Length: " + str(len(body)).encode() +
                    b"\r\nConnection: close\r\n\r\n" + body)
                return
            host = req.header("Host") or owner.default_host
            host = host.split(":")[0]
            owner.flows += 1
            owner.log(f"→ {req.method} https(443)://{host}{req.path()[:60]}")
            upstream = owner.open_upstream(host)
            try:
                upstream.sendall(serialize_request(req, drop=("Proxy-Connection",
                                                               "Accept-Encoding")))
                resp = read_response(Reader(upstream), method=req.method)
            finally:
                upstream.close()
            owner.log(f"← {resp.status} ({len(resp.body)}b) {host}")
            # 客户端取配置 → 在飞行中把 ACCOUNT_DOMAIN 换成本机代理
            try:
                rr = apply_rewrite(resp, owner.local_base, path=req.path())
            except CaptureError as exc:
                owner.last_error = f"{exc.code}: {exc.detail}"
                owner.log(f"! 配置改写放弃（保持原样）: {exc.detail}")
            else:
                if rr.changed:
                    owner.config_rewrites += 1
                    owner.account_origin = rr.origin
                    owner.log(f"★ 配置已改写：ACCOUNT_DOMAIN {rr.origin} → {owner.local_base}"
                              f"（第 {owner.config_rewrites} 次）")
            tls.sendall(serialize_response(resp))
        except (HttpError, OSError, ssl.SSLError) as exc:
            owner.last_error = f"443 转发失败: {exc}"
            owner.log(f"! {owner.last_error}")
        finally:
            try:
                tls.close()
            except OSError:
                pass
