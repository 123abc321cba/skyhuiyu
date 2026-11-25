"""单端口 MITM 代理 —— **PAC 与代理必须同一个端口**。

一个监听同时提供 HTTP 代理和 PAC 服务（`/local-access/desktop.pac`）。
分端口踩过两次坑：

  · PAC(8898) + 代理(8888) 分端口 → 客户端退回直连；
  · PAC 同端口但内容缺规则 → 同样直连。

所以这里的结构是硬的：一个监听、一条路由表。收到 PAC 路径直接在本进程应答，
不往上游转发；其余请求按 CONNECT / 绝对 URI 两条路走。

MITM 的证书用 `ca.LocalCA` 现签（EC P-256 叶子，签一张不到 1ms）。
不 MITM 的 CONNECT 一律盲转发 —— 不碰不该碰的流量，遥测这类会拒绝我们证书的
客户端也就不会被牵连。
"""

from __future__ import annotations

import json
import os
import re
import socket
import socketserver
import ssl
import threading
import time
from pathlib import Path
from typing import Callable

from .authinfo import ERR_AUTHINFO, ParseResult, from_headers, parse_body
from .ca import CaptureError, LocalCA
from .dnsx import RealResolver
from .httpio import (HttpError, Reader, Request, Response, connect_tcp,
                     read_request, read_response, serialize_request,
                     serialize_response)
from .pac import (MITM_HOSTS, PAC_CONTENT_TYPE, PAC_HOSTS, build_pac, host_matches,
                  is_pac_path)

CA_PATH = "/client-proxy-ca.cer"

LogFn = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


class CaptureProxy:
    def __init__(self, ca: LocalCA, sink: Callable[[object, dict], None], *,
                 bind: str = "127.0.0.1", port: int = 8887,
                 mitm_hosts: tuple[str, ...] = MITM_HOSTS,
                 resolver: RealResolver | None = None,
                 account_host: str = "live-as-sky-merge.game.163.com",
                 account_port: int = 443,
                 pac_ttl: float = 1800.0,
                 log: LogFn = _noop) -> None:
        self.ca = ca
        self.sink = sink
        self.bind = bind
        self.port = port
        self.mitm_hosts = tuple(h.lower() for h in mitm_hosts)
        self.resolver = resolver or RealResolver()
        # 游戏被改写的 `ACCOUNT_DOMAIN` 指向本机端口，这些请求要转到真实域名
        self.account_host = account_host
        self.account_port = account_port
        # PAC 自带过期时间戳：进程被强杀、注册表还原失败、蓝屏之后，
        # 这条 PAC 到点会自动退回 DIRECT，不再长期把网络劫到本机。
        self.pac_expires_at = time.time() + pac_ttl
        self.log = log
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._leaf_dir = ca.dir / "leafs"
        self._leaf_dir.mkdir(parents=True, exist_ok=True)
        self.flows = 0
        self.captured = 0
        self.config_rewrites = 0
        # 是否在飞行中改写响应里的 `ACCOUNT_DOMAIN`。
        # 轻量模式（不动游戏、靠平台登录）必须关掉：那条改写会把官方返回的
        # 账号域名换成本机端口，平台缓存下来以后代理一停就连不上了。
        self.rewrite_config = True
        # 经过代理的域名计数 —— 判断"客户端到底走没走代理"的唯一硬证据。
        # mitm：命中 MITM 表，是真正被我们处理的；blind：交过来了但域名没匹配上。
        self.host_hits: dict[str, int] = {}
        self.blind_hits: dict[str, int] = {}
        self.host_lock = threading.Lock()
        self.account_origin = ""
        self.last_error = ""
        # 认不出的响应落在这儿，用来离线判断它到底是 gzip、加密还是自定义二进制
        self.dump_dir = Path(os.environ.get("SKYHUIYU_DUMP_DIR")
                             or (Path(os.environ.get("APPDATA") or Path.home())
                                 / "SkyHuiyu" / "capture-bodies"))
        self._dumped: set[str] = set()
        # 已经入库过的 session token：游戏每秒都在打接口，不去重会刷几千行
        self._last_token = ""
        # 沿途见过的凭据（build_access_key 只在登录请求头里出现一次，必须攒）
        self._pending: dict[str, str] = {}

    @property
    def local_base(self) -> str:
        """改写后写进 ACCOUNT_DOMAIN 的地址（指向代理端口）。"""
        return f"http://127.0.0.1:{self.port}"

    def maybe_rewrite_config(self, path: str, resp: Response) -> bool:
        """配置响应在飞行中改写 ACCOUNT_DOMAIN。改过返回 True。"""
        if not self.rewrite_config:
            return False
        from .rewrite import apply as apply_rewrite

        try:
            rr = apply_rewrite(resp, self.local_base, path=path)
        except CaptureError as exc:
            self.last_error = f"{exc.code}: {exc.detail}"
            self.log(f"! 配置改写放弃（保持原样）: {exc.detail}")
            return False
        if not rr.changed:
            return False
        self.config_rewrites += 1
        self.account_origin = rr.origin
        self.log(f"★ 配置已改写：ACCOUNT_DOMAIN {rr.origin} → {self.local_base}"
                 f"（第 {self.config_rewrites} 次）")
        return True

    def note_host(self, host: str, *, mitm: bool) -> None:
        """记一笔经过代理的域名。

        排障时先看这个，三个结论一眼可分：
          - mitm 和 blind 都空 → 客户端根本没把请求交过来（PAC 没生效，
            或者平台是在我们接管网络之前启动的，连接池已经建好了）
          - 只有 blind → 交过来了但域名不在 MITM 表里，要往 MITM_HOSTS 加
          - mitm 有一堆但没抓到会话 → 流量通了，问题在解析或登录还没到那一步
        """
        key = (host or "").lower().rstrip(".")
        if not key:
            return
        with self.host_lock:
            d = self.host_hits if mitm else self.blind_hits
            # 只留前 300 个不同域名，避免用户浏览器把所有流量都灌进来把内存吃光
            if key in d or len(d) < 300:
                d[key] = d.get(key, 0) + 1

    def host_report(self) -> dict[str, list[tuple[str, int]]]:
        with self.host_lock:
            def top(d: dict[str, int]) -> list[tuple[str, int]]:
                return sorted(d.items(), key=lambda kv: -kv[1])[:15]
            return {"mitm": top(self.host_hits), "blind": top(self.blind_hits)}

    # ------------------------------------------------------------- 生命周期
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
        self._thread = threading.Thread(target=server.serve_forever, name="skyhuiyu-proxy",
                                        daemon=True)
        self._thread.start()
        self.log(f"代理已起 {self.bind}:{self.port}（PAC 同端口 {self.pac_url}）")
        return self.port

    def stop(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        self._thread = None
        self.log("代理已停")

    @property
    def pac_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/local-access/desktop.pac"

    # ------------------------------------------------------------------ 证书
    def server_context(self, host: str) -> ssl.SSLContext:
        hit = self._contexts.get(host)
        if hit is not None:
            return hit
        leaf = self.ca.leaf(host)
        safe = host.replace(".", "_").replace(":", "_").replace("*", "star")
        crt = self._leaf_dir / f"{safe}.crt"
        key = self._leaf_dir / f"{safe}.key"
        if not crt.exists():
            crt.write_bytes(leaf.cert_pem)
        if not key.exists():
            key.write_bytes(leaf.key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(crt), str(key))
        ctx.set_alpn_protocols(["http/1.1"])
        self._contexts[host] = ctx
        return ctx

    # ------------------------------------------------------------------ 上游
    def open_upstream(self, host: str, port: int, *, tls: bool = True) -> socket.socket:
        """连真实服务器（DNS 绕开 hosts），必要时套 TLS。"""
        ip = self.resolver.resolve(host)
        raw = connect_tcp(ip, port, timeout=15.0)
        if not tls:
            return raw
        # 上游不校验证书：我们是这条链的终点，上游 CDN 的 CN 未必等于劫持域名
        # （ma75 就是这种情况），校验只会把本来能通的更新请求打断。
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)

    # ------------------------------------------------------------------ 判定
    def is_self_target(self, hostport: str) -> bool:
        """这条请求是不是被改写后指向我们自己的端口（游戏的 ACCOUNT_DOMAIN）。"""
        host, _, port_s = hostport.partition(":")
        port = int(port_s) if port_s.isdigit() else 80
        return host.strip("[]").lower() in ("127.0.0.1", "localhost", "::1") and port == self.port

    def should_mitm(self, host: str) -> bool:
        """精确表 + 后缀表，与 PAC 用的是同一套规则（pac.host_matches）。"""
        return host_matches(host)

    def is_account_host(self, host: str) -> bool:
        h = (host or "").lower().rstrip(".")
        return h.endswith("game.163.com") or h.endswith("netease.com")

    # ------------------------------------------------------------------ 抓包
    def _remember_creds(self, req: Request) -> None:
        """登录请求头里那几个凭据只出现一次，先记下来，等会话到了再拼上。

        实测：`x-sky-build-access-key` **只在 `/account/auth/login` 的请求头里**发，
        登录之后的接口一个都不带它。而官方验章接口要它（缺了回 423）。
        所以不能只靠"最后一条请求"，得把沿途见过的都攒着。
        """
        low = {k.lower(): v for k, v in req.header_dict().items()}
        for key, hdr in (("build_access_key", "x-sky-build-access-key"),
                         ("level_id", "x-sky-level-id"),
                         ("session_id", "x-session-id"),
                         ("user_id", "x-user-id"),
                         ("user_id", "user-id")):
            val = (low.get(hdr) or "").strip()
            if val and not self._pending.get(key):
                self._pending[key] = val

    def _fill(self, session) -> None:  # noqa: ANN001
        """用攒下来的凭据补齐会话里缺的字段。"""
        for key, attr in (("build_access_key", "build_access_key"),
                          ("level_id", "level_id"),
                          ("session_id", "session_id"),
                          ("user_id", "user_id")):
            if not getattr(session, attr, "") and self._pending.get(key):
                setattr(session, attr, self._pending[key])

    def on_exchange(self, host: str, req: Request, resp: Response) -> None:
        """一条完整请求/响应。会话优先从**请求头**取，其次才是响应体里的 authinfo。"""
        self.flows += 1
        if not self.is_account_host(host):
            return
        self._remember_creds(req)

        # ① 请求头：游戏每个账号请求都带 x-session-token / x-user-id / X-Session-ID。
        #    实测这是唯一稳定的入口（响应体基本是 session-valid 加密载荷）。
        hr = from_headers(req.header_dict())
        if hr.ok and hr.session is not None:
            token = hr.session.session_token
            if token != self._last_token:
                self._last_token = token
                self.captured += 1
                self._fill(hr.session)
                self.sink(hr.session, {
                    "host": host,
                    "path": req.path()[:200],
                    "status": resp.status,
                    "authinfo_path": "headers",
                    "user_agent": req.header("User-Agent"),
                })
                self.log(f"★ 从请求头抓到会话：user_id={hr.session.user_id} "
                         f"session={token[:8]}… level_id={hr.session.level_id or '无'} "
                         f"session_id={hr.session.session_id or '无'} "
                         f"build_key={'有' if hr.session.build_access_key else '无'}")
            # 头就是权威来源，同一个请求不再去啃响应体（避免一条流量入库两次）
            return

        body = resp.body
        is_auth = "/account/auth" in req.path()
        if not body:
            return
        ctype = resp.header("Content-Type").lower()
        is_encrypted = (resp.header("Content-Encoding").lower() == "session-valid")
        if "json" not in ctype and body.lstrip()[:1] not in (b"{", b"[", b"\x1f"):
            # `session-valid` 是服务端自定义编码（会话密钥加密），抓下来当样本用
            if is_auth or is_encrypted:
                self.log(f"  {req.path()[:52]} 响应 {len(body)}b "
                         f"enc={resp.header('Content-Encoding') or '-'} head={body[:24].hex()}")
                self._dump(req, resp)
            return

        result: ParseResult = parse_body(
            body, req.header_dict(), http_status=resp.status,
            encoding=resp.header("Content-Encoding"))
        if result.ok and result.session is not None:
            token = result.session.session_token
            if token != self._last_token:
                self._last_token = token
                self.captured += 1
                self._fill(result.session)
                self.sink(result.session, {
                    "host": host,
                    "path": req.path()[:200],
                    "status": resp.status,
                    "authinfo_path": result.authinfo_path,
                    "user_agent": req.header("User-Agent"),
                })
                self.log(f"★ 从响应体抓到 authinfo：user_id={result.session.user_id} "
                         f"session={token[:8]}… "
                         f"level_id={result.session.level_id or '无'} "
                         f"build_key={'有' if result.session.build_access_key else '无'} "
                         f"({result.authinfo_path})")
            return

        # 登录相关的响应**整条留档**：里面的键名决定了还缺什么字段
        if is_auth or result.error == ERR_AUTHINFO:
            keys = _top_keys(body)
            if keys:
                self.log(f"  {req.path()[:52]} → {result.error or 'ok'}，顶层键 {keys[:14]}")
                if is_auth:
                    self._dump(req, resp)
            else:
                self.log(f"  {req.path()[:52]} → {result.error}，非 JSON: "
                         f"ct={ctype[:24]} ce={resp.header('Content-Encoding') or '-'} "
                         f"{len(body)}b head={body[:24].hex()}")
                self._dump(req, resp)

    def on_error(self, msg: str) -> None:
        self.last_error = msg
        self.log(f"! {msg}")

    def _dump(self, req: Request, resp: Response) -> None:
        """把认不出的响应存一份（同一个路径只存一次，别把磁盘刷爆）。

        连**请求体**一起存：登录请求里的参数是判断响应格式的唯一线索，
        以后要复现/重放也用它。
        """
        path = req.path().split("?", 1)[0]
        if path in self._dumped or len(resp.body) > 8192:
            return
        self._dumped.add(path)
        try:
            self.dump_dir.mkdir(parents=True, exist_ok=True)
            name = f"{int(time.time())}_{req.method}_{re.sub(r'[^A-Za-z0-9]+', '_', path)[:60]}"
            (self.dump_dir / f"{name}.bin").write_bytes(resp.body)
            if req.body:
                (self.dump_dir / f"{name}.req.bin").write_bytes(req.body[:65536])
            (self.dump_dir / f"{name}.json").write_text(json.dumps({
                "method": req.method,
                "path": req.path()[:300],
                "status": resp.status,
                "resp_headers": dict(resp.headers),
                "req_headers": req.header_dict(),
                "bytes": len(resp.body),
                "hex_head": resp.body[:64].hex(),
                "req_bytes": len(req.body),
                "req_hex_head": req.body[:64].hex(),
            }, ensure_ascii=False, indent=2), "utf-8")
            self.log(f"  已存样本 {self.dump_dir / (name + '.bin')}")
        except Exception:  # noqa: BLE001 - 落盘失败不影响代理
            pass


def _top_keys(body: bytes) -> list[str]:
    """响应 JSON 的顶层键名（只看结构，不取值）。"""
    if not body or body.lstrip()[:1] != b"{":
        return []
    try:
        import json as _json

        node = _json.loads(body.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return []
    return [str(k) for k in node] if isinstance(node, dict) else []


class _Handler(socketserver.BaseRequestHandler):
    server: "socketserver.ThreadingTCPServer"

    def handle(self) -> None:  # noqa: C901 - 就是两条分支，拆开反而难读
        owner: CaptureProxy = getattr(self.server, "owner")
        sock: socket.socket = self.request
        sock.settimeout(60.0)
        try:
            rdr = Reader(sock)
            req = read_request(rdr)
            if req is None:
                return
            path = req.path()
            if is_pac_path(path):
                self._send_small(sock, 200,
                                 build_pac(f"127.0.0.1:{owner.port}",
                                           expires_at=owner.pac_expires_at).encode(),
                                 PAC_CONTENT_TYPE)
                owner.log(f"PAC 已应答 → {path}")
                return
            if path.split("?", 1)[0] == CA_PATH:
                self._send_small(sock, 200, owner.ca.der(), "application/x-x509-ca-cert")
                owner.log("CA 已下发 → /client-proxy-ca.cer")
                return
            if req.method.upper() == "CONNECT":
                self._do_connect(owner, sock, rdr, req)
                return
            self._do_plain(owner, sock, req)
        except (HttpError, OSError, ssl.SSLError) as exc:
            owner.on_error(f"{type(exc).__name__}: {exc}")
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # ---- 直连（http:// 绝对 URI） ----
    def _do_plain(self, owner: CaptureProxy, sock: socket.socket, req: Request) -> None:
        hostport = req.host()
        # 游戏的 ACCOUNT_DOMAIN 被指到 http://127.0.0.1:<我们的端口>，
        # 这类请求要转到真实域名（TLS），不能真去连本机 80。
        if owner.is_self_target(hostport):
            self._do_account_rewrite(owner, sock, req)
            return
        host, _, port_s = hostport.partition(":")
        port = int(port_s) if port_s.isdigit() else 80
        owner.log(f"→ {req.method} {host}{req.path()[:70]}")
        upstream = connect_tcp(owner.resolver.resolve(host), port, timeout=15.0)
        try:
            upstream.sendall(serialize_request(req, drop=("Proxy-Connection", "Accept-Encoding")))
            resp = read_response(Reader(upstream), method=req.method)
        finally:
            upstream.close()
        owner.log(f"← {resp.status} ({len(resp.body)}b) {host}{req.path()[:50]}")
        owner.maybe_rewrite_config(req.path(), resp)
        owner.on_exchange(host, req, resp)
        sock.sendall(serialize_response(resp))

    # ---- ACCOUNT_DOMAIN 改写后的账号请求 ----
    def _do_account_rewrite(self, owner: CaptureProxy, sock: socket.socket,
                            req: Request) -> None:
        """把「游戏交给本机的账号请求」原样转到真实域名。

        PAC 里那条 `url.indexOf("http://127.0.0.1:8887/account/")` 规则
        就是为这一步存在的：让 WinINet 把发往本机的请求也送进代理。
        我们在这里换 Host、走 TLS、把响应原样回给游戏，顺手抓 `authinfo`。
        """
        rhost, rport = owner.account_host, owner.account_port
        path = req.path()
        owner.log(f"→ {req.method} {path[:70]} → {rhost}（ACCOUNT_DOMAIN 改写）")
        headers = [(k, v) for k, v in req.headers
                   if k.lower() not in ("host", "proxy-connection")]
        headers.append(("Host", rhost))
        fwd = Request(req.method, path, req.version, headers, req.body)
        try:
            upstream = owner.open_upstream(rhost, rport, tls=True)
        except (OSError, ssl.SSLError) as exc:
            owner.on_error(f"账号上游连接失败 {rhost}:{rport}: {exc}")
            self._send_small(sock, 502, b"account upstream unreachable", "text/plain")
            return
        try:
            upstream.sendall(serialize_request(fwd, drop=("Proxy-Connection", "Accept-Encoding")))
            resp = read_response(Reader(upstream), method=req.method)
        except (HttpError, OSError, ssl.SSLError) as exc:
            owner.on_error(f"账号上游交互失败 {rhost}: {exc}")
            self._send_small(sock, 502, b"account upstream error", "text/plain")
            return
        finally:
            upstream.close()
        owner.log(f"← {resp.status} ({len(resp.body)}b) {rhost}{path[:50]}")
        owner.maybe_rewrite_config(path, resp)
        owner.on_exchange(rhost, fwd, resp)
        try:
            sock.sendall(serialize_response(resp))
        except OSError:
            pass

    # ---- CONNECT ----
    def _do_connect(self, owner: CaptureProxy, sock: socket.socket, rdr: Reader,
                    req: Request) -> None:
        host, _, port_s = req.target.partition(":")
        port = int(port_s) if port_s.isdigit() else 443
        if not owner.should_mitm(host):
            owner.note_host(host, mitm=False)
            self._blind_tunnel(owner, sock, rdr, host, port)
            return
        owner.note_host(host, mitm=True)
        # 这一行是判断"客户端到底有没有走代理"的关键证据：
        # 有 CONNECT 才谈得上抓包，没有就是走直连了（PAC 没生效 / 缓存了旧结果）。
        owner.log(f"CONNECT {host}:{port} → MITM（客户端走代理了）")

        sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        ctx = owner.server_context(host)
        try:
            tls = ctx.wrap_socket(sock, server_side=True)
        except ssl.SSLError as exc:
            owner.on_error(f"客户端拒绝我们的证书 {host}: {exc}")
            return
        tls.settimeout(60.0)
        inner = Reader(tls)
        while True:
            try:
                req2 = read_request(inner)
            except HttpError as exc:
                owner.on_error(f"{host} 请求解析失败: {exc}")
                return
            if req2 is None:
                return
            owner.log(f"→ {req2.method} https://{host}{req2.path()[:70]}")
            try:
                upstream = owner.open_upstream(host, port)
            except (OSError, ssl.SSLError) as exc:
                owner.on_error(f"上游连接失败 {host}:{port}: {exc}")
                self._send_small(tls, 502, b"upstream unreachable", "text/plain")
                return
            try:
                upstream.sendall(serialize_request(req2, drop=("Proxy-Connection",
                                                               "Accept-Encoding")))
                resp = read_response(Reader(upstream), method=req2.method)
                if resp.status == 101:
                    # WebSocket 升级：头必须原样转发，之后整条连接变成字节流。
                    # 把 101 当普通响应改写（加 Content-Length: 0）会直接废掉 WS。
                    tls.sendall(resp.raw_head or serialize_response(resp))
                    owner.log(f"⇅ {host}{req2.path()[:50]} WebSocket 升级，开始双向隧道")
                    self._pump_pair(tls, upstream)
                    return
            except (HttpError, OSError, ssl.SSLError) as exc:
                owner.on_error(f"上游交互失败 {host}: {exc}")
                return
            finally:
                upstream.close()
            owner.log(f"← {resp.status} ({len(resp.body)}b) {host}{req2.path()[:50]}")
            owner.maybe_rewrite_config(req2.path(), resp)
            owner.on_exchange(host, req2, resp)
            tls.sendall(serialize_response(resp))

    @staticmethod
    def _pump_pair(a: socket.socket, b: socket.socket) -> None:
        """两个 socket 之间双向搬字节，直到两边都断。

        进这里的两条路都是长连接：WebSocket 升级后的隧道，和不 MITM 的裸 CONNECT。
        两个 socket 必须改成无限等待 —— 它们会继承调用方设下的读超时
        （`_do_connect` 给的是 60 秒），空闲 60 秒的 WS 就会抛
        `TimeoutError: timed out` 把整条隧道打断，客户端只能反复重连。

        日志里每轮抓取之后必现的 `! TimeoutError: timed out` ×4 就是这个：
        `loadingbaycn-websocket.webapp.163.com` 被 MITM 了 11 次、升级 11 次，
        说明它一直在断线重连 —— 平台界面因此一顿一顿的。

        对端真死了怎么办：WS 有自己的心跳，TCP 层面也会 RST，
        `recv` 会返回空或者抛 `OSError`，循环自然退出；不需要靠读超时兜底。
        """
        for s in (a, b):
            try:
                s.settimeout(None)
            except OSError:
                pass

        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=pump, args=(a, b), daemon=True)
        t.start()
        pump(b, a)
        t.join(timeout=5)

    # ---- 不 MITM 的 CONNECT：原样打洞 ----
    def _blind_tunnel(self, owner: CaptureProxy, sock: socket.socket, rdr: Reader,
                      host: str, port: int) -> None:
        try:
            upstream = connect_tcp(owner.resolver.resolve(host), port, timeout=10.0)
        except OSError as exc:
            owner.on_error(f"盲转发解析/连接失败 {host}:{port}: {exc}")
            self._send_small(sock, 502, b"upstream unreachable", "text/plain")
            return
        sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        if rdr.buf:
            upstream.sendall(bytes(rdr.buf))
            rdr.buf.clear()

        # 走 _pump_pair：它会把两边都改成无限等待。
        # 这里以前是自己复制了一份 pump，而 `connect_tcp(timeout=10.0)` 建的
        # upstream socket 连上之后那个 10 秒超时还在，`recv` 一空闲就断，
        # 表现和 WebSocket 那个 60 秒的坑一模一样。合成一处，别再各写一遍。
        self._pump_pair(sock, upstream)
        try:
            upstream.close()
        except OSError:
            pass

    @staticmethod
    def _send_small(sock: socket.socket, status: int, body: bytes, ctype: str) -> None:
        reason = {200: "OK", 400: "Bad Request", 502: "Bad Gateway"}.get(status, "OK")
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            sock.sendall(head + body)
        except OSError:
            pass


def free_port(host: str = "127.0.0.1", port: int = 8887) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def listening(host: str, port: int, timeout: float = 0.3) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


__all__ = ["CaptureProxy", "free_port", "listening", "CaptureError", "Path"]
