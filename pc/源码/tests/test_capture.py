"""抓取栈离线/本地联调测试（不需要真游戏、不需要联网）。

    python tests/test_capture.py

覆盖：
  · PAC 文本与客户端实抓原文逐条对齐（规范化、ma75、url.indexOf 规则、同端口）
  · authinfo 解析：只认精确键、拒重复键、session2/3、token_sha256 不当 token、UA 推导
  · CA：生成、叶子 SAN、装进 CurrentUser\\ROOT 再删掉
  · hosts：加/删/幂等（用临时文件，不动真 hosts）
  · WinINet：下发 PAC 再还原（快照与原配置逐字段比对）
  · 代理端到端：PAC 同端口应答、明文 HTTP 抓包、CONNECT MITM 抓包（真 TLS）
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from skyhuiyu.capture import authinfo, cef, hostsfile, pac  # noqa: E402
from skyhuiyu.capture.ca import LocalCA  # noqa: E402
from skyhuiyu.capture.proxy import CaptureProxy  # noqa: E402
from skyhuiyu.capture.wininet import (enable_pac, query,  # noqa: E402
                                            restore)

OK = 0
BAD = 0
SKIP = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global OK, BAD
    if cond:
        OK += 1
        print(f"  PASS  {name}")
    else:
        BAD += 1
        print(f"  FAIL  {name}  [{detail}]")


def skip(name: str, why: str) -> None:
    global SKIP
    SKIP += 1
    print(f"  SKIP  {name}  ({why})")


# --------------------------------------------------------------------------- #
# 1) PAC
# --------------------------------------------------------------------------- #

def test_pac() -> None:
    print("\n[PAC]")
    text = pac.build_pac("127.0.0.1:8887")
    check("has lowercase+trailing-dot normalization",
          "host = host.toLowerCase().replace(/\\.$/, '');" in text)
    check("ma75 in hijack list", '"ma75.update.netease.com"' in text)
    check("account host in list", '"live-as-sky-merge.game.163.com"' in text)
    check("url.indexOf rewrite rule", 'url.indexOf("http://127.0.0.1:8887/account/") === 0' in text)
    check("proxy points to proxy port itself", 'return "PROXY 127.0.0.1:8887"' in text)
    check("default DIRECT", "return 'DIRECT';" in text)
    # PAC 与代理同端口 → PAC URL 必须指向代理端口
    check("pac_url on same port", pac.pac_url(8887) == "http://127.0.0.1:8887/local-access/desktop.pac")
    check("is_pac_path desktop", pac.is_pac_path("/local-access/desktop.pac"))
    check("is_pac_path with query", pac.is_pac_path("/proxy.pac?t=1"))
    check("is_pac_path rejects api", not pac.is_pac_path("/api/state"))
    check("content-type 正确",
          pac.PAC_CONTENT_TYPE == "application/x-ns-proxy-autoconfig", pac.PAC_CONTENT_TYPE)
    # 登录页在 WebView2 里，走的是启动器/SDK 的域；只拦那三个域名永远抓不到
    check("后缀表含 webapp.163.com", '"webapp.163.com"' in text, text)
    check("后缀匹配 loadingbaycn", pac.host_matches("loadingbaycn.webapp.163.com"))
    check("后缀匹配 websocket", pac.host_matches("loadingbaycn-websocket.webapp.163.com"))
    check("后缀匹配 game.163.com 子域", pac.host_matches("live-auth-sky-merge.game.163.com"))
    check("无 A 记录的 unisdk 不拦", not pac.host_matches("unisdk.netease.com"))
    check("无关域名不拦", not pac.host_matches("www.example.com"))


# --------------------------------------------------------------------------- #
# 2) authinfo 解析
# --------------------------------------------------------------------------- #

LOGIN_BODY = {
    "code": 0,
    "result": {
        "auth": {"ip": "1.2.3.4"},
        "authinfo": {
            "user": {"user_id": "1234567890", "nickname": "k"},
            "session": "0123456789abcdef0123456789abcdef",
            "session2": "ffffffffffffffffffffffffffffffff",
            "token_sha256": "deadbeef" * 8,
            "game_version": "0.12.0",
            "build": "289624",
            "game_channel": "netease",
            "game_platform": "android",
        },
    },
}

UA = "Sky-Live-0.12.0.289624 (Pixel 7; Android 13; zh_CN)"

# 抓包实测的真实形态（跟游戏发的一模一样）
GAME_UID = "00000000-0000-4000-8000-000000000001"
GAME_TOKEN = "33333333333333333333333333333333"
GAME_UA = "Sky-Main-000000000/0.16.8.421730 (GENERIC-DESKTOP; win 10.0.26200; zh-Hans)"


def test_authinfo() -> None:
    print("\n[authinfo]")
    headers = {"User-Agent": UA, "x-sky-level-id": "lvl-9",
               "x-sky-build-access-key": "KEY-xyz"}
    r = authinfo.extract(LOGIN_BODY, headers)
    check("解析成功", r.ok, r.detail)
    s = r.session
    if s:
        check("user_id", s.user_id == "1234567890", s.user_id)
        check("session 取 32 位 hex（不是 token_sha256）",
              s.session_token == "0123456789abcdef0123456789abcdef", s.session_token)
        check("level_id 来自请求头", s.level_id == "lvl-9", s.level_id)
        check("build_access_key 来自请求头", s.build_access_key == "KEY-xyz", s.build_access_key)
        check("game_version 来自 authinfo", s.game_version == "0.12.0", s.game_version)
        check("platform 来自 authinfo", s.platform == "android", s.platform)
        check("authinfo_path 记下来了", r.authinfo_path.endswith("authinfo"), r.authinfo_path)
        check("session_source=client_proxy", s.session_source == "client_proxy")

    # 没有 authinfo → authinfo_invalid（不能因为别处有 session 就当登录态）
    no_key = {"result": {"user": {"user_id": "1"}, "session": "a" * 32}}
    r2 = authinfo.extract(no_key, headers)
    check("缺 authinfo 键 → authinfo_invalid",
          r2.error == authinfo.ERR_AUTHINFO, r2.error)

    # 有 authinfo 但没有 session
    r3 = authinfo.extract({"authinfo": {"user": {"user_id": "1"}}}, headers)
    check("authinfo 没 session → authinfo_invalid", r3.error == authinfo.ERR_AUTHINFO, r3.error)

    # 有 session 没有用户
    r4 = authinfo.extract({"authinfo": {"session": "b" * 32}}, headers)
    check("authinfo 没用户 → auth_user_invalid", r4.error == authinfo.ERR_AUTH_USER, r4.error)

    # authinfo 是「装 JSON 的字符串」
    inner = json.dumps({"user_id": "42", "session": "c" * 32})
    r5 = authinfo.extract({"authinfo": inner}, headers)
    check("authinfo 是 JSON 字符串也能解", r5.ok and r5.session.user_id == "42",
          r5.detail)

    # authinfo 是 base64
    import base64

    b64 = base64.b64encode(inner.encode()).decode()
    r6 = authinfo.extract({"authinfo": b64}, headers)
    check("authinfo 是 base64 也能解", r6.ok and r6.session.user_id == "42", r6.detail)

    # 重复键 → json_invalid_or_duplicate
    dup = '{"authinfo": {"session": "d%s"}, "authinfo": {"session": "e%s"}}' % ("0" * 32, "0" * 32)
    r7 = authinfo.parse_body(dup.encode(), headers)
    check("重复键 → json_invalid_or_duplicate", r7.error == authinfo.ERR_JSON, r7.error)

    # 空体 / 非 JSON
    check("空体 → empty_response", authinfo.parse_body(b"", headers).error == authinfo.ERR_EMPTY)
    check("非 JSON → json_invalid_or_duplicate",
          authinfo.parse_body(b"<html>", headers).error == authinfo.ERR_JSON)

    # gzip 体
    import gzip

    gz = gzip.compress(json.dumps(LOGIN_BODY).encode())
    r8 = authinfo.parse_body(gz, headers, encoding="gzip")
    check("gzip 响应能解", r8.ok, r8.detail)

    # 短串不当 token
    r9 = authinfo.extract({"authinfo": {"user_id": "1", "session": "short"}}, headers)
    check("短 session 不算登录态", not r9.ok)

    # UA 推导（两条正则）
    bits = authinfo.parse_ua(UA)
    check("UA → 机型", bits.get("device_model") == "Pixel 7", str(bits))
    check("UA → 平台", bits.get("platform") == "android", str(bits))
    check("UA → 系统版本", bits.get("system_version") == "13", str(bits))
    check("UA → 语言", bits.get("language") == "zh_CN", str(bits))
    check("UA → 版本/构建", bits.get("game_version") == "0.12.0" and bits.get("build") == "289624",
          str(bits))
    ios_bits = authinfo.parse_ua("Sky-Live-0.11.1.200000 (iPhone14,2; iOS 16.6; zh-Hans)")
    check("iOS UA 也能解", ios_bits.get("platform") == "ios", str(ios_bits))


# --------------------------------------------------------------------------- #
# 3) CA
# --------------------------------------------------------------------------- #

def test_ca(tmp: Path) -> None:
    print("\n[CA]")
    ca = LocalCA(tmp / "ca")
    ca.load_or_create()
    check("CA 生成", ca.cert_path.exists() and ca.key_path.exists())
    sha1 = ca.sha256
    ca2 = LocalCA(tmp / "ca")
    ca2.load_or_create()
    check("重复调用不重签", ca2.sha256 == sha1)
    check("sha256 是 64 hex", len(sha1) == 64 and all(c in "0123456789abcdef" for c in sha1))

    leaf = ca.leaf("live-as-sky-merge.game.163.com")
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(leaf.cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = [str(n.value) for n in san]
    check("叶子 SAN 正确", "live-as-sky-merge.game.163.com" in names, str(names))
    check("叶子由本 CA 签发", cert.issuer == ca.cert.subject, str(cert.issuer))
    check("叶子不是 CA", not cert.extensions.get_extension_for_class(
        x509.BasicConstraints).value.ca)

    if os.name != "nt":
        skip("CurrentUser\\ROOT", "非 Windows")
        return
    # CA 是长期资产，装一次就一直留着（ca_installed 是持久状态）。
    # 默认只读查询，不往证书库里写写删删；要验证真实安装行为得显式
    #   set SKYHUIYU_CA_TEST=1
    # 而且是"装了就留着"，不做 装→删 的抖动。
    if os.environ.get("SKYHUIYU_CA_TEST") == "1":
        ca.install()
        check("装进 CurrentUser\\ROOT", ca.is_installed())
        check("重复安装返回 False（幂等）", ca.install() is False)
        check("装完就留着，不还原", ca.is_installed())
    else:
        check("只读查询不炸", isinstance(ca.is_installed(), bool))
        skip("CurrentUser\\ROOT 真实安装", "设 SKYHUIYU_CA_TEST=1 才写证书库")


# --------------------------------------------------------------------------- #
# 4) hosts
# --------------------------------------------------------------------------- #

def test_hosts(tmp: Path) -> None:
    print("\n[hosts]")
    p = tmp / "hosts"
    p.write_text("127.0.0.1 localhost\n::1 localhost\n", "utf-8")
    check("初始没开", not hostsfile.is_enabled(p))
    check("开启返回 True", hostsfile.enable(p, backup=False) is True)
    check("开启后 is_enabled", hostsfile.is_enabled(p))
    body = p.read_text("utf-8")
    check("只加 ma75 一行",
          body.count("127.0.0.1 ma75.update.netease.com") == 1, body)
    check("保留了原有内容", "127.0.0.1 localhost" in body)
    check("重复开启返回 False", hostsfile.enable(p, backup=False) is False)
    check("关闭返回 True", hostsfile.disable(p) is True)
    check("关闭后 is_enabled=False", not hostsfile.is_enabled(p))
    check("关闭后无残留标记", hostsfile.BEGIN not in p.read_text("utf-8"))
    check("cleanup 幂等", hostsfile.cleanup(p) == "无需清理", hostsfile.cleanup(p))

    # 历史脚本留下的裸行（没有标记）也要能被识别并清掉
    p2 = tmp / "hosts-legacy"
    p2.write_text("127.0.0.1 localhost\n127.0.0.1\tma75.update.netease.com\n", "utf-8")
    check("裸行也算已开启", hostsfile.is_enabled(p2))
    check("裸行被识别为 legacy", len(hostsfile._legacy_lines(hostsfile.read_text(p2))) == 1)
    check("disable 清掉裸行", hostsfile.disable(p2) is True)
    check("裸行清完 is_enabled=False", not hostsfile.is_enabled(p2))
    check("其它内容保留", "127.0.0.1 localhost" in p2.read_text("utf-8"))


# --------------------------------------------------------------------------- #
# 5) WinINet（真下发再还原）
# --------------------------------------------------------------------------- #

def test_wininet() -> None:
    print("\n[WinINet]")
    if os.name != "nt":
        skip("PAC 下发/还原", "非 Windows")
        return
    snap = query()
    check("能读到当前配置", "mode" in snap, str(snap))
    check("不动 WinHTTP（不做任何 winhttp 调用）", snap["winhttp"] == "untouched")
    # 改系统代理会短暂影响本机联网，默认不干。要验证真下发：
    #   set SKYHUIYU_WININET_TEST=1
    if os.environ.get("SKYHUIYU_WININET_TEST") != "1":
        skip("PAC 真下发再还原", "设 SKYHUIYU_WININET_TEST=1 才动系统代理")
        return
    fake = "http://127.0.0.1:18887/local-access/desktop.pac"
    try:
        applied = enable_pac(fake)
        check("下发后 mode=pac", applied["mode"] == "pac", str(applied))
        check("下发后 pac_url 一致", applied["pac_url"] == fake, applied["pac_url"])
    finally:
        back = restore(snap)
    check("还原后 mode 与原来一致", back["mode"] == snap["mode"],
          f"{back['mode']} != {snap['mode']}")
    check("还原后 pac_url 与原来一致", back["pac_url"] == snap["pac_url"],
          f"{back['pac_url']!r} != {snap['pac_url']!r}")


# --------------------------------------------------------------------------- #
# 6) 代理端到端
# --------------------------------------------------------------------------- #

class _Origin(BaseHTTPRequestHandler):
    payload = b"{}"
    status = 200

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._reply()

    def do_GET(self) -> None:  # noqa: N802
        self._reply()

    def _reply(self) -> None:
        body = type(self).payload
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # noqa: A003
        pass


def _origin(payload: dict, *, tls_ctx: ssl.SSLContext | None = None) -> ThreadingHTTPServer:
    handler = type("H", (_Origin,), {"payload": json.dumps(payload).encode()})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if tls_ctx is not None:
        srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _FakeResolver:
    def __init__(self, ip: str = "127.0.0.1") -> None:
        self.ip = ip

    def resolve(self, host: str) -> str:
        return self.ip


def _read_head(sock: socket.socket) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def _read_all(sock: socket.socket) -> bytes:
    out = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except (TimeoutError, ssl.SSLError):
            break
        if not chunk:
            break
        out += chunk
    return out


def test_proxy(tmp: Path) -> None:
    print("\n[proxy 端到端]")
    ca = LocalCA(tmp / "ca2")
    ca.load_or_create()
    captured: list[tuple] = []

    def sink(session, meta):
        captured.append((session, meta))

    proxy = CaptureProxy(ca, sink, bind="127.0.0.1", port=0,
                         resolver=_FakeResolver(), log=lambda m: None)
    port = proxy.start()
    try:
        # --- PAC 与代理同端口 ---
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(f"GET /local-access/desktop.pac HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
        raw = _read_head(s)
        s.close()
        check("PAC 由代理端口应答", b"200" in raw.split(b"\r\n")[0], raw[:60])
        check("PAC content-type 正确",
              b"application/x-ns-proxy-autoconfig" in raw.lower(), raw[:200])
        check("PAC 内容含 ma75", b"ma75.update.netease.com" in raw)

        # --- CA 下发 ---
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET /client-proxy-ca.cer HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        blob = _read_all(s)
        s.close()
        check("CA 由代理端口下发", b"application/x-x509-ca-cert" in blob.lower(), blob[:120])
        check("下发的是 DER", ca.der() in blob)

        # --- 明文 HTTP 抓包 ---
        host = "live-as-sky-merge.game.163.com"
        origin = _origin(LOGIN_BODY)
        oport = origin.server_address[1]
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            req = (
                f"POST http://{host}:{oport}/account/auth/login HTTP/1.1\r\n"
                f"Host: {host}:{oport}\r\nUser-Agent: {UA}\r\n"
                "x-sky-level-id: lvl-9\r\nx-sky-build-access-key: KEY-xyz\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            s.sendall(req.encode())
            body = _read_all(s)
            s.close()
            check("明文代理转发成功", b"200" in body.split(b"\r\n")[0], body[:80])
            check("明文抓包命中 authinfo", len(captured) == 1, f"{len(captured)}")
            if captured:
                sess, meta = captured[-1]
                check("抓到 user_id", sess.user_id == "1234567890", sess.user_id)
                check("meta 记了路径", meta["path"].startswith("/account/auth/login"), str(meta))
        finally:
            origin.shutdown()

        # --- CONNECT MITM 抓包（真 TLS，客户端只信我们的 CA） ---
        captured.clear()
        proxy._last_token = ""  # 模拟一次新会话（同一个 token 不重复入库是有意的）
        leaf = ca.leaf(host)
        crt = tmp / "origin.crt"
        key = tmp / "origin.key"
        crt.write_bytes(leaf.cert_pem)
        key.write_bytes(leaf.key_pem)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(crt), str(key))
        origin2 = _origin(LOGIN_BODY, tls_ctx=sctx)
        oport2 = origin2.server_address[1]
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            s.sendall(f"CONNECT {host}:{oport2} HTTP/1.1\r\nHost: {host}:{oport2}\r\n\r\n".encode())
            head = _read_head(s)
            check("CONNECT 200", b"200" in head.split(b"\r\n")[0], head[:60])

            cctx = ssl.create_default_context()
            cctx.load_verify_locations(cadata=ca.cert_path.read_bytes().decode())
            tls = cctx.wrap_socket(s, server_hostname=host)
            check("叶子证书通过客户端校验（含主机名）", tls.version() is not None, "")
            tls.sendall(
                f"POST /account/auth/login HTTP/1.1\r\nHost: {host}\r\n"
                f"User-Agent: {UA}\r\nx-sky-level-id: lvl-9\r\n"
                "x-sky-build-access-key: KEY-xyz\r\nContent-Length: 0\r\n"
                "Connection: close\r\n\r\n".encode())
            got = _read_all(tls)
            tls.close()
            check("MITM 解密后回包完整", b"200" in got.split(b"\r\n")[0], got[:80])
            check("MITM 抓包命中 authinfo", len(captured) == 1, f"{len(captured)}")
            if captured:
                sess, _meta = captured[-1]
                check("MITM 抓到 session",
                      sess.session_token == "0123456789abcdef0123456789abcdef",
                      sess.session_token)
        finally:
            origin2.shutdown()

        # --- 非账号域不抓（避免把遥测里的 JSON 当登录态） ---
        captured.clear()
        check("非账号域不算抓取目标", not proxy.is_account_host("update.example.com"))
        check("账号域算抓取目标", proxy.is_account_host(host))
        check("MITM 名单含 ma75 与账号域",
              proxy.should_mitm("ma75.update.netease.com")
              and proxy.should_mitm("live-as-sky-merge.game.163.com"))
        check("MITM 名单含登录页的 webapp 域",
              proxy.should_mitm("loadingbaycn.webapp.163.com"), "")
        check("MITM 名单不含无关域名", not proxy.should_mitm("www.example.com"))

        # --- ACCOUNT_DOMAIN 改写路由：游戏请求 http://127.0.0.1:<proxy>/account/... ---
        captured.clear()
        proxy._last_token = ""
        origin3 = _origin(LOGIN_BODY, tls_ctx=sctx)
        oport3 = origin3.server_address[1]
        proxy.account_port = oport3  # 真实环境是 443，这里指到本地 TLS origin
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            s.sendall((
                f"POST http://127.0.0.1:{port}/account/auth/login HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\nUser-Agent: {UA}\r\n"
                "x-sky-level-id: lvl-9\r\nx-sky-build-access-key: KEY-xyz\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n"
            ).encode())
            body3 = _read_all(s)
            s.close()
            check("改写的账号请求被转到真实域名", b"200" in body3.split(b"\r\n")[0], body3[:80])
            check("改写请求也抓到了 authinfo", len(captured) == 1, f"{len(captured)}")
            if captured:
                sess, meta = captured[-1]
                check("改写路由抓到 session",
                      sess.session_token == "0123456789abcdef0123456789abcdef",
                      sess.session_token)
                check("meta 里的 host 是真实域名", meta["host"] == host, str(meta))
        finally:
            origin3.shutdown()
            proxy.account_port = 443

        check("is_self_target 认本机端口",
              proxy.is_self_target(f"127.0.0.1:{port}") and not proxy.is_self_target("127.0.0.1:9"))

        # --- 请求头抓会话（实测唯一可靠的那条路） ---
        captured.clear()
        proxy._last_token = ""
        origin4 = _origin(LOGIN_BODY, tls_ctx=sctx)
        oport4 = origin4.server_address[1]
        proxy.account_port = oport4
        try:
            hdrs = (
                "X-Session-ID: 035e02d8-04d3-05a4-4206-c30700080009\r\n"
                f"user-id: {GAME_UID}\r\n"
                f"session: {GAME_TOKEN}\r\n"
                f"x-user-id: {GAME_UID}\r\n"
                f"x-session-token: {GAME_TOKEN}\r\n"
                "x-sky-level-id: 3526133726\r\n"
                f"User-Agent: {GAME_UA}\r\n"
            )
            for _ in range(2):  # 连打两次，第二次不该重复入库
                s = socket.create_connection(("127.0.0.1", port), timeout=10)
                s.sendall((
                    f"POST http://127.0.0.1:{port}/account/get_rank HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{port}\r\n{hdrs}"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n"
                ).encode())
                _read_all(s)
                s.close()
            check("请求头里的会话被抓到", len(captured) == 1, f"{len(captured)}")
            if captured:
                sess, meta = captured[-1]
                check("抓到 user_id", sess.user_id == GAME_UID, sess.user_id)
                check("抓到 session token", sess.session_token == GAME_TOKEN, sess.session_token)
                check("抓到 X-Session-ID（重放必需）",
                      sess.session_id == "035e02d8-04d3-05a4-4206-c30700080009", sess.session_id)
                check("抓到 level_id", sess.level_id == "3526133726", sess.level_id)
                check("来源标记为 headers", meta["authinfo_path"] == "headers", str(meta))
            check("同 token 不重复入库", len(captured) == 1, f"{len(captured)}")
        finally:
            origin4.shutdown()
            proxy.account_port = 443
    finally:
        proxy.stop()


# --------------------------------------------------------------------------- #
# 7) WebSocket 升级（101 必须原样转发并变成隧道）
# --------------------------------------------------------------------------- #

def test_ws_upgrade(tmp: Path) -> None:
    print("\n[WebSocket 101]")
    ca = LocalCA(tmp / "ca-ws")
    ca.load_or_create()
    host = "loadingbaycn-websocket.webapp.163.com"

    # 极简 TLS 源站：读头 → 回 101 → 之后原样回显
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    leaf = ca.leaf(host)
    crt = tmp / "ws.crt"
    key = tmp / "ws.key"
    crt.write_bytes(leaf.cert_pem)
    key.write_bytes(leaf.key_pem)
    srv_ctx.load_cert_chain(str(crt), str(key))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    oport = listener.getsockname()[1]

    def serve() -> None:
        conn, _ = listener.accept()
        try:
            tls = srv_ctx.wrap_socket(conn, server_side=True)
            _read_head(tls)
            tls.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                        b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            while True:
                data = tls.recv(4096)
                if not data:
                    break
                tls.sendall(b"E:" + data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()

    proxy = CaptureProxy(ca, lambda s, m: None, bind="127.0.0.1", port=0,
                         resolver=_FakeResolver(), log=lambda m: None)
    port = proxy.start()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(f"CONNECT {host}:{oport} HTTP/1.1\r\nHost: {host}:{oport}\r\n\r\n".encode())
        _read_head(s)
        cctx = ssl.create_default_context()
        cctx.load_verify_locations(cadata=ca.cert_path.read_bytes().decode())
        tls = cctx.wrap_socket(s, server_hostname=host)
        tls.sendall((f"GET /ws?token=abc HTTP/1.1\r\nHost: {host}\r\n"
                     "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").encode())
        head = _read_head(tls)
        check("101 原样转发给客户端", b"101" in head.split(b"\r\n")[0], head[:80])
        check("Upgrade 头没被改写", b"Upgrade: websocket" in head, head[:120])
        check("没有塞 Content-Length: 0", b"Content-Length: 0" not in head, head[:160])
        tls.sendall(b"ping")
        echoed = tls.recv(64)
        check("升级后是双向隧道", echoed == b"E:ping", repr(echoed))
        tls.close()
    finally:
        proxy.stop()
        listener.close()


# --------------------------------------------------------------------------- #
# 8) 游戏配置改写 + 票据让开
# --------------------------------------------------------------------------- #

def test_rewrite(tmp: Path) -> None:
    print("\n[配置改写 / 票据]")
    from skyhuiyu.capture import rewrite as rw
    from skyhuiyu.capture.httpio import Response
    from skyhuiyu.capture.ca import CaptureError

    official = "https://live-as-sky-merge.game.163.com"
    local = "http://127.0.0.1:8887"
    body = json.dumps({"ACCOUNT_DOMAIN": official, "ServerId": "8000"}).encode()

    rr = rw.rewrite_config_body(body, local, path="/config/0.16.8-421730-PC-obt.json")
    check("配置被改写", rr.changed)
    check("记下原值", rr.origin == official, rr.origin)
    check("新 body 指向本机",
          json.loads(rr.body.decode())["ACCOUNT_DOMAIN"] == local, rr.body.decode())
    check("其它字段原样", json.loads(rr.body.decode())["ServerId"] == "8000")
    check("幂等（已是本机就不再改）",
          rw.rewrite_config_body(rr.body, local).changed is False)
    check("没有 ACCOUNT_DOMAIN 的配置不动",
          rw.rewrite_config_body(b'{"a":1}', local).changed is False)
    check("不是 JSON 也不炸",
          rw.rewrite_config_body(b"<html>no", local).changed is False)
    check("配置路径判定", rw.is_config_path("/config/0.16.8-421730-PC-obt.json"))
    check("通知接口不算配置", not rw.is_config_path("/game_notice/announcement_pc.json"))

    # 就地改写一个 Response：头要换掉旧长度/编码，并带上那两个标注头
    resp = Response("HTTP/1.1", 200, "OK",
                    [("Content-Type", "application/json"),
                     ("Content-Length", str(len(body))),
                     ("Content-Encoding", "gzip"),
                     ("ETag", '"abc"')],
                    body)
    rr2 = rw.apply(resp, local, path="/config/x-PC-obt.json")
    check("Response 被就地改写", rr2.changed and json.loads(resp.body.decode())["ACCOUNT_DOMAIN"] == local)
    hdrs = {k.lower(): v for k, v in resp.headers}
    check("打了 x-sp-config-rewritten", hdrs.get(rw.HDR_REWRITTEN) == "1", str(resp.headers))
    check("记了 x-sp-account-origin", hdrs.get(rw.HDR_ORIGIN) == official, str(resp.headers))
    check("旧的 Content-Length 去掉了", "content-length" not in hdrs, str(resp.headers))
    check("旧的 Content-Encoding 去掉了（改了体就不再是 gzip）",
          "content-encoding" not in hdrs, str(resp.headers))
    check("旧 ETag 去掉了", "etag" not in hdrs, str(resp.headers))

    # 改写后不是合法 JSON → 宁可不动（配置坏掉游戏直接起不来）
    bad = b'{"ACCOUNT_DOMAIN": "' + official.encode() + b'", oops}'
    try:
        rw.rewrite_config_body(bad, local)
        ok = True
    except CaptureError as exc:
        ok = exc.code == "configuration_json_invalid"
    check("坏 JSON 抛 configuration_json_invalid 而不是写坏", ok)

    # ---- 票据 ----
    root = tmp / "game"
    ticket = root / "data" / "ThatGameCompany" / "com.netease.sky"
    ticket.mkdir(parents=True)
    (ticket / "liveAccountAuthInfo.bin").write_bytes(b"ticket-bytes")
    gate = rw.TicketGate(root)
    check("找到票据", len(gate.find()) == 1, str(gate.find()))
    moved = gate.park()
    check("票据被让开", len(moved) == 1 and not gate.find())
    check("让开的是改名不是删除", moved[0].exists())
    check("票据能还回去", len(gate.restore()) == 1 and len(gate.find()) == 1)

    gate.park()
    (ticket / "liveAccountAuthInfo.bin").write_bytes(b"new-ticket")
    gate.restore()
    check("有新票时不覆盖", (ticket / "liveAccountAuthInfo.bin").read_bytes() == b"new-ticket")
    check("旧票已丢弃", not gate.parked())

    # ---- 收尾清掉磁盘上残留的本机地址（上一版留下的） ----
    cfg = root / "data" / "config.json"
    cfg.write_text(json.dumps({"ACCOUNT_DOMAIN": local}), "utf-8")
    check("磁盘残留本机地址被还原", rw.reset_disk_account_domain(root) is True)
    check("还原成官方域名",
          json.loads(cfg.read_text("utf-8"))["ACCOUNT_DOMAIN"] == official,
          cfg.read_text("utf-8"))
    check("已经是官方值时不动", rw.reset_disk_account_domain(root) is False)


def _expect_error(fn, code: str) -> bool:  # noqa: ANN001
    from skyhuiyu.capture.ca import CaptureError

    try:
        fn()
    except CaptureError as exc:
        return exc.code == code
    except Exception:  # noqa: BLE001
        return False
    return False


# --------------------------------------------------------------------------- #
# 8) CEF 缓存清理（用假目录，不动真缓存）
# --------------------------------------------------------------------------- #

def test_cef(tmp: Path) -> None:
    print("\n[CEF 缓存]")
    root = tmp / "cef" / "User Data"
    (root / "Default" / "Cache").mkdir(parents=True)
    (root / "Default" / "Cache" / "x").write_bytes(b"1")
    (root / "Default" / "Network").mkdir(parents=True)
    (root / "Default" / "Network" / "TransportSecurity").write_bytes(b"pinning")
    (root / "Default" / "Cookies").write_bytes(b"keep-me")

    out = cef.purge([root])
    check("Cache 目录被删", not (root / "Default" / "Cache").exists())
    check("TransportSecurity 被删",
          not (root / "Default" / "Network" / "TransportSecurity").exists())
    check("Cookies 保留（不把登录态删掉）", (root / "Default" / "Cookies").exists())
    check("summary 有话说", "已清" in cef.summary(out), cef.summary(out))


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="skyhuiyu-cap-"))
    test_pac()
    test_authinfo()
    test_ca(tmp)
    test_hosts(tmp)
    test_wininet()
    test_proxy(tmp)
    test_ws_upgrade(tmp)
    test_rewrite(tmp)
    test_cef(tmp)
    print(f"\n{OK}/{OK + BAD} 通过" + (f"，{SKIP} 跳过" if SKIP else ""))
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
