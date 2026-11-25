"""极简 HTTP/1.1 读写 —— 代理和 443 监听共用。

只做我们要做的事：把一条请求原样读进来、把一条响应读完整、再拼回去。
不引 http.client（它会重编码 chunked、改头、加默认头，抓包时这些改动会让
"回包和官方一模一样"这件事失真），不引 h11（多一层状态机没必要）。

三个必须处理的形状：
  · Content-Length 定长体
  · Transfer-Encoding: chunked
  · 两者都没有 —— 读到对端关闭为止（HTTP/1.0 与部分 agent 就这么干）
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field


class HttpError(RuntimeError):
    pass


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str, default: str = "") -> str:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return default

    def header_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.headers}

    def path(self) -> str:
        """从 target 里取 path（可能是绝对 URI，也可能是 origin-form）。"""
        t = self.target
        if t.startswith("http://") or t.startswith("https://"):
            rest = t.split("://", 1)[1]
            slash = rest.find("/")
            return rest[slash:] if slash >= 0 else "/"
        return t

    def host(self) -> str:
        t = self.target
        if t.startswith("http://") or t.startswith("https://"):
            rest = t.split("://", 1)[1]
            slash = rest.find("/")
            return rest[:slash] if slash >= 0 else rest
        return self.header("Host")

    def body_text(self, limit: int = 65536) -> str:
        return self.body[:limit].decode("utf-8", "replace")


@dataclass
class Response:
    version: str
    status: int
    reason: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    # 原始响应头字节。101 Switching Protocols 必须原样转发（不能改写成定长），
    # 否则 WebSocket 升级会被我们自己的序列化破坏。
    raw_head: bytes = b""

    def header(self, name: str, default: str = "") -> str:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return default

    def header_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.headers}


class Reader:
    """带缓冲的读端。socketserver 的 request 是裸 socket，不能用 makefile（会丢已缓冲数据）。"""

    MAX_HEAD = 256 * 1024

    def __init__(self, sock: socket.socket, initial: bytes = b"") -> None:
        self.sock = sock
        self.buf = bytearray(initial)

    def _fill(self) -> bool:
        chunk = self.sock.recv(65536)
        if not chunk:
            return False
        self.buf += chunk
        return True

    def read_until(self, delim: bytes, limit: int | None = None) -> bytes:
        limit = limit or self.MAX_HEAD
        while True:
            idx = self.buf.find(delim)
            if idx >= 0:
                end = idx + len(delim)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            if len(self.buf) > limit:
                raise HttpError(f"头超过 {limit} 字节还没结束")
            if not self._fill():
                if self.buf:
                    out = bytes(self.buf)
                    self.buf.clear()
                    return out
                return b""

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._fill():
                out = bytes(self.buf)
                self.buf.clear()
                return out
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_all(self) -> bytes:
        while self._fill():
            pass
        out = bytes(self.buf)
        self.buf.clear()
        return out


def _parse_head(head: bytes) -> tuple[str, list[tuple[str, str]]]:
    """返回 (起始行, 头列表)。"""
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    start = lines[0]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return start, headers


def _chunked_body(rdr: Reader, limit: int) -> tuple[bytes, bool]:
    out = bytearray()
    truncated = False
    while True:
        line = rdr.read_until(b"\r\n", 8192)
        if not line:
            break
        try:
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError as exc:
            raise HttpError(f"chunk 长度非法: {line!r}") from exc
        if size == 0:
            # trailer
            while True:
                trailer = rdr.read_until(b"\r\n", 8192)
                if not trailer or trailer == b"\r\n":
                    break
            break
        data = rdr.read_exact(size + 2)
        if len(data) < size + 2:
            out += data[:size]
            truncated = True
            break
        if len(out) < limit:
            out += data[:size]
        else:
            truncated = True
        rdr.read_exact(0)
    return bytes(out), truncated


def read_request(rdr: Reader, max_body: int = 4 * 1024 * 1024) -> Request | None:
    head = rdr.read_until(b"\r\n\r\n")
    if not head:
        return None
    start, headers = _parse_head(head)
    parts = start.split(" ")
    if len(parts) < 3:
        raise HttpError(f"请求行非法: {start!r}")
    method, target, version = parts[0], parts[1], parts[2]
    req = Request(method, target, version, headers)

    te = req.header("Transfer-Encoding").lower()
    cl = req.header("Content-Length")
    if "chunked" in te:
        req.body, _ = _chunked_body(rdr, max_body)
    elif cl.isdigit():
        n = int(cl)
        if n > max_body:
            raise HttpError(f"请求体 {n} 字节超过上限 {max_body}")
        req.body = rdr.read_exact(n)
    return req


def read_response(rdr: Reader, *, method: str = "GET", max_body: int = 8 * 1024 * 1024) -> Response:
    head = rdr.read_until(b"\r\n\r\n")
    if not head:
        raise HttpError("对端没有返回响应头就关了连接")
    start, headers = _parse_head(head)
    parts = start.split(" ", 2)
    if len(parts) < 2:
        raise HttpError(f"状态行非法: {start!r}")
    version = parts[0]
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise HttpError(f"状态码非法: {start!r}") from exc
    reason = parts[2] if len(parts) > 2 else ""
    resp = Response(version, status, reason, headers, raw_head=head)

    if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
        return resp

    te = resp.header("Transfer-Encoding").lower()
    cl = resp.header("Content-Length")
    if "chunked" in te:
        resp.body, _ = _chunked_body(rdr, max_body)
    elif cl.isdigit():
        n = int(cl)
        if n > max_body:
            raise HttpError(f"响应体 {n} 字节超过上限 {max_body}")
        resp.body = rdr.read_exact(n)
    else:
        resp.body = rdr.read_all()
    return resp


def serialize_request(req: Request, *, origin_form: bool = True,
                      drop: tuple[str, ...] = ()) -> bytes:
    """拼回请求字节。absolute-form 的 target 默认改写成 origin-form。"""
    target = req.path() if origin_form else req.target
    lines = [f"{req.method} {target} {req.version}"]
    drop_low = {d.lower() for d in drop}
    for k, v in req.headers:
        if k.lower() in drop_low:
            continue
        lines.append(f"{k}: {v}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + req.body


def serialize_response(resp: Response, *, close: bool = True) -> bytes:
    """拼回响应。统一改成定长 + Connection: close，去掉 chunked 与压缩描述。"""
    skip = {"transfer-encoding", "content-length", "connection", "keep-alive"}
    lines = [f"HTTP/1.1 {resp.status} {resp.reason}".rstrip()]
    for k, v in resp.headers:
        if k.lower() in skip:
            continue
        lines.append(f"{k}: {v}")
    lines.append(f"Content-Length: {len(resp.body)}")
    if close:
        lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + resp.body


def connect_tcp(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def wrap_client_tls(sock: socket.socket, ctx: ssl.SSLContext,
                    server_hostname: str) -> ssl.SSLSocket:
    return ctx.wrap_socket(sock, server_hostname=server_hostname)
