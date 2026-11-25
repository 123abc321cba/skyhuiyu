"""登录响应解析 —— 从登录回包 / 请求头里取出可复用的账号会话。

入口规则：在 login 响应 JSON 里按**精确键名** `authinfo` 命中，不做全字段扫描、
不做子串搜索。这个键一出现，就说明这条响应是登录响应，再从同一份 JSON 里取
`session` 等字段。

统一的失败码（对外用于判定与日志）：

    http_status / empty_response / json_invalid_or_duplicate
    authinfo / authinfo_invalid / auth_user_invalid
    error_code / errno / result / success

字段名也全部来自同一份常量区：

    session / session2 / session3 / session_source(=client_proxy)
    token / token_sha256（哈希，不能当 token）
    build_access_key / game_level_id / user_id
    game_platform / game_channel / game_version / build / sdk_version
    game_device_model / game_system_version / game_language / game_device_name
    x-sky-level-id / x-sky-build-access-key / User-Agent

User-Agent 的两条正则也是原样搬过来的（第 121、124 行），用来从 UA 里
推 `game_device_model` / `game_system_version` / `game_language` / `platform`。
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# --- 两条 UA 正则：带 `/` 与不带 `/` 两种写法都要认 ---
UA_APP_RE = re.compile(r"^Sky-Live-[A-Za-z0-9.-]+/([0-9]+(?:\.[0-9]+){0,3})\.([0-9]+) \(")
# 带 `/` 的是客户端历史格式；不带 `/` 的是 netease_api 里的默认 UA
# （`Sky-Live-0.12.0.289624 (Android 13; Pixel 7; zh_CN; 1080x2400)`）。
# 两种都要认，否则从历史会话里读出来的版本号永远是空。
UA_APP_ALT_RE = re.compile(r"^Sky-Live-([0-9]+(?:\.[0-9]+){0,3})\.([0-9]+) \(")
UA_DEVICE_RE = re.compile(
    r"\(([A-Za-z0-9][A-Za-z0-9,._ -]{0,79}); (iOS|Android) ([0-9]+(?:\.[0-9]+){0,2}); "
    r"([A-Za-z]{2,8}(?:[-_][A-Za-z0-9]{2,8}){0,2})\)$"
)
UA_PLATFORM_RE = re.compile(r"(?:\(|;[ ]*)(iOS|Android|Windows(?: NT)?|Win32|Win64)(?=[ ;)]|$)")

# 32 位小写十六进制 = 会话 token 的标准形态。
SESSION_HEX_RE = re.compile(r"^[a-f0-9]{32}$")

AUTHINFO_KEY = "authinfo"

# 按优先级排的 session 取值键。`token_sha256` 是哈希，永远不取。
SESSION_KEYS: tuple[str, ...] = (
    "session", "session2", "session3",
    "session_token", "sessionToken", "ss", "skey",
)
# 明确的"这不是 token"的键
SESSION_DENY = ("token_sha256", "hashes", "sha256")

USER_KEYS: tuple[str, ...] = (
    "user_id", "userid", "uid", "player_id", "game_user_id",
    # 登录响应里就叫 `user`（实测：authinfo.user = 账号 uuid）。
    # `_first_str` 只收字符串/整数，所以别处的 `user` 对象不会误命中。
    "user",
)
LEVEL_KEYS: tuple[str, ...] = ("game_level_id", "level_id", "x-sky-level-id")
BUILD_KEY_KEYS: tuple[str, ...] = ("build_access_key", "x-sky-build-access-key")
GAME_VERSION_KEYS: tuple[str, ...] = ("game_version",)
BUILD_KEYS: tuple[str, ...] = ("build",)
CHANNEL_KEYS: tuple[str, ...] = ("game_channel", "channel")
PLATFORM_KEYS: tuple[str, ...] = ("game_platform", "platform")
DEVICE_KEYS: tuple[str, ...] = ("game_device_model", "device_model")
SYSVER_KEYS: tuple[str, ...] = ("game_system_version", "system_version")
LANG_KEYS: tuple[str, ...] = ("game_language", "language")

# 统一失败码（见模块 docstring）。外部拿它做判定与日志。
ERR_EMPTY = "empty_response"
ERR_JSON = "json_invalid_or_duplicate"
ERR_AUTHINFO = "authinfo_invalid"
ERR_AUTH_USER = "auth_user_invalid"
ERR_STATUS = "http_status"

MIN_TOKEN_LEN = 16


class DuplicateKey(ValueError):
    """JSON 里有重复键 —— 按 `json_invalid_or_duplicate` 处理。"""


@dataclass
class CapturedSession:
    """一份可用的登录态。字段与 `store.sessions` 表对齐。"""

    user_id: str
    session_token: str
    level_id: str = ""
    build_access_key: str = ""
    user_agent: str = ""
    game_version: str = ""
    build: str = ""
    channel: str = ""
    platform: str = ""
    device_model: str = ""
    system_version: str = ""
    language: str = ""
    session_source: str = "client_proxy"
    # 游戏发的 `X-Session-ID` 是独立的一个 uuid，和 session token 不是一回事。
    # 重放实测：少了它或拼错它，官方回 401/423；带对了就 200。
    session_id: str = ""
    # 登录响应里和 session 并列的还有 session2 / session3，以及 authinfo 里的
    # 设备身份（user / device / key）。这几个键全部留档。
    session2: str = ""
    session3: str = ""
    device: str = ""
    device_key: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def as_extra(self) -> dict[str, Any]:
        return {
            "session_source": self.session_source,
            "session_id": self.session_id,
            "session2": self.session2,
            "session3": self.session3,
            "device": self.device,
            "device_key": self.device_key,
            "game_platform": self.platform,
            "game_channel": self.channel,
            "game_device_model": self.device_model,
            "game_system_version": self.system_version,
            "game_language": self.language,
        }


def from_headers(headers: dict[str, str]) -> ParseResult:
    """从**游戏自己的请求头**里取会话 —— 这是实测唯一稳定可靠的入口。

    游戏每个账号请求都带这套头（抓包实测）：

        X-Session-ID     035e02d8-04d3-05a4-4206-c30700080009   ← 独立 uuid
        user-id / x-user-id        00000000-...
        session / x-session-token  33333333333333333333333333333333   ← 32 hex
        x-sky-level-id             3526133726

    比解析响应体强得多：响应体大多是 `Content-Encoding: session-valid` 的加密载荷，
    啃不动；头是明文的，而且拿到就能重放（实测原样重放 → HTTP 200）。
    """
    h = {k.lower(): (v or "").strip() for k, v in headers.items()}
    token = h.get("x-session-token") or h.get("session") or ""
    user_id = h.get("x-user-id") or h.get("user-id") or ""
    if not token or not user_id:
        return ParseResult(error=ERR_AUTHINFO, detail="请求头里没有 x-session-token / x-user-id")
    if len(token) < MIN_TOKEN_LEN:
        return ParseResult(error=ERR_AUTHINFO, detail=f"session 太短: {token!r}")
    ua = h.get("user-agent", "")
    bits = parse_ua(ua)
    return ParseResult(session=CapturedSession(
        user_id=user_id,
        session_token=token,
        session_id=h.get("x-session-id", ""),
        level_id=h.get("x-sky-level-id", "") or h.get("x-sky-level", ""),
        build_access_key=h.get("x-sky-build-access-key", ""),
        user_agent=ua,
        game_version=bits.get("game_version", ""),
        build=bits.get("build", ""),
        platform=bits.get("platform", ""),
        device_model=bits.get("device_model", ""),
        system_version=bits.get("system_version", ""),
        language=bits.get("language", ""),
        raw={"headers": h},
    ), authinfo_path="headers")


@dataclass
class ParseResult:
    session: CapturedSession | None = None
    error: str = ""
    detail: str = ""
    authinfo_path: str = ""

    @property
    def ok(self) -> bool:
        return self.session is not None


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """检测重复键，命中即 `json_invalid_or_duplicate`。"""
    seen: set[str] = set()
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in seen:
            raise DuplicateKey(k)
        seen.add(k)
        out[k] = v
    return out


def loads_strict(text: str) -> Any:
    """严格 JSON 解析：重复键判错，NaN/Infinity 判错（标准 JSON 没有这两个）。"""
    return json.loads(
        text,
        object_pairs_hook=_pairs_hook,
        parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"non-standard constant {c}")),
    )


def find_authinfo(node: Any, path: str = "") -> tuple[Any, str] | None:
    """层层下钻找 `authinfo` 键（精确键名，不做子串匹配）。

    返回 (值, 路径)。只认精确键名，所以 `authinfo_invalid` 这种键不会被误命中。
    """
    if isinstance(node, dict):
        for k, v in node.items():
            here = f"{path}.{k}" if path else k
            if k == AUTHINFO_KEY:
                return v, here
            hit = find_authinfo(v, here)
            if hit is not None:
                return hit
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hit = find_authinfo(v, f"{path}[{i}]")
            if hit is not None:
                return hit
    return None


def _coerce_object(value: Any) -> dict[str, Any] | None:
    """authinfo 可能是对象，也可能是「装着 JSON 的字符串」或 base64。

    网易的登录回包两种形态都出现过，资源层也可能按 base64 传 JSON。
    三种都试，是为了对齐真实回包，不是兜底。
    """
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text[:1] in "{[":
        try:
            parsed = loads_strict(text)
        except Exception:  # noqa: BLE001
            return None
        return parsed if isinstance(parsed, dict) else None
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(text + "=" * (-len(text) % 4))
            parsed = loads_strict(raw.decode("utf-8"))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _walk_values(node: Any, keys: Iterable[str]) -> list[Any]:
    """按传入的键名顺序收集值：先浅后深，同名键取最外层那个。"""
    keyset = tuple(keys)
    out: list[Any] = []
    if isinstance(node, dict):
        for k in keyset:
            v = node.get(k)
            if isinstance(v, (str, int)) and str(v).strip():
                out.append(v)
        for v in node.values():
            if isinstance(v, (dict, list)):
                out.extend(_walk_values(v, keyset))
    elif isinstance(node, list):
        for v in node:
            out.extend(_walk_values(v, keyset))
    return out


def _first_str(node: Any, keys: Iterable[str]) -> str:
    for v in _walk_values(node, keys):
        s = str(v).strip()
        if s:
            return s
    return ""


def parse_ua(ua: str) -> dict[str, str]:
    """从 User-Agent 里推平台/机型/系统/语言。"""
    out: dict[str, str] = {}
    if not ua:
        return out
    m = UA_APP_RE.match(ua) or UA_APP_ALT_RE.match(ua)
    if m:
        out["game_version"] = m.group(1)
        out["build"] = m.group(2)
    m = UA_DEVICE_RE.search(ua)
    if m:
        out["device_model"] = m.group(1).strip()
        out["platform"] = m.group(2).lower()
        out["system_version"] = m.group(3)
        out["language"] = m.group(4)
    if not out.get("platform"):
        m = UA_PLATFORM_RE.search(ua)
        if m:
            name = m.group(1).lower()
            out["platform"] = "android" if name.startswith("android") else (
                "ios" if name == "ios" else "windows"
            )
    return out


def _pick_session(scopes: list[Any]) -> str:
    """挑 session token。作用域按由外到内排好序。

    实测的登录响应是**平级**的：

        {"authinfo": {"user": .., "device": .., "key": ..},
         "session": "44444444444444444444444444444444",
         "session2": "55555555555555555555555555555555",
         "session3": "66666666666666666666666666666666", ...}

    `authinfo` 只是"这是登录响应"的标记，session 和它平级 —— 所以根对象必须排在
    最前面找，再从同一份 JSON 里取 session。
    """
    candidates: list[str] = []
    for scope in scopes:
        if not isinstance(scope, dict):
            continue
        for key in SESSION_KEYS:
            v = scope.get(key)
            if isinstance(v, str):
                s = v.strip()
                if s and key not in SESSION_DENY and len(s) >= MIN_TOKEN_LEN:
                    candidates.append(s)
    if not candidates:
        return ""
    for c in candidates:
        if SESSION_HEX_RE.match(c):
            return c
    return max(candidates, key=len)


def extract(payload: Any, headers: dict[str, str] | None = None, *,
            http_status: int = 200) -> ParseResult:
    """从一条响应里解析登录态。

    `headers` 用抓到的**请求头**（UA / x-sky-level-id / x-sky-build-access-key
    是随请求发的，不在响应体里）。
    """
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    ua = hdrs.get("user-agent", "")
    ua_bits = parse_ua(ua)

    if payload is None:
        return ParseResult(error=ERR_EMPTY, detail="响应体为空或不是 JSON")

    hit = find_authinfo(payload)
    if hit is None:
        return ParseResult(error=ERR_AUTHINFO, detail="响应里没有 authinfo 键")

    value, path = hit
    obj = _coerce_object(value)
    if obj is None:
        return ParseResult(error=ERR_AUTHINFO, detail=f"{path} 不是对象，也不是 JSON/base64",
                           authinfo_path=path)

    root = payload if isinstance(payload, dict) else {}
    token = _pick_session([root, obj, payload])
    if not token:
        return ParseResult(error=ERR_AUTHINFO, detail=f"{path} 里找不到 session",
                           authinfo_path=path)

    # 用户标识在 authinfo.user 里（实测就是账号 uuid）
    user_id = _first_str(obj, USER_KEYS)
    if not user_id:
        for seg in ("user", "auth", "login", "account"):
            sub = obj.get(seg)
            if isinstance(sub, dict):
                user_id = _first_str(sub, USER_KEYS + ("id", "account", "account_id"))
                if user_id:
                    break
    if not user_id:
        user_id = _first_str(root, USER_KEYS)
    if not user_id:
        return ParseResult(error=ERR_AUTH_USER, detail=f"{path} 里找不到用户标识",
                           authinfo_path=path)

    def pick(keys: tuple[str, ...], fallback: str = "") -> str:
        return _first_str(obj, keys) or _first_str(root, keys) or fallback

    session_obj = CapturedSession(
        user_id=user_id,
        session_token=token,
        level_id=hdrs.get("x-sky-level-id", "") or pick(LEVEL_KEYS),
        build_access_key=hdrs.get("x-sky-build-access-key", "") or pick(BUILD_KEY_KEYS),
        user_agent=ua,
        game_version=pick(GAME_VERSION_KEYS, ua_bits.get("game_version", "")),
        build=pick(BUILD_KEYS, ua_bits.get("build", "")),
        channel=pick(CHANNEL_KEYS),
        platform=pick(PLATFORM_KEYS, ua_bits.get("platform", "")),
        device_model=pick(DEVICE_KEYS, ua_bits.get("device_model", "")),
        system_version=pick(SYSVER_KEYS, ua_bits.get("system_version", "")),
        language=pick(LANG_KEYS, ua_bits.get("language", "")),
        session_id=hdrs.get("x-session-id", ""),
        session2=_first_str(root, ("session2",)),
        session3=_first_str(root, ("session3",)),
        device=_first_str(obj, ("device",)),
        device_key=_first_str(obj, ("key",)),
        raw={"authinfo": obj, "root": root},
    )
    return ParseResult(session=session_obj, authinfo_path=path)


def parse_body(body: bytes, headers: dict[str, str] | None = None, *,
               http_status: int = 200, encoding: str = "") -> ParseResult:
    """字节级入口：先解压（若有 content-encoding），再按 JSON 解析。"""
    if not body:
        return ParseResult(error=ERR_EMPTY, detail="响应体为空")
    data = body
    enc = (encoding or "").lower().strip()
    # 有的接口不写 Content-Encoding 却照样发 gzip（实测 `/account/get_rank` 这类小响应）。
    # 按魔数认，比信头靠谱。
    if not enc and body[:2] == b"\x1f\x8b":
        enc = "gzip"
    elif not enc and body[:1] == b"\x1f" and body[1:2] == b"\x8b":
        enc = "gzip"
    if enc in ("gzip", "x-gzip"):
        import gzip

        try:
            data = gzip.decompress(body)
        except OSError as exc:
            return ParseResult(error=ERR_JSON, detail=f"gzip 解压失败: {exc}")
    elif enc == "deflate":
        import zlib

        try:
            data = zlib.decompress(body)
        except zlib.error:
            try:
                data = zlib.decompress(body, -zlib.MAX_WBITS)
            except zlib.error as exc:
                return ParseResult(error=ERR_JSON, detail=f"deflate 解压失败: {exc}")
    elif enc == "br":
        try:
            import brotli  # type: ignore[import-not-found]
        except ImportError:
            return ParseResult(error=ERR_JSON, detail="响应是 brotli 压缩，未装 brotli 模块")
        data = brotli.decompress(body)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return ParseResult(error=ERR_JSON, detail=f"不是 utf-8: {exc}")
    try:
        payload = loads_strict(text)
    except DuplicateKey as exc:
        return ParseResult(error=ERR_JSON, detail=f"JSON 有重复键 {exc.args[0]!r}")
    except ValueError as exc:
        return ParseResult(error=ERR_JSON, detail=f"JSON 解析失败: {exc}")
    return extract(payload, headers, http_status=http_status)
