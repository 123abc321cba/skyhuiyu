"""官方（网易国服）接口客户端。

**信封协议**（2026-11-16 运行时实测确认，细节见 `envelope.py`）：

    POST https://live-as-sky-merge.game.163.com/account/star/verify
         wire {"user": <uuid>, "body": base64(RC4(<json>, key=<session2>))}
         json {"user": <uuid>, "user_id": <uuid>, "session": <session>, "uri": "<徽章 URL>"}
         回包 gzip(RC4(body, session2)) →
              {"result":"ok|consumable_on_cooldown", "star_tag_def_name":…,
               "bound_to_user":…, "bound_to_other":…, "linked_to":…,
               "get_consumables":[…], "changes":{"added":{id:n}}}

    POST …/account/consumable/get_consumables1      json {"user","user_id","session"}
    POST …/account/consumable/consume_item1         json {"user","user_id","session",
                                                          "get_consumables":{…}}

请求头（游戏客户端）：Content-Type / X-Session-ID / trace-id /
x-user-id / x-session-token / User-Agent / x-sky-level-id / x-sky-build-access-key。

**不要**用明文发 json —— 官方对玩家数据接口只收信封，明文一律 423/404（实测）。
信封的 RC4 密钥是登录响应顶层的 `session2`，缺它什么都发不出去。
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from . import envelope

import aiohttp

API_BASE = "https://live-as-sky-merge.game.163.com"
PATH_VERIFY = "/account/star/verify"
PATH_CONSUME = "/account/consumable/consume_item1"
PATH_CONSUMABLES = "/account/consumable/get_consumables1"
PATH_DEFS = "/account/consumable/get_consumable_defs"
PATH_BUFFS = "/account/buff/get_buffs1"
PATH_STAR = "/account/star/get"

UA_RE = re.compile(r"^Sky-Live-[A-Za-z0-9.-]+/([0-9]+(?:\.[0-9]+){0,3})\.([0-9]+) \(")

# 判定词表（顺序有意义：先特殊后通用）
VERIFY_VERDICTS: tuple[tuple[str, str], ...] = (
    ("CANNOT_UPDATE_NFC_COUNTER", "nfc_counter_update_failed"),
    # 官方网络层处理失败：结果**未确认**。官方把这种标成 store_unconfirmed，
    # 并且明确"不要自动重发" —— 因为重发可能二次入账或触发风控。
    ("atomicity_failure", "atomicity_failure"),
    ("already_bound", "already_bound"),
    ("consumable_on_cooldown", "cooldown"),
    ("identity_mismatch", "identity_mismatch"),
    ("invalid_fields", "invalid_fields"),
    ("verified_no_inventory", "verified_no_inventory"),
    ("bound_to_other", "bound_to_other"),
    ("bound_to_user", "bound_to_user"),
    ("unbound", "unbound"),
    ("verified", "verified"),
    ("success", "verified"),
)

CONSUME_VERDICTS: tuple[tuple[str, str], ...] = (
    ("insufficient_consumables", "insufficient_consumables"),
    ("invalid_consumable_def", "invalid_consumable_def"),
    ("atomicity_failure", "atomicity_failure"),
    ("result_conflict", "result_conflict"),
    ("buff_on_cooldown", "buff_on_cooldown"),
    ("already_buffed", "already_buffed"),
    ("max_buffs", "max_buffs"),
    ("ban_message_boat", "ban_message_boat"),
    ("social_feed_disabled", "social_feed_disabled"),
    ("consumable_on_cooldown", "cooldown"),
    ("used_no_inventory", "used_no_inventory"),
    ("used", "used"),
    ("success", "used"),
)


class NeteaseError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass
class Session:
    """一份抓到的登录态。"""

    user_id: str
    session_token: str
    level_id: str = ""
    build_access_key: str = ""
    user_agent: str = (
        "Sky-Live-0.12.0.289624 (Android 13; Pixel 7; zh_CN; 1080x2400)"
    )
    game_version: str = ""
    device_model: str = "Pixel 7"
    system_version: str = "Android 13"
    language: str = "zh_CN"
    # 游戏发的 `X-Session-ID`，和 session token 不是一个东西。
    # 实测：拿 session token 冒充它 → 401/423；带上真实值 → 200。
    session_id: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def session2(self) -> str:
        """信封的 RC4 密钥。登录响应顶层那个 `session2`，没有它什么都发不出去。"""
        return str(self.extra.get("session2") or "")

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Session":
        extra = row.get("extra_obj") or {}
        return cls(
            user_id=str(row.get("user_id") or ""),
            session_token=str(row.get("session_token") or ""),
            level_id=str(row.get("level_id") or ""),
            build_access_key=str(row.get("build_access_key") or ""),
            user_agent=str(row.get("user_agent") or cls.__dataclass_fields__["user_agent"].default),
            game_version=str(row.get("game_version") or ""),
            device_model=str(extra.get("game_device_model") or "Pixel 7"),
            system_version=str(extra.get("game_system_version") or "Android 13"),
            language=str(extra.get("game_language") or "zh_CN"),
            session_id=str(extra.get("session_id") or ""),
            extra=extra,
        )

    def is_usable(self) -> bool:
        # session2 是信封的 RC4 密钥，缺了它官方一律拒（实测 423/404）。
        return bool(self.user_id) and bool(self.session_token) and bool(self.session2)


@dataclass
class VerifyOutcome:
    verdict: str
    http_status: int
    detail: str = ""
    handles: list[dict[str, Any]] = field(default_factory=list)
    user_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    # 回包里的 `star_tag_def_name`：这次验章对应**哪一件**道具/魔法的内部名。
    # 拿它去 get_consumable_defs 换 id，再去库存里核对 —— 这是"到底存进去没有"的唯一硬证据。
    star_tag_def_name: str = ""
    bound_to_user: bool = False


def game_headers(session: Session, *, trace_id: str | None = None) -> dict[str, str]:
    """构造游戏请求头。

    头名与顺序按**抓包实测**对齐（`/account/get_rank` 的原始请求头）：
    游戏同时发 `user-id` / `x-user-id` 和 `session` / `x-session-token` 两套，
    外加独立的 `X-Session-ID`。少一套或 X-Session-ID 拼错都会被官方拒（401/423）。
    """
    headers = {
        "Content-Type": "application/json",
        "X-Session-ID": session.session_id or session.session_token,
        "trace-id": trace_id or uuid.uuid4().hex,
        "user-id": session.user_id,
        "session": session.session_token,
        "x-user-id": session.user_id,
        "x-session-token": session.session_token,
        "User-Agent": session.user_agent,
    }
    if session.level_id:
        headers["x-sky-level-id"] = session.level_id
    if session.build_access_key:
        headers["x-sky-build-access-key"] = session.build_access_key
    return headers


_RESULT_VERDICTS = {
    "ok": "verified",
    "consumable_on_cooldown": "cooldown",
    "bound_to_other": "bound_to_other",
    "unbound": "unbound",
    "identity_mismatch": "identity_mismatch",
}

# 道具定义表按 user_id 缓存（name → id）。静态数据，没必要每次验章都重拉。
_DEFS_CACHE: dict[str, tuple[float, dict[str, int]]] = {}
_DEFS_TTL = 3600.0


def _verdict_from_result(parsed: Any) -> str | None:
    """优先用回包的 `result` 字段判成败。

    为什么不能只靠关键字扫描：解开的响应是一整个 JSON，
    里面固定带 `"invalid_fields":[]` 这类**键名**，纯文本匹配会把它当成失败。
    """
    if not isinstance(parsed, dict):
        return None
    result = parsed.get("result")
    if not isinstance(result, str) or not result:
        return None
    if result in _RESULT_VERDICTS:
        return _RESULT_VERDICTS[result]
    if result.startswith("CANNOT_UPDATE_NFC_COUNTER"):
        return "nfc_counter_update_failed"
    return result


def _walk(node: Any, want: tuple[str, ...]) -> list[Any]:
    out: list[Any] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k in want:
                out.append(v)
            out.extend(_walk(v, want))
    elif isinstance(node, list):
        for v in node:
            out.extend(_walk(v, want))
    return out


_FALSY_KEYS = ("success", "ok", "result_ok", "verified")


def _string_values(node: Any) -> list[str]:
    """只收 JSON 里的**字符串值**，绝不收键名。

    原来的实现拿整段响应文本做子串匹配，于是 {"success":false} 里的
    "success" 这个键名就把失败判成了成功 —— 一次误判会连带触发一次
    不可撤销的 consume。
    """
    out: list[str] = []
    if isinstance(node, dict):
        for v in node.values():
            out.extend(_string_values(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_string_values(v))
    elif isinstance(node, str):
        out.append(node)
    return out


def _explicit_false(node: Any) -> bool:
    """回包里有没有明确的失败标志（success/ok/verified == false）。"""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _FALSY_KEYS and v is False:
                return True
            if _explicit_false(v):
                return True
    elif isinstance(node, list):
        for v in node:
            if _explicit_false(v):
                return True
    return False


def _is_code_like(needle: str) -> bool:
    """能安全做子串匹配的"代码型"词：带下划线、或全大写、或足够长。

    短词（used / bound）只允许整值相等 —— 否则 "unused" 会命中 "used"、
    "unbound" 会命中 "bound"。
    """
    return "_" in needle or needle.isupper() or len(needle) >= 9


def classify(raw: str | Any, table: tuple[tuple[str, str], ...]) -> str | None:
    """按词表顺序判定，匹配对象是**字段值**而不是整段文本。

    规则：
      1. 值与词完全相等 → 命中；
      2. 值是较长的代码串（带下划线/全大写）且包含该词 → 命中；
      3. 回包里有明确的 success/ok/verified == false → 未命中（判失败）。
    词的顺序即优先级，与原表一致。
    """
    payload: Any = raw
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
        except Exception:  # noqa: BLE001
            payload = [raw]

    values = [v.lower() for v in _string_values(payload)]
    if not values:
        return None

    for needle, verdict in table:
        n = needle.lower()
        for v in values:
            if v == n:
                return verdict
            if _is_code_like(needle) and n in v:
                return verdict

    if _explicit_false(payload):
        return None
    return None


def parse_handles(payload: Any) -> list[dict[str, Any]]:
    """从 get_consumables / verify 回包里抠出可用句柄。

    兼容两种形状：
        {"get_consumables": {"entries": [{"handle": .., "id": .., "count": n}]}}
        {"items": [{"handle": .., "def_name": .., "quantity": n}]}
    """
    out: list[dict[str, Any]] = []
    for key in ("get_consumables", "get_consumable", "items", "entries", "consumables"):
        for node in _walk(payload, (key,)):
            items = node.get("entries") or node.get("items") or node.get("list") if isinstance(node, dict) else node
            if isinstance(items, list):
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    handle = it.get("handle") or it.get("item_handle") or it.get("id")
                    if handle in (None, ""):
                        # 真实回包（2026-11-18 实测 injections#9）长这样：
                        #   {"get_consumables":[{"consumable_id":1883796228,
                        #                        "cooldown_until":0,"quantity":1}]}
                        # 里面**没有** handle / item_handle / id 三个键中的任何一个。
                        # 原来这里直接 continue，于是 handles 恒定是空列表，
                        # `len(outcome.handles) == 1` 永远不成立 —— auto_consume 从来没跑过。
                        handle = it.get("consumable_id") or it.get("def_id")
                    if handle in (None, ""):
                        continue
                    out.append({
                        "handle": str(handle),
                        "consumable_id": it.get("consumable_id") or it.get("id") or it.get("def_id") or 0,
                        "def_name": it.get("def_name") or it.get("name") or "",
                        "quantity": it.get("quantity") or it.get("count") or 1,
                    })
    # 去重（同 handle 只留一条）
    seen: set[str] = set()
    uniq: list[dict[str, Any]] = []
    for it in out:
        if it["handle"] in seen:
            continue
        seen.add(it["handle"])
        uniq.append(it)
    return uniq


class NeteaseClient:
    """一个 session 一个 client。aiohttp 连接池由外部注入。"""

    def __init__(self, http: aiohttp.ClientSession, session: Session) -> None:
        self._http = http
        self.session = session

    async def _post(self, path: str, body: dict[str, Any]) -> tuple[int, str, Any]:
        """发一个**信封**请求。

        官方对玩家数据接口只收 `{"user": …, "body": base64(RC4(json, session2))}`，
        收明文一律 423/404（实测）。响应是 `gzip(RC4(body, session2))`，这里直接解开，
        所以返回的 `parsed` 是可读的 dict，`text` 只是留个兜底。
        """
        url = API_BASE + path
        headers = game_headers(self.session)
        try:
            wire = envelope.wrap(self.session.user_id, body, self.session.session2)
            async with self._http.post(url, data=json.dumps(wire, ensure_ascii=False),
                                       headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=20)) as r:
                raw = await r.read()
                parsed = None
                text = ""
                if raw:
                    try:
                        parsed = envelope.open_body(raw, self.session.session2)
                        text = json.dumps(parsed, ensure_ascii=False)
                    except Exception:  # noqa: BLE001
                        text = raw[:400].decode("utf-8", "replace")
                return r.status, text, parsed
        except aiohttp.ClientError as exc:
            raise NeteaseError("network", str(exc)) from exc
        except TimeoutError as exc:
            raise NeteaseError("timeout", str(exc)) from exc

    # --- 验章（存） ---
    async def verify(self, badge_url: str) -> VerifyOutcome:
        payload = envelope.verify_payload(
            self.session.user_id, self.session.session_token, badge_url)
        status, text, parsed = await self._post(PATH_VERIFY, payload)
        verdict = _verdict_from_result(parsed) or classify(text, VERIFY_VERDICTS)

        # 官方拒绝时常常是**空响应**（实测 422 / 423 都是 0 字节），
        # 这时解不出任何东西，必须按 HTTP 码判定，否则只会显示「未识别结果」，
        # 用户根本看不出是会话过期。
        if parsed is None and status != 200:
            if status in (401, 403, 422, 423):
                verdict = "session_expired"
            elif status == 404:
                verdict = "session_expired"
            else:
                verdict = verdict or f"http_{status}"
        # 423 Locked 是官方对"登录态不完整/失效"的实际回应（实测）。
        # 只认 401/403 会把它判成 unknown，用户只看到"未知"，根本不知道是凭据问题。
        if status in (401, 403, 423):
            verdict = "session_invalid"
        if verdict is None:
            verdict = "unknown"
        detail = ""
        if isinstance(parsed, dict):
            for key in ("message", "msg", "errmsg", "detail"):
                if isinstance(parsed.get(key), str):
                    detail = parsed[key]
                    break
        if not detail and verdict == "session_invalid":
            missing = [n for n, v in (
                ("x-sky-build-access-key", self.session.build_access_key),
                ("x-sky-level-id", self.session.level_id),
            ) if not v]
            detail = (
                f"官方拒绝（HTTP {status}）：登录态不完整或已失效。"
                + (f"这份会话缺 {', '.join(missing)}。" if missing else "")
                + "重新抓一份完整的会话即可。"
            )
        uid = ""
        for node in _walk(parsed, ("user_id", "userid", "uid")):
            if isinstance(node, (str, int)) and str(node):
                uid = str(node)
                break
        return VerifyOutcome(
            verdict=verdict,
            http_status=status,
            detail=detail or text[:400],
            handles=parse_handles(parsed) if parsed is not None else [],
            user_id=uid,
            raw=parsed if isinstance(parsed, dict) else {"raw_text": text[:4000]},
            star_tag_def_name=str((parsed or {}).get("star_tag_def_name") or "")
            if isinstance(parsed, dict) else "",
            bound_to_user=bool((parsed or {}).get("bound_to_user"))
            if isinstance(parsed, dict) else False,
        )

    # --- 刷新库存（拿句柄） ---
    async def refresh_consumables(self) -> tuple[int, Any, str]:
        body = envelope.base_payload(self.session.user_id, self.session.session_token)
        status, text, parsed = await self._post(PATH_CONSUMABLES, body)
        return status, parsed, text

    # --- 验章后的库存核对（"到底存进去没有"的唯一硬证据） ---
    async def _def_name_to_id(self) -> dict[str, int]:
        """`get_consumable_defs` 的 name → id 映射，进程内缓存。

        defs 有 600+ 条、150KB+，每次验章都拉一遍太亏；这份表是静态定义，
        一小时内复用足够。
        """
        now = time.time()
        ent = _DEFS_CACHE.get(self.session.user_id)
        if ent is not None and now - ent[0] < _DEFS_TTL:
            return ent[1]
        status, _text, parsed = await self.consumable_defs()
        if status != 200 or not isinstance(parsed, dict):
            raise NeteaseError("defs_unavailable", f"http {status}")
        table: dict[str, int] = {}
        for d in parsed.get("get_consumable_defs") or []:
            if not isinstance(d, dict):
                continue
            name, cid = d.get("name"), d.get("id")
            if name and cid is not None:
                try:
                    table[str(name)] = int(cid)
                except (TypeError, ValueError):
                    continue
        if table:
            _DEFS_CACHE[self.session.user_id] = (now, table)
        return table

    async def confirm_stored(self, star_tag_def_name: str) -> dict[str, Any]:
        """核实这次验章的结果是否真的落进了库存。

        **为什么必须做这一步**：验章回 `{"result":"ok","bound_to_user":true}`
        只证明"这个徽章 URL 通过校验并绑到了你的账号"，
        并不证明对应的道具/魔法真的进了库存。2026-11-18 现场：
        界面提示"魔法已存入"，可游戏里翻遍背包都没有 —— 那句提示是从
        `result=="ok"` 直接翻译过来的，从来没有去库存里看过一眼。

        返回三态，**不要把"查不了"当成"没存上"**：
            confirmed=True   库存里确实有这件东西（还能拿到数量/冷却）
            confirmed=False  查得通，但库存里没有 → 真的没进去
            confirmed=None   查不了（会话失效/接口异常/名字对不上），结论未知
        """
        name = (star_tag_def_name or "").strip()
        if not name:
            return {"confirmed": None, "reason": "官方回包没给 star_tag_def_name"}
        try:
            table = await self._def_name_to_id()
        except NeteaseError as exc:
            return {"confirmed": None, "reason": f"取道具定义表失败（{exc.code}）"}
        cid = table.get(name)
        if cid is None:
            return {"confirmed": None, "reason": f"道具定义表里没有 {name}", "def_name": name}
        try:
            status, parsed, _text = await self.refresh_consumables()
        except NeteaseError as exc:
            return {"confirmed": None, "reason": f"取库存失败（{exc.code}）", "def_name": name}
        if status != 200:
            return {"confirmed": None, "reason": f"取库存被拒（HTTP {status}）",
                    "def_name": name, "consumable_id": cid}
        for it in (parsed or {}).get("get_consumables") or []:
            if not isinstance(it, dict):
                continue
            try:
                if int(it.get("consumable_id") or 0) != cid:
                    continue
            except (TypeError, ValueError):
                continue
            return {
                "confirmed": True,
                "def_name": name,
                "consumable_id": cid,
                "quantity": it.get("quantity"),
                "cooldown_until": it.get("cooldown_until") or 0,
            }
        return {"confirmed": False, "def_name": name, "consumable_id": cid}

    # --- 用（消耗触发魔法） ---
    async def consume(self, *, handle: str, consumable_id: int | str, count: int = 1) -> tuple[str, int, Any, str]:
        body = envelope.base_payload(self.session.user_id, self.session.session_token)
        body["get_consumables"] = {
            "handle": handle,
            "consumable_id": int(consumable_id) if str(consumable_id).isdigit() else consumable_id,
            "consumable_count": int(count),
        }
        status, text, parsed = await self._post(PATH_CONSUME, body)
        verdict = classify(text, CONSUME_VERDICTS) or ("unknown" if status == 200 else "http_error")
        return verdict, status, parsed, text

    # --- 杂项 ---
    async def consumable_defs(self) -> tuple[int, Any, str]:
        body = envelope.base_payload(self.session.user_id, self.session.session_token)
        return await self._post(PATH_DEFS, body)

    async def star_tags(self) -> tuple[int, Any, str]:
        body = envelope.base_payload(self.session.user_id, self.session.session_token)
        return await self._post(PATH_STAR, body)

    async def buffs(self) -> tuple[int, Any, str]:
        body = envelope.base_payload(self.session.user_id, self.session.session_token)
        return await self._post(PATH_BUFFS, body)

    # --- 会话健康检查（用最轻的接口试一下） ---
    async def check(self) -> tuple[bool, str]:
        try:
            status, _parsed, text = await self.refresh_consumables()
        except NeteaseError as exc:
            return False, exc.detail or exc.code
        if status == 200:
            return True, "ok"
        # 422 / 423 / 404 都是官方对「会话不匹配或已过期」的实际回应（实测，且常常是空响应）
        if status in (401, 403, 404, 422, 423):
            return False, "session_expired"
        return False, f"http_{status}: {text[:200]}"


