"""HTTP + WebSocket 服务。

对外（局域网）：
    GET  /badge, /ws        WebSocket（iOS 连 ws://<host>:<port>/badge）
    GET  /pair.png          ★ 二维码：手机扫它完成配对
    GET  /pair.svg          同上（SVG，无 Pillow 时自动用这个）
    GET  /pair.json         二维码原始 JSON（调试用）

本地面板（浏览器打开 http://127.0.0.1:<port>/ ）：
    GET  /  /ui/           控制台
    GET  /api/state        全量状态
    POST /api/config       改配置（backend / account / auto_consume / port …）
    POST /api/session      手工导入抓到的会话（调试 & 离线验证）
    GET  /api/session/check 探活当前会话
    POST /api/badges/{id}/verify  对某条已存徽章补做一次官方验证
    GET  /api/badges       徽章列表
    GET  /api/injections   注入记录
    GET  /api/export       导出全部徽章 JSON
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import WSMsgType, web

from . import PROTOCOL, __version__
from .capture import CaptureError, CaptureStack
from .config import Config, lan_addresses
from .crypto import CryptoBox, fingerprint_of, new_private_key, private_key_from_pem, private_key_to_pem, public_bytes
from .inject import make_backend
from .netease_api import NeteaseClient, Session
from .qr import qr_payload, qr_png, qr_svg
from .session import AppContext, ConnectionSession
from .store import Store

log = logging.getLogger("skyhuiyu.server")
WEB_DIR = Path(__file__).parent / "web"


# --------------------------------------------------------------------------- #
# 长期密钥（指纹跨重启稳定，手机上不用重新确认）
# --------------------------------------------------------------------------- #

def load_or_create_server_key(store: Store):
    pem = store.meta_get("server_key_pem")
    if pem:
        try:
            return private_key_from_pem(pem.encode())
        except Exception:  # noqa: BLE001
            log.warning("存档的服务器密钥坏了，重新生成")
    key = new_private_key()
    store.meta_set("server_key_pem", private_key_to_pem(key).decode())
    return key


# --------------------------------------------------------------------------- #
# 应用装配
# --------------------------------------------------------------------------- #

def build_app(ctx: AppContext) -> web.Application:
    app = web.Application(middlewares=[_error_mw])
    app["ctx"] = ctx
    # 抓取栈由 run() 装配（需要 cfg + store，且要跑崩溃自愈）
    app["capture"] = None

    app.router.add_get("/", _index)
    app.router.add_get("/ui", _index)
    app.router.add_get("/ui/", _index)
    app.router.add_static("/ui/static/", WEB_DIR, show_index=False, follow_symlinks=False)

    app.router.add_get("/pair.png", _pair_png)
    app.router.add_get("/pair.svg", _pair_svg)
    app.router.add_get("/pair.json", _pair_json)

    app.router.add_get("/badge", _ws)
    app.router.add_get("/ws", _ws)

    app.router.add_get("/api/state", _api_state)
    app.router.add_get("/api/catalog", _api_catalog)
    app.router.add_get("/catalog/icon/{img:[^/]+\\.png}", _catalog_icon)
    app.router.add_post("/api/config", _api_config)
    app.router.add_post("/api/session", _api_session)
    app.router.add_get("/api/session/check", _api_session_check)
    app.router.add_get("/api/badges", _api_badges)
    app.router.add_get("/api/badges/{bid:\\d+}/qr.png", _api_badge_qr)
    app.router.add_get("/api/badges/{bid:\\d+}/qr.svg", _api_badge_qr_svg)
    app.router.add_post("/api/badges/{bid:\\d+}/verify", _api_badge_verify)
    app.router.add_get("/api/injections", _api_injections)
    app.router.add_get("/api/export", _api_export)
    app.router.add_route("*", "/api/capture", _api_capture)
    app.router.add_get("/healthz", _healthz)
    return app


def _ctx(request: web.Request) -> AppContext:
    return request.app["ctx"]


# --------------------------------------------------------------------------- #
# 面板
# --------------------------------------------------------------------------- #

async def _index(request: web.Request) -> web.StreamResponse:
    target = WEB_DIR / "index.html"
    if not target.exists():
        return web.Response(text="web/index.html 丢失", status=500)
    return web.FileResponse(target, headers={"Cache-Control": "no-store"})


async def _healthz(request: web.Request) -> web.Response:
    ctx = _ctx(request)
    return web.json_response({
        "ok": True, "version": __version__, "protocol": PROTOCOL,
        "uptime": round(time.time() - ctx.started_at, 1),
    })


# --------------------------------------------------------------------------- #
# 二维码
# --------------------------------------------------------------------------- #

def _payload(ctx: AppContext) -> tuple[str, dict[str, Any]]:
    box = CryptoBox(private_key=ctx.server_key)
    host = ctx.cfg.advertise
    payload = qr_payload(box.public_key_base64, host, int(ctx.cfg.port))
    info = {
        "payload": payload,
        "pubkey": box.public_key_base64,
        "pubkey_hex": box.public_key_hex,
        "fingerprint": box.fingerprint,
        "host": host,
        "port": int(ctx.cfg.port),
        "lan_addresses": lan_addresses(),
        "protocol": PROTOCOL,
    }
    return payload, info


async def _pair_png(request: web.Request) -> web.Response:
    payload, _ = _payload(_ctx(request))
    try:
        data = qr_png(payload)
        ctype = "image/png"
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            ctype = "image/svg+xml"
        return web.Response(body=data, content_type=ctype,
                            headers={"Cache-Control": "no-store"})
    except Exception as exc:  # noqa: BLE001
        log.exception("二维码生成失败")
        return web.Response(text=f"二维码生成失败: {exc}", status=500)


async def _pair_svg(request: web.Request) -> web.Response:
    payload, _ = _payload(_ctx(request))
    try:
        return web.Response(text=qr_svg(payload), content_type="image/svg+xml",
                            headers={"Cache-Control": "no-store"})
    except Exception as exc:  # noqa: BLE001
        return web.Response(text=f"二维码生成失败: {exc}", status=500)


async def _pair_json(request: web.Request) -> web.Response:
    _payload_str, info = _payload(_ctx(request))
    return web.json_response(info, headers={"Cache-Control": "no-store"})


# --------------------------------------------------------------------------- #
# WebSocket
# --------------------------------------------------------------------------- #

async def _ws(request: web.Request) -> web.StreamResponse:
    ctx = _ctx(request)
    ws = web.WebSocketResponse(heartbeat=30.0, autoping=True, max_msg_size=1 << 20)
    await ws.prepare(request)
    peer = f"{request.remote}"
    conn = ConnectionSession(ctx, peer)
    log.info("WS 连接 peer=%s path=%s", peer, request.path)

    try:
        # ★ 连上立刻发 server_hello（iOS 第一件事就是等这条）
        await ws.send_str(json.dumps(conn.hello(), ensure_ascii=False))

        async for msg in ws:
            if msg.type == WSMsgType.ERROR:
                log.warning("WS 错误 peer=%s: %s", peer, ws.exception())
                break
            if msg.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                continue

            # 契约 A 的最后一道保险：handle_frame 内部已兜异常，
            # 这里再兜一次，保证"每条消息恰好一条应答"不依赖上游自觉。
            try:
                out = await conn.handle_frame(msg.data)
            except Exception:  # noqa: BLE001
                log.exception("handle_frame 抛出未捕获异常 peer=%s", peer)
                out = [{"status": "error", "message": "PC 内部错误",
                        "error": "internal", "inject": {"ok": False, "action": "internal",
                                                        "detail": "PC 内部错误，请重发"}}]

            for frame in out:
                await ws.send_str(json.dumps(frame, ensure_ascii=False, default=str))

            # 协议层要求断开（例如 legacy 客户端配对被拒：不能回帧，只能断）
            code = getattr(conn, "close_code", None)
            if code:
                reason = str(getattr(conn, "close_reason", "") or "")[:100]
                log.warning("主动关闭 peer=%s code=%s reason=%s", peer, code, reason)
                await ws.close(code=code, message=reason.encode("utf-8"))
                break
    except ConnectionResetError:
        log.info("WS 被重置 peer=%s", peer)
    finally:
        log.info("WS 关闭 peer=%s", peer)
    return ws


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #

async def _api_state(request: web.Request) -> web.Response:
    ctx = _ctx(request)
    _payload_str, info = _payload(ctx)
    sess_row = ctx.store.latest_session(ctx.cfg.account)
    session_info: dict[str, Any] = {"present": bool(sess_row)}
    if sess_row:
        session_info.update({
            "account": sess_row.get("account"),
            "user_id": sess_row.get("user_id"),
            "captured_at": sess_row.get("captured_at"),
            "last_ok": sess_row.get("last_ok"),
            "has_level_id": bool(sess_row.get("level_id")),
            "has_build_key": bool(sess_row.get("build_access_key")),
            "user_agent": (sess_row.get("user_agent") or "")[:120],
        })
    return web.json_response({
        "version": __version__,
        "protocol": PROTOCOL,
        "uptime": round(time.time() - ctx.started_at, 1),
        "pair": info,
        "config": ctx.cfg.as_public(),
        "backend": getattr(ctx.backend, "name", "?"),
        "stats": ctx.store.stats(),
        "devices": [d.as_dict() for d in ctx.store.list_devices()],
        # 默认按 uid 去重：同一枚章反复贴只显示一枚（徽章库语义）
        "badges": [b.as_dict() for b in ctx.store.list_badges(limit=100)],
        "session": session_info,
        "preflight": ctx.preflight or {},
        "catalog": _catalog_state(ctx),
        # 「记录」页用：最近提交流水（含官方判定）
        "injections": [dict(r) for r in ctx.store.list_injections(limit=60)],
        "capture": _capture_state(request),
    })


async def _api_catalog(request: web.Request) -> web.Response:
    """整本徽章库（115 种），并把「已拥有」标出来。

    面板据此渲染：已拥有的原色排前面、未拥有的淡化排后面。
    """
    ctx = _ctx(request)
    owned: dict[str, dict[str, Any]] = {}
    for b in ctx.store.list_badges(limit=1000, dedupe=True):
        if b.sku and b.sku not in owned:
            owned[b.sku] = {
                "badge_id": b.id,
                "uid": b.uid,
                "counter": b.counter,
                "status": b.status,
                "received_at": b.received_at,
            }

    items = []
    for row in ctx.store.badge_catalog_all():
        sk = row["sk"]
        hit = owned.get(sk)
        items.append({
            "sk": sk,
            "img": row["img"],
            "name": row["name"],
            "name_en": row["name_en"],
            "desc": row["descr"],
            "effect": row["effect"],
            "cooldown_ms": row["cooldown_ms"],
            "disabled": bool(row["disabled"]),
            "owned": hit is not None,
            "badge": hit,
        })

    # 已拥有的排前面（按收到时间倒序），其余按图鉴序号
    items.sort(key=lambda x: (0, -(x["badge"]["received_at"] if x["badge"] else 0))
               if x["owned"] else (1, 0))

    return web.json_response({
        "count": len(items),
        "owned": sum(1 for i in items if i["owned"]),
        "items": items,
    })


def _catalog_state(ctx: AppContext) -> dict[str, Any]:
    """徽章库规模 + 有图标的数量（面板展示用）。"""
    try:
        from .catalog import icon_path

        with ctx.store.connect() as db:
            defs = db.execute("SELECT COUNT(*) c FROM consumable_defs").fetchone()["c"]
            tags = db.execute("SELECT COUNT(*) c FROM star_tag_defs").fetchone()["c"]
            builtin = db.execute("SELECT COUNT(*) c FROM badge_catalog").fetchone()["c"]
            imgs = [r["img"] for r in db.execute(
                "SELECT img FROM badge_catalog WHERE img <> ''")]
        with_icon = sum(1 for i in imgs if icon_path(i).exists())
        return {"defs": defs, "tags": tags, "builtin": builtin, "with_icon": with_icon}
    except Exception:  # noqa: BLE001
        return {"defs": 0, "tags": 0, "builtin": 0, "with_icon": 0}


async def _catalog_icon(request: web.Request) -> web.Response:
    """徽章图标：内置在包里，按图片 id 取。"""
    from .catalog import icon_path

    name = request.match_info["img"]
    img_id = name[:-4] if name.endswith(".png") else name
    if not img_id.isdigit():
        return web.json_response({"ok": False, "error": "bad_img"}, status=400)
    path = icon_path(img_id)
    if not path.exists():
        return web.json_response({"ok": False, "error": "no_icon"}, status=404)
    return web.Response(
        body=path.read_bytes(),
        content_type="image/png",
        headers={"Cache-Control": "public, max-age=86400"},
    )


def _capture_state(request: web.Request) -> dict[str, Any] | None:
    stack: CaptureStack | None = request.app.get("capture")
    if stack is None:
        return None
    try:
        return stack.snapshot_for_ui()
    except Exception as exc:  # noqa: BLE001 - 面板不能因为抓取栈异常而整页 500
        log.warning("读取抓取栈状态失败: %s", exc)
        return {"recovery_error": str(exc)}


async def _api_capture(request: web.Request) -> web.Response:
    """抓取栈：GET 看状态，POST {"action": "enable"|"disable"|"status"} 开关。

    开关是阻塞活（要动 hosts / WinINet），所以扔到线程池里跑，别卡住 WebSocket。
    """
    stack: CaptureStack | None = request.app.get("capture")
    if stack is None:
        return web.json_response({"ok": False, "error": "抓取栈未装配"}, status=503)
    if request.method == "GET":
        return web.json_response({"ok": True, "capture": stack.snapshot_for_ui()})

    guard = _guard_write(request)
    if guard is not None:
        return guard
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return web.json_response({"ok": False, "error": "body 不是 JSON"}, status=400)
    action = str((body or {}).get("action", "")).lower()
    loop = asyncio.get_running_loop()
    try:
        if action == "status":
            return web.json_response({"ok": True, "capture": stack.snapshot_for_ui()})
        if action == "enable":
            purge = bool((body or {}).get("purge_cef", True))
            keep_ticket = bool((body or {}).get("keep_ticket", False))
            # 轻量模式：跳过 ma75 劫持 / 清缓存 / 让票据，靠平台自己登录产生流量
            light = bool((body or {}).get("light", False))
            st = await loop.run_in_executor(
                None, lambda: stack.enable(purge_cef=purge,
                                           park_ticket=not keep_ticket,
                                           hijack_ma75=not light))
            return web.json_response({"ok": True, "capture": st})
        if action == "platforms":
            from .capture.launcher import find_candidates
            cands = await loop.run_in_executor(None, find_candidates)
            return web.json_response({"ok": True,
                                      "candidates": [str(c) for c in cands]})
        if action == "launch_platform":
            # 由我们启动官方平台 —— 必须先让 PAC 生效再拉起进程，
            # 否则平台已有的连接池不会再走代理（错误码 official_pc_proxy_required 拦的就是这个）
            from .capture.launcher import LaunchError, launch as launch_platform, pick
            hint = (body or {}).get("path") or None
            try:
                exe = await loop.run_in_executor(None, lambda: pick(hint))
                info = await loop.run_in_executor(None, lambda: launch_platform(exe))
            except LaunchError as exc:
                return web.json_response({"ok": False, "error_code": exc.code,
                                          "error": exc.detail}, status=409)
            return web.json_response({"ok": True, "platform": info})
        if action == "disable":
            out = await loop.run_in_executor(None, stack.disable)
            return web.json_response({"ok": True, **out})
        return web.json_response({"ok": False, "error": f"未知 action: {action}"}, status=400)
    except CaptureError as exc:
        return web.json_response({"ok": False, "error_code": exc.code, "error": exc.detail},
                                 status=409)


def _guard_write(request: web.Request) -> web.Response | None:
    """管理面写接口的两道闸。

    没有这两道，任意网页都能对 127.0.0.1:8765 发起无预检的跨站 POST
    （form-urlencoded / text/plain 都能被 request.json() 解析），
    一条 POST 就能把 config 写坏、把 token 导走。
    """
    ctype = (request.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if ctype != "application/json":
        return web.json_response({"ok": False, "error": "需要 Content-Type: application/json"},
                                 status=415)
    origin = request.headers.get("Origin")
    if origin:
        host = request.headers.get("Host", "")
        # 只允许同源（含 file://、null 一律拒）
        if not host or origin.split("//")[-1].split("/")[0] != host:
            return web.json_response({"ok": False, "error": "跨站请求被拒绝"}, status=403)
    return None


# 每个字段的允许类型与取值范围：写进 config.json 之前必须卡住，
# 否则一条 POST {"port":"abc"} 就能让服务永远起不来。
_CONFIG_SCHEMA: dict[str, tuple[type, Any]] = {
    "backend": (str, {"local", "netease", "relay"}),
    "account": (str, None),
    "auto_consume": (bool, None),
    "auto_store": (bool, None),
    "advertise_host": (str, None),
    "port": (int, (1, 65535)),
    "allowed_fingerprints": (list, None),
    "inject_timeout": (float, (1.0, 300.0)),
    "open_browser": (bool, None),
    "log_level": (str, {"DEBUG", "INFO", "WARNING", "ERROR"}),
    "bind": (str, None),
}


def _coerce_config(key: str, value: Any) -> tuple[bool, Any, str]:
    """返回 (是否合法, 规范化后的值, 错误说明)。"""
    spec = _CONFIG_SCHEMA.get(key)
    if spec is None:
        return False, None, "未知字段"
    typ, constraint = spec

    if typ is float and isinstance(value, int) and not isinstance(value, bool):
        value = float(value)
    if typ is int and isinstance(value, bool):
        return False, None, "类型不对"
    if typ is list:
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            return False, None, "必须是字符串数组"
        return True, [x.strip().lower() for x in value if x.strip()], ""
    if not isinstance(value, typ):
        return False, None, f"需要 {typ.__name__}"

    if isinstance(constraint, set):
        if value not in constraint:
            return False, None, f"只能是 {sorted(constraint)}"
    elif isinstance(constraint, tuple) and typ in (int, float):
        lo, hi = constraint
        if not (lo <= value <= hi):
            return False, None, f"取值范围 {lo}~{hi}"
    if typ is str:
        value = value.strip()
    return True, value, ""


async def _api_config(request: web.Request) -> web.Response:
    ctx = _ctx(request)
    blocked = _guard_write(request)
    if blocked is not None:
        return blocked
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return web.json_response({"ok": False, "error": "body 不是 JSON"}, status=400)
    if not isinstance(body, dict):
        return web.json_response({"ok": False, "error": "body 不是对象"}, status=400)

    # 先全量校验，再落盘：任何一个字段非法就整单拒绝，不留半截配置
    staged: dict[str, Any] = {}
    for k, v in body.items():
        if k not in _CONFIG_SCHEMA:
            continue
        ok, val, err = _coerce_config(k, v)
        if not ok:
            return web.json_response({"ok": False, "error": f"{k}: {err}", "field": k},
                                     status=400)
        staged[k] = val

    changed: list[str] = []
    for k, v in staged.items():
        setattr(ctx.cfg, k, v)
        changed.append(k)

    if "backend" in changed:
        ctx.backend = make_backend(ctx.cfg, ctx.store, ctx.http)
    ctx.cfg.save()
    log.info("配置已更新: %s", ",".join(changed) or "(无)")
    return web.json_response({"ok": True, "changed": changed, "config": ctx.cfg.as_public(),
                              "restart_required": "port" in changed or "bind" in changed})


async def _api_session(request: web.Request) -> web.Response:
    """手工导入会话。字段与 capture/mitm_addon.py 写入的一致。"""
    ctx = _ctx(request)
    blocked = _guard_write(request)
    if blocked is not None:
        return blocked
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return web.json_response({"ok": False, "error": "body 不是 JSON"}, status=400)
    if not isinstance(body, dict):
        return web.json_response({"ok": False, "error": "body 不是对象"}, status=400)
    user_id = str(body.get("user_id") or "").strip()
    token = str(body.get("session_token") or body.get("session") or "").strip()
    if not user_id or not token:
        return web.json_response({"ok": False, "error": "需要 user_id 和 session_token"}, status=400)

    sid = ctx.store.save_session(
        account=str(body.get("account") or ctx.cfg.account),
        user_id=user_id,
        session_token=token,
        level_id=str(body.get("level_id") or ""),
        build_access_key=str(body.get("build_access_key") or ""),
        user_agent=str(body.get("user_agent") or ""),
        game_version=str(body.get("game_version") or ""),
        extra=body.get("extra") if isinstance(body.get("extra"), dict) else {},
    )
    return web.json_response({"ok": True, "session_id": sid})


async def _api_session_check(request: web.Request) -> web.Response:
    ctx = _ctx(request)
    row = ctx.store.latest_session(ctx.cfg.account)
    if not row:
        return web.json_response({"ok": False, "error": "no_session"}, status=404)
    client = NeteaseClient(ctx.http, Session.from_row(row))
    ok, detail = await client.check()
    if ok:
        ctx.store.mark_session_ok(int(row["id"]))
    return web.json_response({"ok": ok, "detail": detail})


async def _api_badges(request: web.Request) -> web.Response:
    ctx = _ctx(request)
    return web.json_response({"badges": [b.as_dict() for b in ctx.store.list_badges(limit=500)]})


async def _api_badge_qr(request: web.Request) -> web.Response:
    """把徽章 URL 渲染成二维码 —— 给**游戏自己的扫码器**扫。

    依据：`sky.thatg.co/?s=…`（星章）那个页面**不显示短码**，只把整条 URL 做成二维码，
    绑定由游戏客户端完成；而 PC 端配置里 `QRCodeScanner` 是打开的。
    所以绑定不需要我们调任何接口，只需要把二维码摆到游戏面前。
    """
    ctx = _ctx(request)
    badge = ctx.store.get_badge(int(request.match_info["bid"]))
    if badge is None:
        return web.json_response({"ok": False, "error": "没有这条徽章"}, status=404)
    return web.Response(
        body=qr_png(badge.url),
        headers={"Content-Type": "image/png", "Cache-Control": "no-store",
                 "Content-Disposition": f'inline; filename="badge-{badge.id}.png"'},
    )


async def _api_badge_qr_svg(request: web.Request) -> web.Response:
    ctx = _ctx(request)
    badge = ctx.store.get_badge(int(request.match_info["bid"]))
    if badge is None:
        return web.json_response({"ok": False, "error": "没有这条徽章"}, status=404)
    return web.Response(text=qr_svg(badge.url), content_type="image/svg+xml",
                        headers={"Cache-Control": "no-store"})


async def _api_badge_verify(request: web.Request) -> web.Response:
    """对已入库的徽章补做一次官方验证（走当前 backend，不经过手机）。"""
    ctx = _ctx(request)
    bid = int(request.match_info["bid"])
    badge = ctx.store.get_badge(bid)
    if badge is None:
        return web.json_response({"ok": False, "error": "not_found"}, status=404)

    # 这个接口会**真的**再打一次官方接口。netease + auto_consume 时点一下
    # 就可能消耗掉一件道具，且官方侧不可撤销；所以必须显式确认，且不接受跨站调用。
    blocked = _guard_write(request)
    if blocked is not None:
        return blocked
    body: dict[str, Any] = {}
    try:
        if request.can_read_body:
            body = await request.json() or {}
    except Exception:  # noqa: BLE001
        body = {}
    if not isinstance(body, dict):
        body = {}
    if not body.get("confirm"):
        return web.json_response(
            {"ok": False, "error": "need_confirm",
             "message": "补验证会真的调用一次官方接口，确认请带 {\"confirm\": true}"},
            status=400,
        )

    result = await ctx.backend.handle(badge)
    return web.json_response({"ok": result.ok, "inject": result.as_dict()})


async def _api_injections(request: web.Request) -> web.Response:
    ctx = _ctx(request)
    bid = request.query.get("badge")
    rows = ctx.store.list_injections(int(bid) if bid and bid.isdigit() else None, limit=100)
    return web.json_response({"injections": rows})


async def _api_export(request: web.Request) -> web.Response:
    ctx = _ctx(request)
    payload = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "version": __version__,
        "badges": [b.as_dict() for b in ctx.store.list_badges(limit=100000)],
    }
    return web.json_response(payload, dumps=lambda o: json.dumps(o, ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------- #
# 生命周期
# --------------------------------------------------------------------------- #

@web.middleware
async def _error_mw(request: web.Request, handler):
    try:
        return await handler(request)
    except web.HTTPException:
        raise
    except Exception:  # noqa: BLE001
        log.exception("处理 %s %s 失败", request.method, request.path)
        return web.json_response({"ok": False, "error": "internal"}, status=500)


def create_ctx(cfg: Config) -> tuple[AppContext, Store]:
    store = Store(cfg.db_path)
    key = load_or_create_server_key(store)
    ctx = AppContext(cfg=cfg, store=store, backend=None, http=None, server_key=key)  # type: ignore[arg-type]
    return ctx, store


async def run(cfg: Config) -> None:
    from .logging_setup import setup as setup_logging

    logfile = setup_logging(cfg.data_path, cfg.log_level)
    log.info("日志文件 %s", logfile)
    ctx, _store = create_ctx(cfg)
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as http:
        ctx.http = http
        ctx.backend = make_backend(cfg, ctx.store, http)
        app = build_app(ctx)

        # 抓取栈：先做崩溃自愈（系统代理可能还指着上次那个已经不存在的端口）
        stack = CaptureStack(cfg, ctx.store, log=lambda m: log.info("%s", m))
        app["capture"] = stack
        try:
            recovered = await asyncio.get_running_loop().run_in_executor(None, stack.recover)
            if recovered:
                log.warning("抓取栈自愈：%s", recovered)
        except Exception as exc:  # noqa: BLE001 - 自愈失败不能挡住徽章服务
            log.warning("抓取栈自愈失败: %s", exc)

        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, cfg.bind, cfg.port)
        await site.start()

        box = CryptoBox(private_key=ctx.server_key)
        log.info("sky·徽遇 %s 已启动  %s", __version__, f"{cfg.bind}:{cfg.port}")
        log.info("面板   http://127.0.0.1:%d/", cfg.port)
        log.info("二维码 http://%s:%d/pair.png   指纹 %s",
                 cfg.advertise, cfg.port, box.fingerprint)
        log.info("手机连 ws://%s:%d/badge", cfg.advertise, cfg.port)
        log.info("后端 %s", ctx.backend.name)

        # 启动自检：会话还能不能用。无效就把可复制的操作步骤放进 ctx.preflight，
        # 面板会顶出一条红色提示，用户不用猜为什么点不动。
        try:
            from . import catalog as _catalog
            from . import preflight as _preflight
            from .netease_api import Session as _Session

            pf = await _preflight.check(cfg, ctx.store, http)
            ctx.preflight = pf
            if pf["ok"]:
                row = ctx.store.latest_session(cfg.account)
                if row:
                    cat = await _catalog.refresh(cfg, ctx.store, http, _Session.from_row(row))
                    log.info("徽章库：定义 %d / 星章 %d", cat.get("defs", 0), cat.get("tags", 0))
            else:
                log.warning("会话不可用：%s", pf["detail"])
            # 内置徽章库（115 条，含中文名/图标）先导入，再给历史徽章补名称
            builtin = _catalog.import_builtin(ctx.store)
            if builtin:
                log.info("内置徽章库：%d 条", builtin)
            # 不管有没有会话都补一次名称：SKU 是离线能从链接里解出来的
            labeled = _catalog.backfill(ctx.store)
            if labeled:
                log.info("历史徽章补名称：%d 枚", labeled)
        except Exception as exc:  # noqa: BLE001 - 自检失败不能挡住服务
            log.warning("启动自检异常：%s", exc)
            ctx.preflight = {"ok": True, "reason": "skipped", "detail": str(exc), "steps": ""}

        if cfg.open_browser:
            import webbrowser

            try:
                webbrowser.open(f"http://127.0.0.1:{cfg.port}/")
            except Exception:  # noqa: BLE001
                pass

        try:
            # 纯保活：服务由 aiohttp 自己跑，这里只是别让 main() 返回。
            # 原来的 `while True: await asyncio.sleep(3600)` 既不是体检周期也不是轮询，
            # 却长得像"每小时做一次什么" —— 会话有效性只在**启动时**实测一次
            # （见上面 682 行的 preflight.check），运行期要复查走 /api/session/check。
            await asyncio.Event().wait()
        finally:
            # 进程要退了，系统代理不能还指着我们：还原干净再走
            if stack.proxy.ready or stack.listener443.ready:
                try:
                    await asyncio.get_running_loop().run_in_executor(None, stack.disable)
                except Exception as exc:  # noqa: BLE001
                    log.warning("退出时还原抓取栈失败: %s", exc)
            await runner.cleanup()

