"""单连接协议状态机 —— 握手、配对、收章、回执。

一条连接一个 `ConnectionSession` 实例。所有帧都由 `handle_frame()` 处理，
返回值就是要发回去的帧列表（0 或 1 条）。**必须保证严格一问一答**：
iOS 端是顺序 `receive()`，多推一条就会永久错位。
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from . import PROTOCOL
from .config import Config
from .crypto import CryptoBox, CryptoError, b64e, decode_pubkey_any, fingerprint_of
from .inject import InjectResult
from .inject.base import Backend
from .protocol import (
    ERR_BAD_BADGE,
    ERR_BAD_FRAME,
    ERR_BAD_JSON,
    ERR_BAD_PUBKEY,
    ERR_BUSY,
    ERR_CRYPTO,
    ERR_NOT_PAIRED,
    ERR_RATE,
    is_probable_badge_url,
)
from .store import INFLIGHT, Store

log = logging.getLogger("skyhuiyu.session")

MAX_MSG_PER_10S = 30

# 应用自定义关闭码：4000-4999 归应用使用
WS_CLOSE_REJECTED = 4003


@dataclass
class AppContext:
    cfg: Config
    store: Store
    backend: Backend
    http: aiohttp.ClientSession
    server_key: Any = None                 # ec.EllipticCurvePrivateKey（长期密钥，重启不变）
    started_at: float = field(default_factory=time.time)
    # 进程内**正在提交**的 rid。DB 里的 inflight 分不清"同伴此刻在跑"还是
    # "上次进程死了留下的"：在集合里 = busy（可重试，安全），不在 = 遗留
    # （官方侧状态未知，必须人工核对）。进程重启集合自空，语义自动正确。
    inflight: set[str] = field(default_factory=set)
    # 启动预检结果：{ok, reason, detail, steps, session}
    # 面板据此提示「会话已失效」，并把可复制的操作步骤直接摆出来。
    preflight: dict[str, Any] = field(default_factory=dict)


def _ack(status: str, message: str, *, inject: InjectResult | None = None,
         record: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    frame: dict[str, Any] = {"status": status, "message": message}
    if inject is not None:
        frame["inject"] = inject.as_dict()
    if record is not None:
        frame["record"] = record
    frame.update(extra)
    return frame


class ConnectionSession:
    def __init__(self, ctx: AppContext, peer: str) -> None:
        self.ctx = ctx
        self.peer = peer
        self.box = CryptoBox(private_key=ctx.server_key)
        self.paired = False
        self.device_id = ""
        self.device_fp = ""
        self._msg_times: list[float] = []
        self._rid_memo: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ 入口
    async def handle_frame(self, raw: str | bytes) -> list[dict[str, Any]]:
        """入口。**任何**异常都必须变成一条应答。

        为什么：iOS 端是严格顺序 receive()，PC 少回一条，手机就永久卡在
        等待上（后面每条错位一格）。所以这里是唯一的不变量守卫，
        真实处理逻辑在 _dispatch 里，异常一律兜成一条 error 帧。
        """
        try:
            return await self._dispatch(raw)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("处理帧时代码层异常 peer=%s", self.peer)
            return [_ack("error", f"PC 内部错误: {exc}", error="internal")]

    async def _dispatch(self, raw: str | bytes) -> list[dict[str, Any]]:
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                return [_ack("error", "非 UTF-8 帧", error=ERR_BAD_FRAME)]
        if not self._rate_ok():
            log.warning("限流触发 peer=%s", self.peer)
            return [_ack("error", "发太快了", error=ERR_RATE)]
        try:
            msg = json.loads(raw)
        except Exception:  # noqa: BLE001
            return [_ack("error", "帧不是 JSON", error=ERR_BAD_JSON)]
        if not isinstance(msg, dict):
            return [_ack("error", "帧不是 JSON 对象", error=ERR_BAD_JSON)]

        if "phone_pubkey" in msg:
            if not self.paired:
                return await self._handle_pairing(msg)
            return await self._handle_badge(msg)
        # 兼容纯握手探测
        return [_ack("error", "缺少 phone_pubkey", error=ERR_BAD_FRAME)]

    def _rate_ok(self) -> bool:
        now = time.time()
        self._msg_times = [t for t in self._msg_times if now - t < 10.0]
        if len(self._msg_times) >= MAX_MSG_PER_10S:
            return False
        self._msg_times.append(now)
        return True

    # ---------------------------------------------------------------- 配对
    def _reject(self, why: str, *, legacy: bool | None = None,
                **extra: Any) -> list[dict[str, Any]]:
        """拒绝配对。

        legacy=None  —— 判不出对方是不是老客户端（明文都没解开）：
                        **不回帧**，只置关闭码让 _ws 断开。回一条错误帧
                        会让 v1.0 把它当成 badge 的结果，比直接断更糟。
        legacy=True  —— 确认是老客户端：同样不回帧，断开。
        legacy=False —— 新客户端（pairing 带 proto），回一条 error。
        """
        log.warning("配对被拒 peer=%s (%s): %s",
                    self.peer, "legacy/未知" if legacy is not False else "v1.1", why)
        if legacy is False:
            return [_ack("error", why, **extra)]
        self.close_code = WS_CLOSE_REJECTED
        self.close_reason = why
        return []

    async def _handle_pairing(self, msg: dict[str, Any]) -> list[dict[str, Any]]:
        phone_pub = msg.get("phone_pubkey")
        blob = msg.get("data")
        if not isinstance(phone_pub, str) or not isinstance(blob, str):
            return self._reject("配对帧字段缺失", error=ERR_BAD_FRAME)
        try:
            peer_raw = decode_pubkey_any(phone_pub)
        except CryptoError as exc:
            return self._reject(f"公钥无法解析: {exc}", error=ERR_BAD_PUBKEY)

        try:
            self.box.derive(peer_raw)
            inner = self.box.decrypt_json_str(blob)
        except CryptoError as exc:
            return self._reject(f"解密失败: {exc}", error=ERR_CRYPTO)

        if inner.get("type") != "pairing":
            return self._reject("明文类型不是 pairing", error=ERR_BAD_FRAME)

        # ★ 版本协商：v1.0 的 pairing 明文里没有 proto，且发完不读应答。
        legacy = "proto" not in inner
        # ★ 设备身份 = 手机公钥的指纹，不是 PC 自己的
        phone_fp = fingerprint_of(peer_raw)
        want_fp = str(inner.get("fingerprint") or "").lower()
        if want_fp and want_fp != phone_fp:
            log.warning("手机自报指纹与公钥不符: 自报 %s / 实算 %s", want_fp, phone_fp)

        # 白名单（空 = 全收）
        allow = [x.lower() for x in self.ctx.cfg.allowed_fingerprints if x]
        if allow and phone_fp not in allow:
            return self._reject("该手机不在白名单", legacy=legacy,
                                error=ERR_BAD_PUBKEY, fingerprint=phone_fp)

        dev = self.ctx.store.upsert_device(phone_fp, b64e(peer_raw),
                                          name=str(inner.get("device") or ""))
        self.ctx.store.bump_pair_count(dev.id)
        self.paired = True
        self.device_id = dev.id
        self.device_fp = phone_fp

        log.info("配对成功 peer=%s 手机指纹=%s PC 指纹=%s device=%s legacy=%s",
                 self.peer, phone_fp, self.box.fingerprint, dev.id, legacy)

        if legacy:
            log.info("legacy 客户端（pairing 无 proto），配对阶段不回任何帧")
            return []
        return [_ack("ok", "paired", device_id=dev.id, fingerprint=phone_fp,
                     server_fingerprint=self.box.fingerprint)]

    # ---------------------------------------------------------------- 收章
    @staticmethod
    def _frame_from_receipt(cached: dict[str, Any]) -> dict[str, Any]:
        payload = cached.get("payload_obj") or {}
        if payload:
            return payload
        inject = InjectResult(bool(cached["ok"]), cached["action"] or "cached",
                              cached["detail"] or "")
        return _ack("ok" if cached["ok"] else "error", cached["detail"] or "", inject=inject)

    async def _handle_badge(self, msg: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.box.is_derived or not self.paired:
            return [_ack("error", "尚未配对", error=ERR_NOT_PAIRED)]
        blob = msg.get("data")
        if not isinstance(blob, str):
            return [_ack("error", "缺 data", error=ERR_BAD_FRAME)]
        try:
            inner = self.box.decrypt_json_str(blob)
        except CryptoError as exc:
            return [_ack("error", f"解密失败: {exc}", error=ERR_CRYPTO)]

        if inner.get("type") != "badge":
            return [_ack("error", "明文类型不是 badge", error=ERR_BAD_FRAME)]

        uid = str(inner.get("uid") or "").strip().upper()
        token = str(inner.get("token") or "").strip()
        url = str(inner.get("url") or "").strip()
        try:
            counter = int(inner.get("counter") or 0)
        except (TypeError, ValueError):
            counter = 0

        if not uid or not token:
            return [_ack("error", "uid/token 为空", error=ERR_BAD_BADGE)]
        if not url:
            return [_ack("error", "url 为空", error=ERR_BAD_BADGE)]
        if not is_probable_badge_url(url):
            log.warning("URL 形态可疑（仍然入库，便于排查）: %s", url[:120])

        rid_raw = inner.get("rid")
        rid = str(rid_raw) if rid_raw not in (None, "") else f"legacy:{uid}:{counter}:{token[:16]}"

        # ---- 1. 已有完成的回执：直接原样返回，绝不再提交 ----
        cached = self.ctx.store.get_receipt(self.device_id, rid)
        if cached is not None and cached.get("action") != INFLIGHT:
            log.info("rid=%s 命中回执，直接返回", rid)
            return [self._frame_from_receipt(cached)]
        if cached is not None:
            if rid in self.ctx.inflight:
                # 同伴此刻正在提交同一个 rid：让他等，不要说成"状态未知"
                inject = InjectResult(
                    False, "busy", "同一枚章正在处理中，稍等再重发这条即可",
                    {"rid": rid, "badge_id": cached.get("badge_id")},
                )
                return [_ack("error", inject.detail, inject=inject, rid=rid)]
            # 不在活跃集合里却留着 inflight，说明上一个进程死在半路。
            # 官方侧状态未知。★ 绝不自动重发：可能已经消耗过。
            inject = InjectResult(
                False, "uncertain",
                "上一笔提交被中断，官方侧状态未知，请到 PC 面板核对后再决定是否重推",
                {"rid": rid, "badge_id": cached.get("badge_id")},
            )
            return [_ack("error", inject.detail, inject=inject, rid=rid)]

        # ---- 2. 入库（新建的先挂 pending，别让中断后的重试被当成 duplicate 吞掉）----
        badge, created = self.ctx.store.add_badge(
            uid=uid, counter=counter, token=token, url=url,
            device_id=self.device_id, backend=self.ctx.cfg.backend, status="pending",
        )

        # ---- 2.5 徽章库识别：从链接里的 sku 算出"这是什么"（纯本地查表，不联网）----
        try:
            from . import catalog as _catalog

            info = _catalog.describe(self.ctx.store, url)
            if info.get("sku") or info.get("def_name"):
                self.ctx.store.set_badge_catalog(
                    badge.id,
                    sku=info.get("sku", ""),
                    def_name=info.get("def_name", ""),
                    label=info.get("name", ""),
                    img=info.get("img", ""),
                )
                badge = self.ctx.store.get_badge(badge.id) or badge
                log.info("徽章识别 uid=%s → %s（sku=%s）",
                         uid, info.get("name") or info.get("def_name") or "未知",
                         info.get("sku"))
        except Exception as exc:  # noqa: BLE001 - 识别失败不影响入库
            log.warning("徽章识别失败 uid=%s: %s", uid, exc)

        if not created and badge.status != "pending":
            # 真的重复：同一枚章同一计数已处理完，不再打官方接口
            inject = InjectResult(
                True, "duplicate",
                f"这枚徽章已记录过（第 {badge.counter} 次），状态：{badge.status}",
                {"badge_id": badge.id, "counter": badge.counter, "status": badge.status},
            )
            frame = _ack("ok", inject.detail, inject=inject, record=badge.as_dict(), rid=rid)
            self.ctx.store.put_receipt(
                device_id=self.device_id, rid=rid, uid=uid, counter=counter, ok=True,
                action="duplicate", detail=inject.detail, payload=frame, badge_id=badge.id,
            )
            return [frame]

        # ---- 3. 原子抢占回执：同一 (device, rid) 只有一个执行者 ----
        if not self.ctx.store.claim_receipt(
            device_id=self.device_id, rid=rid, uid=uid, counter=counter, badge_id=badge.id
        ):
            other = self.ctx.store.get_receipt(self.device_id, rid)
            inject = InjectResult(
                False, "busy", "同一枚章正在处理中，稍等再重发这条即可",
                {"rid": rid, "owner_action": (other or {}).get("action")},
            )
            return [_ack("error", inject.detail, inject=inject, rid=rid)]

        # 抢到了：登记到进程内活跃集合，直到本函数退出（含取消）才移除。
        # 这样并发的同 rid 会被判 busy，而不是被误判成"上次中断"。
        self.ctx.inflight.add(rid)
        try:
            # ---- 4. 提交（带超时；取消也要把状态写清楚）----
            timeout = float(self.ctx.cfg.inject_timeout)
            try:
                inject = await asyncio.wait_for(self.ctx.backend.handle(badge), timeout=timeout)
            except asyncio.TimeoutError:
                log.warning("提交超时 %.1fs badge=%s", timeout, badge.id)
                inject = InjectResult(False, "timeout",
                                      f"提交超时（{timeout:.0f}s），官方可能已收到，请到面板核对",
                                      {"badge_id": badge.id})
            except asyncio.CancelledError:
                # 关服/Ctrl+C：徽章已入库但这次提交没做完。写成 interrupted，
                # 下次同 rid 会走"状态未知"分支，不会被误判成 duplicate。
                self.ctx.store.set_badge_status(badge.id, "interrupted", "服务关闭时提交中断")
                self.ctx.store.finish_receipt(
                    device_id=self.device_id, rid=rid, ok=False, action="uncertain",
                    detail="服务关闭时提交中断", payload={},
                )
                raise
            except Exception as exc:  # noqa: BLE001
                log.exception("提交后端异常")
                inject = InjectResult(False, "backend_error", str(exc), {"badge_id": badge.id})

            # ---- 5. 收尾 ----
            # 后端可能已经写过更精确的状态（比如 netease 的 "unconfirmed"：
            # 官方回了 ok、但库存里核对不到）。这里原本一律覆盖成 stored/failed，
            # 会把"未确认"抹平成"已入库" —— 又是一个"提示存了其实没存"的口子。
            # 所以后端给了 badge_status 就听后端的。
            self.ctx.store.set_badge_status(
                badge.id,
                str(inject.extra.get("badge_status") or ("stored" if inject.ok else "failed")),
                inject.detail or inject.action,
            )
            frame = _ack("ok" if inject.ok else "error", inject.detail or inject.action,
                         inject=inject, record=badge.as_dict(), rid=rid)
            self.ctx.store.finish_receipt(
                device_id=self.device_id, rid=rid, ok=inject.ok, action=inject.action,
                detail=inject.detail, payload=frame,
            )
            log.info("收章 uid=%s counter=%d rid=%s -> %s(%s)",
                     uid, counter, rid, inject.action, "ok" if inject.ok else "fail")
            return [frame]
        finally:
            self.ctx.inflight.discard(rid)

    # ---------------------------------------------------------------- 握手
    def hello(self) -> dict[str, Any]:
        cfg = self.ctx.cfg
        return {
            "type": "server_hello",
            "pubkey": self.box.public_key_base64,
            "pubkey_hex": self.box.public_key_hex,
            "fingerprint": self.box.fingerprint,
            "protocol": PROTOCOL,
            "host": cfg.advertise,
            "port": int(cfg.port),
            "name": "SkyHuiyu Bridge",
        }

