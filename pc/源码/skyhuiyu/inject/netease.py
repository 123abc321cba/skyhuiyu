"""netease 后端：入库 + 调官方 /account/star/verify。

流程：
    1. 从 sessions 表取最近一份抓到的登录态；
    2. POST /account/star/verify  {"uri": <徽章 URL>}
    3. 按词表判定：verified / verified_no_inventory / bound_to_user /
       bound_to_other / unbound / nfc_counter_update_failed / cooldown / ...
    4. 每次调用写一条 injections 记录（含 request_id 与原始回包），失败可人工对账；
    5. cfg.auto_consume=True 且只识别出 1 个可用句柄时，顺手 consume 一次。

没有会话 / 会话失效：返回 ok=False + action="no_session" / "session_invalid"，
徽章数据仍然已经入库 —— 手机端会看到失败原因，但数据不丢，可以在面板上补验证。
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import aiohttp

from ..config import Config
from ..netease_api import NeteaseClient, NeteaseError, Session, parse_handles
from ..store import BadgeRow, Store
from .base import InjectResult

OK_VERDICTS = {"verified", "verified_no_inventory", "bound_to_user"}
HARD_FAIL = {
    "bound_to_other": "这枚徽章绑在别的账号上",
    "unbound": "徽章未绑定成功",
    "nfc_counter_update_failed": "徽章 NFC 计数器更新失败（可能被别的设备刷过），请重新贴一次标签",
    "cooldown": "该魔法在冷却中",
    "identity_mismatch": "会话与账号不匹配",
    "invalid_fields": "请求字段被官方拒绝",
    "session_invalid": "登录态失效，请重新抓包",
    "session_expired": "登录态已过期（官方回空响应），重新抓一次会话即可",
    # 官方网络层处理失败 —— 结果未确认。官方口径是
    # "the outcome remains unconfirmed. Do not repeat automatically."
    "atomicity_failure": "官方网络层处理失败，这次结果未确认。别自动重发，先去游戏里看一眼",
    "already_bound": "徽章已经登记过了，去游戏里确认绑定状态即可",
}


class NeteaseBackend:
    name = "netease"

    def __init__(self, cfg: Config, store: Store, http: aiohttp.ClientSession) -> None:
        self.cfg = cfg
        self.store = store
        self.http = http

    async def _client(self) -> tuple[NeteaseClient | None, str]:
        row = self.store.latest_session(self.cfg.account)
        if not row:
            return None, "no_session"
        sess = Session.from_row(row)
        if not sess.is_usable():
            # 分开报：缺的是信封密钥，不是「没抓过会话」。轻量抓取只拿得到请求头，
            # 拿不到登录响应里的 session2，必须完整抓取（强制登录一次）。
            return None, "session_incomplete"
        return NeteaseClient(self.http, sess), ""

    async def _consume_once(
        self,
        client: NeteaseClient,
        handle: dict[str, Any],
        request_id: str,
        badge: BadgeRow,
    ) -> tuple[str, int, Any, str]:
        """调一次 `consume_item1` 并落一条 injection。

        这个接口**不可撤销**：一旦回落就真的把一个魔法用掉了。
        所以每次调用都必须留档，而且失败绝不自动重发（官方没有幂等语义）。
        """
        verdict, status, parsed, text = await client.consume(
            handle=str(handle.get("handle") or ""),
            consumable_id=handle.get("consumable_id") or 0,
        )
        self.store.add_injection(
            badge_id=badge.id, backend=self.name + ":consume", request_id=request_id,
            url=badge.url, http_status=status, result=verdict, detail=text[:400],
            response=parsed if isinstance(parsed, dict) else {"raw": text[:2000]},
        )
        return verdict, status, parsed, text

    async def handle(self, badge: BadgeRow) -> InjectResult:
        client, why = await self._client()
        if client is None:
            detail = ("还没有抓到官方登录态，徽章已入库"
                      if why == "no_session" else
                      "这份会话缺 session2（信封密钥）：轻量抓取只拿得到请求头，"
                      "拿不到登录响应。用完整抓取重新登录一次，徽章已入库")
            return InjectResult(
                ok=False,
                action=why or "no_session",
                detail=detail,
                extra={"badge_id": badge.id, "stored": True},
            )

        request_id = str(uuid.uuid4())

        # 先探一次会话是否还活着：官方对过期的会话回 422 空响应，
        # 而**验章本身会消耗官方的一次尝试**。所以宁可先花一个只读请求确认，
        # 也不要拿一次真实验章去撞一个必然失败的会话。
        try:
            alive, why = await client.check()
        except Exception as exc:  # noqa: BLE001
            alive, why = False, str(exc)
        if not alive:
            self.store.add_injection(
                badge_id=badge.id, backend=self.name, request_id=request_id, url=badge.url,
                http_status=0, result="session_expired",
                detail=f"预检失败：{why}", response={"preflight": why},
            )
            return InjectResult(
                False, "session_expired",
                "登录态已过期（预检未通过），重新抓一次会话再验章",
                {"badge_id": badge.id, "preflight": why},
            )

        try:
            outcome = await client.verify(badge.url)
        except NeteaseError as exc:
            self.store.add_injection(
                badge_id=badge.id, backend=self.name, request_id=request_id, url=badge.url,
                http_status=0, result=exc.code, detail=exc.detail, response={"error": exc.code},
            )
            return InjectResult(False, exc.code, exc.detail or "网络失败", {"badge_id": badge.id})
        except Exception as exc:  # noqa: BLE001
            # 官方接口没有"重试即安全"的语义：这里只记录，绝不自动重发
            self.store.add_injection(
                badge_id=badge.id, backend=self.name, request_id=request_id, url=badge.url,
                http_status=0, result="error", detail=str(exc), response={"error": str(exc)},
            )
            return InjectResult(False, "error", str(exc), {"badge_id": badge.id})

        self.store.add_injection(
            badge_id=badge.id, backend=self.name, request_id=request_id, url=badge.url,
            http_status=outcome.http_status, result=outcome.verdict,
            detail=outcome.detail, response=outcome.raw,
        )

        if outcome.verdict in OK_VERDICTS:
            # ——— 关键一步：验章回 ok ≠ 道具进了库存 ———
            # result=="ok" + bound_to_user 只说明"徽章 URL 通过校验并绑到账号"。
            # 以前这里直接把 ok 翻成「魔法已存入」发给手机，于是出现
            # "提示存好了、游戏里翻遍背包没有" —— 提示在撒谎，因为压根没查过库存。
            conf = await client.confirm_stored(outcome.star_tag_def_name)
            confirmed = conf.get("confirmed")

            row = self.store.latest_session(self.cfg.account)
            if row:
                self.store.mark_session_ok(int(row["id"]))

            # 核对结论单独落一条 injection：事后能查清"某次验章到底进没进账"
            self.store.add_injection(
                badge_id=badge.id, backend=self.name + ":confirm", request_id=request_id,
                url=badge.url, http_status=outcome.http_status,
                result=("inventory_ok" if confirmed is True
                        else "inventory_missing" if confirmed is False
                        else "inventory_unknown"),
                detail=str(conf.get("reason") or conf.get("def_name") or "")[:400],
                response=conf,
            )

            extra: dict[str, Any] = {
                "badge_id": badge.id,
                "verdict": outcome.verdict,
                "request_id": request_id,
                "def_name": outcome.star_tag_def_name,
                "confirmed": confirmed,
            }

            if confirmed is True:
                self.store.set_badge_status(badge.id, "verified", "official_ok+inventory")
                extra["badge_status"] = "verified"
                qty = conf.get("quantity")
                detail = (f"已存入官方账号（库存 {qty}）。"
                          "游戏不会实时刷新背包 —— 换场景或重登游戏才看得到。")
            elif confirmed is False:
                self.store.set_badge_status(badge.id, "unconfirmed",
                                            "official_ok_but_no_inventory")
                extra["badge_status"] = "unconfirmed"
                detail = ("官方回了成功，但库存里查不到这件。"
                          "重贴一次徽章补存；还不行就是官方没入账，别当成已存入。")
            else:
                self.store.set_badge_status(
                    badge.id, "unconfirmed", str(conf.get("reason") or "inventory_unknown"))
                extra["badge_status"] = "unconfirmed"
                detail = (f"官方回了成功，库存核对没做成（{conf.get('reason') or '原因未知'}）。"
                          "结论未知，别当成已存入。")

            if self.cfg.auto_consume and len(outcome.handles) == 1:
                verdict, status, parsed, text = await self._consume_once(
                    client, outcome.handles[0], request_id, badge)
                # auto_store：用的时候发现没货，就回去再存一次补货，然后立刻重试。
                # 事件流实证（seq 125→129）：
                #   use_started → out_of_stock → auto_store_started → store_succeeded → use_succeeded
                if verdict == "insufficient_consumables" and self.cfg.auto_store:
                    again = await client.verify(badge.url)
                    self.store.add_injection(
                        badge_id=badge.id, backend=self.name + ":autostore",
                        request_id=request_id, url=badge.url,
                        http_status=again.http_status, result=again.verdict,
                        detail="库存不足 → 自动重存补货", response=again.raw,
                    )
                    if again.verdict in OK_VERDICTS:
                        verdict, status, parsed, text = await self._consume_once(
                            client, outcome.handles[0], request_id, badge)
                        detail += "；库存不足，已自动补存并重试"
                    else:
                        detail += f"；库存不足，自动补存没成功（{again.verdict}）"
                extra["consumed"] = verdict
                detail += f"；已使用：{verdict}"
                if verdict == "used":
                    self.store.set_badge_status(badge.id, "used", verdict)
                    extra["badge_status"] = "used"
            return InjectResult(True, outcome.verdict, detail, extra)

        if outcome.verdict == "cooldown":
            self.store.set_badge_status(badge.id, "cooldown", "consumable_on_cooldown")
            # ok=True 但状态是 cooldown：不塞 badge_status 就会被 session 写成 "stored"，
            # 用户看到"已入库"，还以为冷却已经过去了。
            return InjectResult(True, "cooldown", "魔法在冷却中（不是失败，过一会再用）",
                                {"badge_id": badge.id, "verdict": outcome.verdict,
                                 "badge_status": "cooldown"})
        if outcome.verdict == "nfc_counter_update_failed":
            self.store.set_badge_status(badge.id, "retry_tag", outcome.verdict)
            return InjectResult(
                False, "nfc_counter_update_failed",
                HARD_FAIL["nfc_counter_update_failed"],
                {"badge_id": badge.id, "verdict": outcome.verdict,
                 "badge_status": "retry_tag", "next_step": "refresh_badge"},
            )

        self.store.set_badge_status(badge.id, "failed", outcome.verdict)
        return InjectResult(
            False,
            outcome.verdict,
            HARD_FAIL.get(outcome.verdict) or outcome.detail or "官方返回未识别结果",
            {"badge_id": badge.id, "verdict": outcome.verdict,
             "badge_status": "failed", "http_status": outcome.http_status},
        )

    # ------------------------------------------------------------ 使用魔法
    async def use_badge(self, badge: BadgeRow) -> InjectResult:
        """把上一次验章回执里的魔法用掉（consume_item1）。

        验章只负责把魔法存进账号；「用掉」是另一次操作：官方回执里的
        `get_consumables` 带可用句柄，`consume_item1` 用它触发效果。
        同一枚徽章通常只对应一个魔法，识别出多个就拒绝猜。
        """
        client, why = await self._client()
        if client is None:
            return InjectResult(False, why or "no_session",
                                "会话不完整，先完整抓取一次登录", {"badge_id": badge.id})

        last: tuple[dict[str, Any], dict[str, Any]] | None = None
        for inj in self.store.list_injections(badge.id, limit=30):
            if inj.get("result") not in OK_VERDICTS:
                continue
            try:
                resp = json.loads(inj.get("response") or "{}")
            except Exception:  # noqa: BLE001
                continue
            if isinstance(resp, dict) and resp.get("get_consumables"):
                last = (inj, resp)
                break
        if last is None:
            return InjectResult(False, "no_magic",
                                "没有可用的魔法记录，先提交一次验章",
                                {"badge_id": badge.id})

        _inj, resp = last
        handles = parse_handles(resp)
        if len(handles) != 1:
            return InjectResult(
                False, "magic_selection_required",
                f"这次回执里有 {len(handles)} 个可用魔法，无法确定用哪一个",
                {"badge_id": badge.id, "handles": handles[:5]},
            )
        handle = handles[0]
        request_id = str(uuid.uuid4())
        try:
            verdict, status, parsed, text = await client.consume(
                handle=str(handle.get("handle") or ""),
                consumable_id=handle.get("consumable_id") or 0,
            )
        except NeteaseError as exc:
            return InjectResult(False, exc.code, exc.detail or "网络失败",
                                {"badge_id": badge.id})
        self.store.add_injection(
            badge_id=badge.id, backend=self.name + ":use", request_id=request_id,
            url=badge.url, http_status=status, result=verdict, detail=text[:400],
            response=parsed if isinstance(parsed, dict) else {"raw": text[:2000]},
        )
        if verdict in ("used", "success"):
            self.store.set_badge_status(badge.id, "used", "used")
            return InjectResult(True, "used", "魔法已使用",
                                {"badge_id": badge.id, "verdict": verdict,
                                 "badge_status": "used"})
        if verdict == "cooldown":
            self.store.set_badge_status(badge.id, "cooldown", verdict)
            return InjectResult(False, "cooldown", "魔法在冷却中，过一会再试",
                                {"badge_id": badge.id, "verdict": verdict,
                                 "badge_status": "cooldown"})
        detail = {
            "insufficient_consumables": "库存不足，先重新贴一次徽章补存",
            "used_no_inventory": "官方说用了，但库存里没有这件",
            "invalid_consumable_def": "官方不认这个魔法定义",
            "result_conflict": "官方回执冲突，结果未确认",
        }.get(verdict, text[:200] or "官方未接受使用请求")
        self.store.set_badge_status(badge.id, "verified", f"use_failed:{verdict}")
        return InjectResult(False, verdict, detail,
                            {"badge_id": badge.id, "verdict": verdict})

