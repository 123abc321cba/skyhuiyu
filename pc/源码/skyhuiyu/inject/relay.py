"""relay 后端：入库 + 把验章/使用交给本机运行的外部验章服务。

外部服务的接口约定（本机 HTTP，默认 `http://127.0.0.1:62759`）：

    GET  /api/v1/status
    GET  /api/v1/accounts
    GET  /api/v1/accounts/{account}/badges
    POST /api/v1/accounts/{account}/badges
    POST /api/v1/accounts/{account}/badges/{badge}/store
    GET  /api/v1/accounts/{account}/badge-status
    POST /api/v1/accounts/{account}/use

服务的回包统一是 `{"ok": bool, "data": {...}}`。store 成功后会返回
`stored=true` 与最近可用的魔法句柄；`use` 需要显式 `confirmed:true`。

这个后端的定位：本机已经有能连官方、能同步游戏显示的外部服务时，
把「验章 / 使用魔法」这两步委托给它，本程序只负责收章、入库、留档。
服务不在场就明确报 `relay_unreachable` / `no_account`，不假装成功。
"""

from __future__ import annotations

import uuid
from typing import Any

import aiohttp

from ..config import Config
from ..store import BadgeRow, Store
from .base import InjectResult


class RelayBackend:
    name = "relay"

    def __init__(self, cfg: Config, store: Store, http: aiohttp.ClientSession) -> None:
        self.cfg = cfg
        self.store = store
        self.http = http
        self.base = (cfg.relay_url or "http://127.0.0.1:62759").rstrip("/")

    # ------------------------------------------------------------------ HTTP
    async def _req(self, method: str, path: str,
                   body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        url = self.base + "/api/v1" + path
        kwargs: dict[str, Any] = {"timeout": aiohttp.ClientTimeout(total=30)}
        if body is not None:
            kwargs["json"] = body
        async with self.http.request(method, url, **kwargs) as resp:
            try:
                data = await resp.json(content_type=None)
            except Exception:  # noqa: BLE001
                data = {}
            return resp.status, data if isinstance(data, dict) else {}

    @staticmethod
    def _data(node: dict[str, Any]) -> dict[str, Any]:
        inner = node.get("data")
        return inner if isinstance(inner, dict) else node

    async def _account(self) -> tuple[str, str]:
        """返回 (account_id, 错误码)。优先 active_account_id，其次第一个账号。"""
        try:
            st, node = await self._req("GET", "/status")
        except (aiohttp.ClientError, TimeoutError) as exc:
            return "", f"relay_unreachable: {exc}"
        if st != 200:
            return "", f"relay_unreachable: HTTP {st}"
        account = str(self._data(node).get("active_account_id") or "")
        if account:
            return account, ""
        try:
            st, node = await self._req("GET", "/accounts")
        except (aiohttp.ClientError, TimeoutError) as exc:
            return "", f"relay_unreachable: {exc}"
        if st != 200:
            return "", f"relay_unreachable: HTTP {st}"
        for item in self._data(node).get("accounts") or []:
            if isinstance(item, dict) and str(item.get("id") or ""):
                return str(item["id"]), ""
        return "", "no_account"

    async def _ensure_badge(self, account: str, badge: BadgeRow) -> tuple[str, str]:
        """在外部服务里找到或创建同 URL 的徽章，返回 (badge_id, 错误)。"""
        try:
            st, node = await self._req("GET", f"/accounts/{account}/badges")
        except (aiohttp.ClientError, TimeoutError):
            st, node = 0, {}
        if st == 200:
            for item in self._data(node).get("badges") or []:
                if isinstance(item, dict) and item.get("url") == badge.url:
                    return str(item.get("id") or ""), ""
        try:
            st, node = await self._req(
                "POST", f"/accounts/{account}/badges",
                {"category_id": "", "name": badge.label or badge.uid, "url": badge.url},
            )
        except (aiohttp.ClientError, TimeoutError) as exc:
            return "", f"relay_error: {exc}"
        payload = self._data(node)
        new_id = str(payload.get("id") or payload.get("badge_id") or "")
        if st not in (200, 201) or not new_id:
            return "", f"store_failed: 保存徽章失败 HTTP {st}"
        return new_id, ""

    async def _handle_from_status(self, account: str) -> str:
        try:
            st, node = await self._req("GET", f"/accounts/{account}/badge-status")
        except (aiohttp.ClientError, TimeoutError):
            return ""
        for item in self._data(node).get("recent_items") or []:
            if isinstance(item, dict) and item.get("handle"):
                return str(item["handle"])
        return ""

    # ------------------------------------------------------------------ 流程
    async def handle(self, badge: BadgeRow) -> InjectResult:
        request_id = str(uuid.uuid4())
        account, why = await self._account()
        if not account:
            detail = ("本机外部验章服务里没有可用账号：先在它的界面里完成一次登录抓取。"
                      if why == "no_account" else f"连不上外部验章服务（{self.base}）：{why}")
            self.store.add_injection(
                badge_id=badge.id, backend=self.name, request_id=request_id, url=badge.url,
                http_status=0, result=why.split(":")[0], detail=detail, response={"error": why},
            )
            return InjectResult(False, why.split(":")[0], detail,
                                {"badge_id": badge.id, "stored": True})

        relay_badge_id, why = await self._ensure_badge(account, badge)
        if not relay_badge_id:
            self.store.add_injection(
                badge_id=badge.id, backend=self.name, request_id=request_id, url=badge.url,
                http_status=0, result="store_failed", detail=why, response={"error": why},
            )
            return InjectResult(False, "store_failed", why, {"badge_id": badge.id})

        try:
            st, receipt = await self._req(
                "POST", f"/accounts/{account}/badges/{relay_badge_id}/store",
                {"request_id": request_id},
            )
        except (aiohttp.ClientError, TimeoutError) as exc:
            self.store.add_injection(
                badge_id=badge.id, backend=self.name, request_id=request_id, url=badge.url,
                http_status=0, result="relay_error", detail=str(exc), response={"error": str(exc)},
            )
            return InjectResult(False, "relay_error", f"验章请求失败：{exc}",
                                {"badge_id": badge.id, "request_id": request_id})

        rec = self._data(receipt)
        reason = str(rec.get("reason_code") or rec.get("state") or "")
        diagnostic = rec.get("diagnostic") or {}
        detail = ""
        if isinstance(diagnostic, dict):
            detail = str(diagnostic.get("message") or diagnostic.get("next_step") or "")

        self.store.add_injection(
            badge_id=badge.id, backend=self.name, request_id=request_id, url=badge.url,
            http_status=st, result=reason or f"http_{st}", detail=detail, response=receipt,
        )

        if st != 200 or receipt.get("ok") is False:
            self.store.set_badge_status(badge.id, "failed", reason or f"http_{st}")
            return InjectResult(False, reason or f"http_{st}", detail or "外部服务验章失败",
                                {"badge_id": badge.id, "request_id": request_id,
                                 "badge_status": "failed"})

        stored = bool(rec.get("stored"))
        used = bool(rec.get("used"))
        if stored:
            self.store.set_badge_status(badge.id, "verified", reason or "stored")
        elif used:
            self.store.set_badge_status(badge.id, "used", reason or "used")

        # 需要时接着用掉一个魔法句柄（外部服务会同步游戏显示）
        if self.cfg.auto_consume and stored:
            handle = str(rec.get("item_handle") or "") or await self._handle_from_status(account)
            if handle:
                try:
                    st2, used_node = await self._req(
                        "POST", f"/accounts/{account}/use",
                        {"confirmed": True, "item_handle": handle,
                         "request_id": str(uuid.uuid4())},
                    )
                    self.store.add_injection(
                        badge_id=badge.id, backend=self.name + ":use", request_id=request_id,
                        url=badge.url, http_status=st2,
                        result=str(self._data(used_node).get("state") or f"http_{st2}"),
                        detail="", response=used_node,
                    )
                    if self._data(used_node).get("used") is True:
                        used = True
                        self.store.set_badge_status(badge.id, "used", "used")
                except (aiohttp.ClientError, TimeoutError):
                    pass

        if not stored and not used:
            self.store.set_badge_status(badge.id, "failed", reason or "not_stored")
            return InjectResult(False, reason or "not_stored",
                                detail or "外部服务没有确认存入",
                                {"badge_id": badge.id, "request_id": request_id,
                                 "badge_status": "failed"})

        return InjectResult(
            True, reason or ("used" if used else "stored"),
            detail or ("已存入并同步游戏显示" if not used else "已存入并使用魔法"),
            {"badge_id": badge.id, "request_id": request_id,
             "badge_status": "used" if used else "verified", "used": used},
        )
