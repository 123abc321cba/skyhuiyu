"""relay 后端的离线测试（不打真服务，用脚本化 transport）。

    python tests/test_relay.py
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp  # noqa: E402

from skyhuiyu.config import Config  # noqa: E402
from skyhuiyu.inject.relay import RelayBackend  # noqa: E402
from skyhuiyu.store import Store  # noqa: E402

OK = 0
BAD = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global OK, BAD
    if cond:
        OK += 1
        print(f"  PASS  {name}")
    else:
        BAD += 1
        print(f"  FAIL  {name}  {detail}")


class Fake(RelayBackend):
    def __init__(self, cfg, store, routes, raise_on=()):
        super().__init__(cfg, store, None)  # type: ignore[arg-type]
        self.routes = routes
        self.raise_on = set(raise_on)
        self.calls: list[tuple[str, str, dict | None]] = []

    async def _req(self, method, path, body=None):
        self.calls.append((method, path, body))
        key = f"{method} {path}"
        if key in self.raise_on:
            raise aiohttp.ClientError("boom")
        if key in self.routes:
            return self.routes[key]
        return self.routes.get(path, (200, {"ok": False}))


def run():
    tmp = tempfile.mkdtemp(prefix="skyhuiyu-relay-")
    try:
        store = Store(os.path.join(tmp, "t.db"))
        cfg = Config(data_dir=tmp, backend="relay")
        badge, _ = store.add_badge(
            uid="UID1", counter=3, token="TOK", url="https://sky.thatg.co/?s=x",
            device_id="d1", backend="relay",
        )

        print("\n[服务不在场]")
        be = Fake(cfg, store, {}, raise_on={"GET /status"})
        out = asyncio.run(be.handle(badge))
        check("relay_unreachable", out.action == "relay_unreachable", out.action)

        print("\n[没有账号]")
        be = Fake(cfg, store, {
            "GET /status": (200, {"ok": True, "data": {"active_account_id": ""}}),
            "GET /accounts": (200, {"ok": True, "data": {"accounts": []}}),
        })
        out = asyncio.run(be.handle(badge))
        check("no_account", out.action == "no_account", out.action)

        print("\n[存入成功]")
        be = Fake(cfg, store, {
            "GET /status": (200, {"ok": True, "data": {"active_account_id": "ACC"}}),
            "GET /accounts/ACC/badges": (200, {"ok": True, "data": {"badges": []}}),
            "POST /accounts/ACC/badges": (201, {"ok": True, "data": {"id": "B1"}}),
            "POST /accounts/ACC/badges/B1/store": (200, {"ok": True, "data": {
                "stored": True, "state": "stored", "reason_code": "verified"}}),
        })
        out = asyncio.run(be.handle(badge))
        check("ok=True", out.ok, out.as_dict())
        check("action=verified", out.action == "verified", out.action)
        check("状态 verified", store.get_badge(badge.id).status == "verified",
              store.get_badge(badge.id).status)
        store_calls = [c for c in be.calls if c[1].endswith("/store")]
        check("store 带 request_id",
              bool(store_calls) and isinstance(store_calls[0][2], dict)
              and bool(store_calls[0][2].get("request_id")),
              str(store_calls))

        print("\n[冷却：不冒充存入]")
        be = Fake(cfg, store, {
            "GET /status": (200, {"ok": True, "data": {"active_account_id": "ACC"}}),
            "GET /accounts/ACC/badges": (200, {"ok": True, "data": {"badges": [
                {"id": "B1", "url": badge.url}]}}),
            "POST /accounts/ACC/badges/B1/store": (200, {"ok": True, "data": {
                "stored": False, "state": "cooldown", "reason_code": "cooldown"}}),
        })
        out = asyncio.run(be.handle(badge))
        check("失败不冒充成功", out.ok is False, out.as_dict())
        check("状态 failed", store.get_badge(badge.id).status == "failed",
              store.get_badge(badge.id).status)

        print("\n[存入后自动使用]")
        cfg2 = Config(data_dir=tmp, backend="relay", auto_consume=True)
        be = Fake(cfg2, store, {
            "GET /status": (200, {"ok": True, "data": {"active_account_id": "ACC"}}),
            "GET /accounts/ACC/badges": (200, {"ok": True, "data": {"badges": [
                {"id": "B1", "url": badge.url}]}}),
            "POST /accounts/ACC/badges/B1/store": (200, {"ok": True, "data": {
                "stored": True, "state": "stored"}}),
            "GET /accounts/ACC/badge-status": (200, {"ok": True, "data": {
                "recent_items": [{"handle": "H1"}]}}),
            "POST /accounts/ACC/use": (200, {"ok": True, "data": {"used": True}}),
        })
        out = asyncio.run(be.handle(badge))
        check("use 被调用", any(c[1] == "/accounts/ACC/use" for c in be.calls), str(be.calls))
        check("状态 used", store.get_badge(badge.id).status == "used",
              store.get_badge(badge.id).status)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{OK}/{OK + BAD} 通过")
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
