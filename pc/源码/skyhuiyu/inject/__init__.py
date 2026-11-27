"""注入后端 —— 决定"收到徽章之后 PC 干什么"。

    local    只入库（默认，零配置，手机立刻能用）
    netease  入库 + 自己调官方 /account/star/verify（走本项目实现的信封协议）
    relay    入库 + 把验章与使用交给本机运行的外部验章服务
"""

from __future__ import annotations

from typing import Any

import aiohttp

from ..config import Config
from ..store import BadgeRow, Store
from .base import InjectResult, Backend
from .local import LocalBackend
from .netease import NeteaseBackend
from .relay import RelayBackend

__all__ = ["InjectResult", "Backend", "LocalBackend", "NeteaseBackend",
           "RelayBackend", "make_backend"]


def make_backend(cfg: Config, store: Store, http: aiohttp.ClientSession) -> Backend:
    name = (cfg.backend or "local").lower()
    if name == "netease":
        return NeteaseBackend(cfg, store, http)
    if name == "relay":
        return RelayBackend(cfg, store, http)
    return LocalBackend(cfg, store)


async def run_inject(backend: Backend, badge: BadgeRow) -> InjectResult:
    return await backend.handle(badge)
