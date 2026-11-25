"""local 后端：只入库，不打任何外部接口。

作用：手机那边立刻能跑通全链路（配对 → 上传 → 解密 → 入库），
不需要游戏账号、不需要抓包。徽章 URL 会原样存下来，之后随时可以
切到 netease 后端补做验证，URL 不丢。
"""

from __future__ import annotations

from ..config import Config
from ..store import BadgeRow, Store
from .base import InjectResult


class LocalBackend:
    name = "local"

    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store

    async def handle(self, badge: BadgeRow) -> InjectResult:
        # 同一 uid+token 的计数器回落要提醒（说明贴的是旧标签或数据被回滚）
        last = self.store.last_counter(badge.uid, badge.token)
        warn = ""
        if last is not None and badge.counter < last:
            warn = f"计数器回落（上次 {last}，本次 {badge.counter}）"
        return InjectResult(
            ok=True,
            action="stored",
            detail="已保存到本地库" + ("；" + warn if warn else ""),
            extra={"badge_id": badge.id, "counter": badge.counter, "warning": warn},
        )
