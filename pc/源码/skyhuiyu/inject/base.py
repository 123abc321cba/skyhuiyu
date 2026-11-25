"""注入后端接口。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..store import BadgeRow


@dataclass
class InjectResult:
    ok: bool
    action: str
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        d = {"ok": self.ok, "action": self.action, "detail": self.detail}
        if self.extra:
            d.update(self.extra)
        return d


class Backend(Protocol):
    name: str

    async def handle(self, badge: BadgeRow) -> InjectResult:  # pragma: no cover - 协议
        ...
