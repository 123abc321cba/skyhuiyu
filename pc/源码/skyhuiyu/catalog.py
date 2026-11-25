"""徽章名称识别 + 徽章库。

分三层，全部来自官方数据，不内置任何硬编码名字：

1. 徽章链接里的 `s=` 是一段 base64，解出来是 `n=…&s=…&sk=SKY-PL-ST-CRE-MF&t=…&u=…`
   → `sk` 就是这枚徽章的 **SKU**。
2. `/account/star/get` 返回 `get_star_tag_defs`：每个 SKU 对应一个 `consumable_name`。
3. `/account/consumable/get_consumable_defs` 返回道具定义：id / name / icon / 分类 / 冷却。

于是「这枚章是什么」不需要验章就能算出来：
    sku → consumable_name → 道具定义 → 显示名 + 图标
验章响应里的 `star_tag_def_name` 也是同一个 `consumable_name`，两条路能对上。
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

log = logging.getLogger("skyhuiyu.catalog")


def parse_sku(url: str) -> str:
    """从徽章链接里取 SKU（s= 参数里那段 base64 的 sk 字段）。"""
    try:
        q = parse_qs(urlparse(url).query)
        raw = (q.get("s") or [""])[0]
        if not raw:
            return ""
        pad = "=" * (-len(raw) % 4)
        decoded = base64.b64decode(raw + pad).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""
    for part in decoded.split("&"):
        if part.startswith("sk="):
            return part[3:].strip()
    return ""


def human_name(def_name: str) -> str:
    """把 `outfit_prop_jumbo_mischief_cat` 这种 id 变成可读的名字。

    官方定义里没有中文名时用这个：去掉常见前缀，把下划线换成空格。
    """
    if not def_name:
        return ""
    s = def_name
    for prefix in ("outfit_prop_", "outfit_", "prop_", "spell_", "consumable_"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    return s.replace("_", " ").strip()


async def refresh(cfg, store, http, session) -> dict[str, Any]:
    """拉官方定义表并入库。会话无效时静默跳过（预检那边已经报过）。"""
    from .netease_api import NeteaseClient

    client = NeteaseClient(http, session)
    out = {"defs": 0, "tags": 0, "error": ""}

    try:
        status, parsed, _text = await client.consumable_defs()
        if status == 200 and isinstance(parsed, dict):
            items = parsed.get("get_consumable_defs") or []
            out["defs"] = store.upsert_consumable_defs(items)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"道具定义: {exc}"
        log.warning("拉取道具定义失败：%s", exc)

    try:
        status, parsed, _text = await client.star_tags()
        if status == 200 and isinstance(parsed, dict):
            tags = parsed.get("get_star_tag_defs") or []
            out["tags"] = store.upsert_star_tags(tags)
    except Exception as exc:  # noqa: BLE001
        out["error"] += f" 星章定义: {exc}"
        log.warning("拉取星章定义失败：%s", exc)

    if out["defs"] or out["tags"]:
        log.info("徽章库已更新：道具定义 %d 条，星章定义 %d 条", out["defs"], out["tags"])
        out["labeled"] = backfill(store)
    return out


def backfill(store) -> int:
    """给库里还没名字的徽章补上名称（老数据升级用）。"""
    n = 0
    try:
        for badge in store.list_badges(limit=2000, dedupe=False):
            if badge.label and badge.def_name:
                continue
            info = describe(store, badge.url)
            if not (info["sku"] or info["def_name"]):
                continue
            store.set_badge_catalog(
                badge.id,
                sku=info["sku"],
                def_name=info["def_name"],
                label=info["name"],
                img=info.get("img", ""),
            )
            n += 1
    except Exception as exc:  # noqa: BLE001
        log.warning("补名称失败：%s", exc)
    if n:
        log.info("已为 %d 枚历史徽章补上名称", n)
    return n


def builtin_path() -> Path:
    return Path(__file__).resolve().parent / "web" / "catalog" / "badges.json"


def import_builtin(store) -> int:
    """把内置徽章库（SKU/中文名/图标 id/冷却/效果）导入本机库。

    数据来源是官方目录的本地缓存（115 条），随程序打包，不需要联网。
    """
    p = builtin_path()
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text("utf-8"))
        items = data.get("badges") or []
        n = store.import_badge_catalog(items)
        if n:
            log.info("内置徽章库已导入 %d 条", n)
        return n
    except Exception as exc:  # noqa: BLE001
        log.warning("导入内置徽章库失败：%s", exc)
        return 0


def icon_path(img: str) -> Path:
    return Path(__file__).resolve().parent / "web" / "catalog" / "icons" / f"{img}.png"


def describe(store, url: str) -> dict[str, str]:
    """给一枚徽章算出 (sku, def_name, 显示名, 图标, 冷却, 说明)。

    优先级：
      1. 内置徽章库（SKU 精确命中）—— 有中文名、图标、冷却、效果说明
      2. 官方道具定义 + 星章定义表 —— 只有英文 id
      3. SKU 原样 —— 保证永远不为空
    """
    sku = parse_sku(url)
    entry = store.badge_catalog_entry(sku) if sku else None
    def_name = store.consumable_for_sku(sku) if sku else ""

    if entry and entry.get("name"):
        return {
            "sku": sku,
            "def_name": def_name,
            "name": entry["name"],
            "img": entry.get("img") or "",
            "cooldown_ms": str(entry.get("cooldown_ms") or 0),
            "desc": entry.get("descr") or "",
            "effect": entry.get("effect") or "",
            "source": "builtin",
        }

    info = store.consumable_def(def_name) if def_name else None
    name = (info or {}).get("name") or ""
    return {
        "sku": sku,
        "def_name": def_name,
        "name": name or human_name(def_name) or sku,
        "img": "",
        "cooldown_ms": "",
        "desc": "",
        "effect": "",
        "source": "official" if info else ("sku" if sku else ""),
    }


