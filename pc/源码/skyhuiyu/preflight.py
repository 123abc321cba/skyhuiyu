"""启动预检：会话还能不能用，不能用就给一段**可以直接复制**的操作步骤。

为什么要在启动时做：官方对过期会话回 422 **空响应**，验章会白白消耗一次机会。
所以先用只读接口探一次，探不出来就立刻告诉用户，而不是让他点完才发现失败。

步骤里的路径全部按**当前运行的程序**生成（打包成 exe 后就是 exe 自己的路径），
用户复制粘贴即可，不需要自己找目录。
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import aiohttp

from .netease_api import NeteaseClient, Session

log = logging.getLogger("skyhuiyu.preflight")


def program_dir() -> Path:
    """当前程序所在目录（打包后是 exe 所在目录，未打包是项目根）。"""
    exe = Path(sys.executable)
    if exe.name.lower().endswith(".exe") and "python" not in exe.name.lower():
        return exe.parent
    return Path(__file__).resolve().parents[1]


def manual_steps(data_dir: Path) -> str:
    """给用户抄的步骤（含真实路径）。"""
    d = program_dir()
    bat = d / "抓取会话.bat"
    return (
        "会话无效，需要重新抓一次：\n"
        f"1) 关掉游戏\n"
        f"2) 双击这个文件（会自己申请管理员权限）：\n"
        f"   {bat}\n"
        f"3) 启动游戏，正常登录，进到主界面\n"
        f"4) 窗口里出现「★ 会话已抓取！」后，按 Ctrl+C 退出\n"
        f"   （退出时会自动还原系统代理；hosts 在抓到那一刻就已经撤了）\n"
        f"5) 回到本程序点「体检」确认可用，再点徽章「提交官方」\n"
        f"\n"
        f"注意：第 4 步之后不要重启游戏——重启会换新会话，刚抓到的就作废了。\n"
        f"日志：{Path(data_dir) / 'logs'}"
    )


async def check(cfg, store, http: aiohttp.ClientSession) -> dict[str, Any]:
    """返回 {ok, reason, detail, steps, session}。"""
    row = store.latest_session(cfg.account)
    if not row:
        reason = "no_session"
        detail = "还没有抓到过官方登录态"
        steps = manual_steps(cfg.data_path)
        log.warning("预检：%s", detail)
        return {"ok": False, "reason": reason, "detail": detail,
                "steps": steps, "session": None}

    sess = Session.from_row(row)
    if not sess.session2:
        reason = "no_session2"
        detail = "这份会话缺 session2（信封密钥），是很早抓的老会话"
        steps = manual_steps(cfg.data_path)
        log.warning("预检：%s（session id=%s）", detail, row.get("id"))
        return {"ok": False, "reason": reason, "detail": detail,
                "steps": steps, "session": None}

    client = NeteaseClient(http, sess)
    try:
        ok, why = await client.check()
    except Exception as exc:  # noqa: BLE001
        ok, why = False, str(exc)

    if ok:
        log.info("预检：会话有效（user_id=%s）", sess.user_id)
        return {"ok": True, "reason": "ok", "detail": "会话有效", "steps": "",
                "session": {"user_id": sess.user_id, "level_id": sess.level_id}}

    log.warning("预检：会话无效（%s）", why)
    return {"ok": False, "reason": why, "detail": f"会话已失效（{why}）",
            "steps": manual_steps(cfg.data_path), "session": None}
