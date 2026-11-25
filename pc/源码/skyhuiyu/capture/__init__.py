"""抓取栈 —— 让游戏自己走代理，从登录流量里取账号会话。

分层：

    ca.py        本地 CA（签发叶子证书 + 装 CurrentUser\\ROOT）
    pac.py       PAC 文本生成（与代理同端口）
    proxy.py     单端口 MITM 代理（代理 + PAC 同一个监听）
    sni443.py    443 监听（ma75 透传 + 配置改写）
    hostsfile.py hosts 管理（只加 ma75）
    wininet.py   系统代理下发 / 还原（InternetSetOption）
    cef.py       CEF 解析缓存清理
    authinfo.py  登录响应解析（只认 authinfo 键）
    stack.py     整条链的编排 + desktop.status / proxy.status 语义

入口：

    python -m skyhuiyu.capture status
    python -m skyhuiyu.capture enable      # 需要管理员（写 hosts）
    python -m skyhuiyu.capture disable
    python -m skyhuiyu.capture run         # enable 之后前台常驻
"""

from __future__ import annotations

from .ca import CaptureError, LocalCA
from .stack import CaptureEvent, CaptureStack

__all__ = ["CaptureStack", "CaptureEvent", "CaptureError", "LocalCA"]
