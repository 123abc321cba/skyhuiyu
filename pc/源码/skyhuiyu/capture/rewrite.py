"""在飞行中改写配置响应 —— 让账号请求落到本机代理。

为什么不在磁盘上改：启动器每次启动都会从
`ma75.update.netease.com/config/<版本>-PC-obt.json` 重新拉一份配置、盖到本地文件上，
再传给游戏。磁盘上的改写在第一次启动时就被冲掉了，白改。

真正的入口在响应里：配置 JSON 的 `ACCOUNT_DOMAIN` 字段决定游戏把 `/account/*`
发到哪里。我们在代理这一层把它换成本机端口，游戏就会把账号请求交到代理，
代理再转去真实域名，并抄一份响应（含 `authinfo`）。

改写时给响应打两个标注头（只用于本地排障，游戏不读）：

    x-sp-config-rewritten   ← 改过就给它打这个头
    x-sp-account-origin     ← 原值记在这个头里

被改的是 `ACCOUNT_DOMAIN` 字段，改写次数记在 `config_rewrites` 计数器里。

这样也解释了 PAC 里那条看着多余的规则：

    url.indexOf("http://127.0.0.1:8887/account/") === 0  → PROXY 127.0.0.1:8887

因为被改写后的账号地址就是 `http://127.0.0.1:8887`，需要 WinINet 把它也允许送进代理。
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .ca import CaptureError

DEFAULT_GAME_ROOT = Path(r"D:\FeverApps\sky")
TICKET_NAME = "liveAccountAuthInfo.bin"
PARKED_SUFFIX = ".skyhuiyu-parked"

# 改写时给响应加的标注头（只用于本地排障，游戏不读）
HDR_REWRITTEN = "x-sp-config-rewritten"
HDR_ORIGIN = "x-sp-account-origin"

_ACCOUNT_RE = re.compile(rb'("ACCOUNT_DOMAIN"\s*:\s*)"([^"]*)"')


def is_config_path(path: str) -> bool:
    """是不是客户端在取配置。

    实测的形态：`/config/0.16.8-421730-PC-obt.json`。判断只认这个特征，
    不按 `game_notice/` 之类的通知接口乱猜 —— 那些也走同一个域名。
    """
    p = path.split("?", 1)[0].lower()
    return "/config/" in p or p.endswith("-obt.json")


@dataclass
class RewriteResult:
    body: bytes
    changed: bool = False
    origin: str = ""

    @property
    def headers(self) -> dict[str, str]:
        if not self.changed:
            return {}
        return {HDR_REWRITTEN: "1", HDR_ORIGIN: self.origin}


def rewrite_config_body(body: bytes, local_base: str, *, path: str = "") -> RewriteResult:
    """把配置 JSON 里的 `ACCOUNT_DOMAIN` 换成 `local_base`（如 `http://127.0.0.1:8887`）。

    只动这一个字段：其余字节原样保留（客户端可能对格式敏感，重新 dump 会改掉
    缩进/转义/键序）。改完必须仍是合法 JSON，否则**整份放弃，原样返回** ——
    配置坏掉比抓不到更严重，游戏会直接起不来。
    """
    if not body or b"ACCOUNT_DOMAIN" not in body:
        return RewriteResult(body)
    m = _ACCOUNT_RE.search(body)
    if m is None:
        return RewriteResult(body)
    origin = m.group(2).decode("utf-8", "replace")
    if origin.rstrip("/") == local_base.rstrip("/"):
        return RewriteResult(body, changed=False, origin=origin)
    new = _ACCOUNT_RE.sub(
        lambda mm: mm.group(1) + b'"' + local_base.encode() + b'"', body, count=1)
    try:
        json.loads(new.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        # 宁可不改，也不能把配置写坏
        raise CaptureError("configuration_json_invalid",
                           f"{path or 'config'} 改写后不是合法 JSON: {exc}") from exc
    return RewriteResult(new, changed=True, origin=origin)


def apply(resp, local_base: str, *, path: str = "") -> RewriteResult:
    """就地改写一个 `httpio.Response`（443 透传与代理两条路都用它，只有一份实现）。

    改过就重建头：旧的 `Content-Length` / `Content-Encoding` / `ETag` 全部作废，
    换成那两个标注头。
    """
    rr = rewrite_config_body(getattr(resp, "body", b"") or b"", local_base, path=path)
    if not rr.changed:
        return rr
    resp.body = rr.body
    keep = [(k, v) for k, v in resp.headers
            if k.lower() not in ("content-length", "content-encoding", "etag")]
    keep.extend(rr.headers.items())
    resp.headers = keep
    return rr


def game_root(root: str | Path | None = None) -> Path:
    if root:
        return Path(root)
    env = os.environ.get("SKYHUIYU_GAME_ROOT", "")
    return Path(env) if env else DEFAULT_GAME_ROOT


def reset_disk_account_domain(root: str | Path | None = None) -> bool:
    """把**本地** config.json 里残留的本机地址改回官方域名。

    我们不再改磁盘配置（启动器每次都会重新拉一份），但上一版留下的
    `ACCOUNT_DOMAIN: http://127.0.0.1:8887` 可能还躺在文件里。代理一停它就是个
    死端口，游戏会登不上 —— 收工时顺手清掉，避免留下这种隐患。
    """
    path = game_root(root) / "data" / "config.json"
    if not path.exists():
        return False
    try:
        text = path.read_text("utf-8")
    except OSError:
        return False
    m = _ACCOUNT_RE.search(text.encode("utf-8"))
    if m is None:
        return False
    if not m.group(2).decode("utf-8", "replace").lower().startswith("http://127.0.0.1"):
        return False
    new = _ACCOUNT_RE.sub(
        lambda mm: mm.group(1) + b'"' + OFFICIAL_DOMAIN.encode() + b'"', text.encode("utf-8"), count=1)
    try:
        json.loads(new.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    path.write_text(new.decode("utf-8"), "utf-8")
    return True


OFFICIAL_DOMAIN = "https://live-as-sky-merge.game.163.com"


class TicketGate:
    """登录票据（`liveAccountAuthInfo.bin`）的让开与还回。

    有票 → 游戏直接连真实服务器、**不产生登录请求**，日志里就只剩 ma75 的更新检查。
    让开是改名而不是删除：抓完能还回去，用户不至于被登出后回不来。
    """

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = game_root(root)

    def find(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.rglob(TICKET_NAME) if p.is_file())

    def parked(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(p for p in self.root.rglob(TICKET_NAME + PARKED_SUFFIX) if p.is_file())

    def park(self) -> list[Path]:
        moved: list[Path] = []
        for p in self.find():
            target = p.with_name(p.name + PARKED_SUFFIX)
            try:
                if target.exists():
                    target.unlink()
                p.rename(target)
                moved.append(target)
            except OSError as exc:
                raise CaptureError("ticket_park_failed", f"{p}: {exc}") from exc
        return moved

    def restore(self) -> list[Path]:
        """还回去。游戏已经写了新票就不覆盖（旧票直接丢掉）。"""
        back: list[Path] = []
        for parked in self.parked():
            original = parked.with_name(parked.name[: -len(PARKED_SUFFIX)])
            try:
                if original.exists():
                    parked.unlink()
                    continue
                parked.rename(original)
                back.append(original)
            except OSError:
                continue
        return back
