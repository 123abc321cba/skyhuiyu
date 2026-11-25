"""hosts 管理 —— 只加 `ma75.update.netease.com`。

为什么只加这一个：
  · 账号域（`live-as-sky-merge` / `live-auth-sky-merge`）靠 PAC 走代理，不需要 hosts，
    这样不会波及那些不读 PAC 的进程（内嵌 OpenSSL 的遥测客户端会拒绝我们的证书，
    hosts 一劫持它就整条断，游戏报"无法连接"）；
  · **ma75 必须 hosts 到本机**：启动器启动第一件事是打更新检查，它不走 PAC 的那条
    路径（CEF 的 proxy_resolver 对启动阶段的 ma75 请求会先做 DNS），所以得让它在
    DNS 层就落到本机 443 监听上。实际也只需要这一个域名。
"""

from __future__ import annotations

import ctypes
import os
import shutil
from ctypes import wintypes
from pathlib import Path

from .ca import CaptureError

HOSTS_HOST = "ma75.update.netease.com"
HOSTS_IP = "127.0.0.1"
BEGIN = "# >>> SkyHuiyu Bridge (ma75) >>>"
END = "# <<< SkyHuiyu Bridge (ma75) <<<"


def flush_dns_cache() -> bool:
    """改完 hosts 必须刷 DNS 客户端缓存 —— 不刷就是"hosts 干净了但游戏还连不上"。

    写 hosts 文件**不会**通知 DNS Client 服务。改之前解析过的域名会继续沿用
    缓存里的旧记录直到 TTL 到期，于是：

        hosts 已经把 live-as-sky-merge.game.163.com 还原成真实解析了
        但缓存里还留着 127.0.0.1
        游戏查 DNS → 127.0.0.1 → 本机没人监听 → 报「网络连接失败 错误码130」

    2026-11-18 现场就是这么栽的：hosts 已干净、系统代理已还原，
    唯独缓存没刷，光遇一直 130。

    用 `DnsFlushResolverCache` 而不是起 `ipconfig /flushdns` 子进程：
    打包成 exe 后不想为一个 API 调用多一次进程创建（也少一次被杀软盯上的机会）。
    """
    if os.name != "nt":
        return False
    try:
        lib = ctypes.WinDLL("dnsapi", use_last_error=True)
        lib.DnsFlushResolverCache.restype = wintypes.BOOL
        lib.DnsFlushResolverCache.argtypes = []
        return bool(lib.DnsFlushResolverCache())
    except Exception:  # noqa: BLE001 - 刷缓存失败不该挡住主流程，但要能从返回值看出来
        return False



def default_hosts_path() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def _has_block(text: str) -> bool:
    return BEGIN in text and END in text


def _active_ma75_line(line: str) -> bool:
    s = line.strip()
    if not s or s.startswith("#"):
        return False
    parts = s.split()
    if len(parts) < 2:
        return False
    return parts[0] in (HOSTS_IP, "0.0.0.0", "::1") and HOSTS_HOST in parts[1:]


def _legacy_lines(text: str) -> list[str]:
    """没有我们标记、但把 ma75 指到本机的行。

    这些是历史实验脚本留下的（`pac_server.py` 那一轮直接往 hosts 里塞了一行）。
    我们的 443 一停，它们就把启动器的更新检查钉死在一个没人监听的端口上，
    表现就是"无法连接 请检查网络并重试"。所以清理时必须一起收掉。
    """
    inside = False
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s == BEGIN:
            inside = True
            continue
        if s == END:
            inside = False
            continue
        if not inside and _active_ma75_line(line):
            out.append(line)
    return out


def _strip_block(text: str) -> str:
    out: list[str] = []
    skipping = False
    for line in text.splitlines():
        if line.strip() == BEGIN:
            skipping = True
            continue
        if line.strip() == END:
            skipping = False
            continue
        if not skipping:
            out.append(line)
    # 去掉我们留下的连续空行
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + "\n"


def _strip_legacy(text: str) -> str:
    keep = [line for line in text.splitlines() if not _active_ma75_line(line)]
    while keep and not keep[-1].strip():
        keep.pop()
    return "\n".join(keep) + "\n"


def read_text(path: Path | None = None) -> str:
    p = path or default_hosts_path()
    try:
        return p.read_text("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def is_enabled(path: Path | None = None) -> bool:
    """hosts 里当前是否真的把 ma75 指到本机（带不带我们的标记都算）。"""
    return any(_active_ma75_line(line) for line in read_text(path).splitlines())


def _flush_if_real(path: Path) -> None:
    """只有动到**真** hosts 才刷缓存；测试传临时文件时刷它纯属噪声。"""
    try:
        if str(Path(path)).lower() == str(default_hosts_path()).lower():
            flush_dns_cache()
    except Exception:  # noqa: BLE001
        pass


def enable(path: Path | None = None, *, backup: bool = True) -> bool:
    """写入 ma75 → 127.0.0.1（带标记）。已存在返回 False。需要管理员。"""
    p = path or default_hosts_path()
    text = read_text(p)
    if is_enabled(p):
        return False
    body = _strip_block(text) if _has_block(text) else text
    body = _strip_legacy(body)
    block = f"{BEGIN}\n{HOSTS_IP} {HOSTS_HOST}\n{END}\n"
    if backup:
        bak = p.with_suffix(p.suffix + ".skyhuiyu-bak")
        if p.exists() and not bak.exists():
            shutil.copy2(p, bak)
    try:
        p.write_text(body + block, "utf-8")
    except PermissionError as exc:
        raise CaptureError("hosts_write_denied", f"没有管理员权限，写不了 {p}") from exc
    except OSError as exc:
        raise CaptureError("hosts_write_failed", f"{p}: {exc}") from exc
    # 让新映射立刻生效：不刷缓存的话，改之前解析过的域名仍走旧记录
    _flush_if_real(p)
    return True


def disable(path: Path | None = None) -> bool:
    """去掉 ma75 映射（我们那段 + 历史遗留的裸行）。没有可删的返回 False。"""
    p = path or default_hosts_path()
    text = read_text(p)
    if not _has_block(text) and not _legacy_lines(text):
        return False
    body = _strip_block(text) if _has_block(text) else text
    body = _strip_legacy(body)
    try:
        p.write_text(body, "utf-8")
    except PermissionError as exc:
        raise CaptureError("hosts_write_denied", f"没有管理员权限，写不了 {p}") from exc
    # ★ 这一步是 2026-11-18 那次「光遇 130」的根因缺口：
    #   hosts 已经还原，但 DNS 缓存里还留着 127.0.0.1，
    #   游戏继续往本机一个死端口连，报「网络连接失败 错误码130」。
    _flush_if_real(p)
    return True


def cleanup(path: Path | None = None) -> str:
    """把残留还原：有我们的段就删掉，并清掉备份文件。返回做了什么。"""
    p = path or default_hosts_path()
    done: list[str] = []
    if disable(p):
        done.append("hosts 段已删除")
    bak = p.with_suffix(p.suffix + ".skyhuiyu-bak")
    if bak.exists():
        try:
            bak.unlink()
            done.append("备份已删除")
        except OSError:
            pass
    return "；".join(done) or "无需清理"
