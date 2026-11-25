"""系统代理下发 —— 走 WinINet（`InternetSetOption`），不写注册表键。

为什么用 API 而不是直接改注册表：
  · `InternetSetOption(PER_CONNECTION_OPTION)` 会连带刷新 WinINet 的解析缓存，
    手写注册表键不会，写完还得自己发 WM_SETTINGCHANGE + InternetSetOption(REFRESH)；
  · 能先 `InternetQueryOption` 拿到用户原本的配置，退出时原样还原。

**不动 WinHTTP。** 实测把 `netsh winhttp` reset 成 Direct 之后
游戏直接报"网络异常"—— 它有一部分请求走 WinHTTP，需要一个可用配置。
"""

from __future__ import annotations

import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .ca import CaptureError

# ---- WinINet 常量 ----
INTERNET_OPTION_PER_CONNECTION_OPTION = 75
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

INTERNET_PER_CONN_FLAGS = 1
INTERNET_PER_CONN_PROXY_SERVER = 2
INTERNET_PER_CONN_PROXY_BYPASS = 3
INTERNET_PER_CONN_AUTOCONFIG_URL = 4

PROXY_TYPE_DIRECT = 0x0001
PROXY_TYPE_PROXY = 0x0002
PROXY_TYPE_AUTO_PROXY_URL = 0x0004
PROXY_TYPE_AUTO_DETECT = 0x0008

WINHTTP_UNTOUCHED = "untouched"


class _Value(ctypes.Union):
    _fields_ = [
        ("dwValue", wintypes.DWORD),
        ("pszValue", ctypes.c_void_p),
        ("ftValue", wintypes.FILETIME),
    ]


class INTERNET_PER_CONN_OPTION(ctypes.Structure):
    _fields_ = [("dwOption", wintypes.DWORD), ("Value", _Value)]


class INTERNET_PER_CONN_OPTION_LIST(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("pszConnection", wintypes.LPWSTR),
        ("dwOptionCount", wintypes.DWORD),
        ("dwOptionError", wintypes.DWORD),
        ("pOptions", ctypes.POINTER(INTERNET_PER_CONN_OPTION)),
    ]


def _wininet():  # noqa: ANN202
    if os.name != "nt":
        raise CaptureError("proxy_enable_unsupported", "系统代理下发只实现 Windows")
    lib = ctypes.WinDLL("wininet", use_last_error=True)
    lib.InternetSetOptionW.restype = wintypes.BOOL
    lib.InternetSetOptionW.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                       ctypes.c_void_p, wintypes.DWORD]
    lib.InternetQueryOptionW.restype = wintypes.BOOL
    lib.InternetQueryOptionW.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    return lib


def _read_psz(ptr: int | None) -> str:
    return ctypes.wstring_at(ptr) if ptr else ""


def _free_psz(ptr: int | None) -> None:
    if ptr:
        try:
            ctypes.windll.kernel32.GlobalFree(ctypes.c_void_p(ptr))
        except Exception:  # noqa: BLE001
            pass


def query() -> dict[str, Any]:
    """读当前 LAN 连接的 WinINet 配置（PAC URL / 固定代理 / 直连）。"""
    lib = _wininet()
    opts = (INTERNET_PER_CONN_OPTION * 4)()
    for i, opt in enumerate((INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_PROXY_SERVER,
                             INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_AUTOCONFIG_URL)):
        opts[i].dwOption = opt
        opts[i].Value.pszValue = None

    lst = INTERNET_PER_CONN_OPTION_LIST()
    lst.dwSize = ctypes.sizeof(lst)
    lst.pszConnection = None  # LAN
    lst.dwOptionCount = 4
    lst.dwOptionError = 0
    lst.pOptions = ctypes.cast(opts, ctypes.POINTER(INTERNET_PER_CONN_OPTION))

    size = wintypes.DWORD(ctypes.sizeof(lst))
    if not lib.InternetQueryOptionW(None, INTERNET_OPTION_PER_CONNECTION_OPTION,
                                    ctypes.byref(lst), ctypes.byref(size)):
        raise CaptureError("proxy_query_failed", f"WinINet 查询失败 ({ctypes.get_last_error()})")

    flags = int(opts[0].Value.dwValue)
    pac = _read_psz(opts[3].Value.pszValue)
    server = _read_psz(opts[1].Value.pszValue)
    bypass = _read_psz(opts[2].Value.pszValue)
    # 只有 1..3 是 API 分配的字符串，必须 GlobalFree；第 0 项是 DWORD，
    # 把它当指针 free 会直接把堆搞坏（0xC0000374）。
    for o in opts[1:]:
        _free_psz(o.Value.pszValue)

    mode = "direct"
    if flags & PROXY_TYPE_AUTO_PROXY_URL:
        mode = "pac"
    elif flags & PROXY_TYPE_PROXY:
        mode = "fixed"
    elif flags & PROXY_TYPE_AUTO_DETECT:
        mode = "auto_detect"
    return {
        "flags": flags,
        "mode": mode,
        "pac_url": pac,
        "proxy_server": server,
        "proxy_bypass": bypass,
        "winhttp": WINHTTP_UNTOUCHED,
    }


def _apply(options: list[tuple[int, Any, bool]]) -> None:
    """options: [(dwOption, value, is_string)]，一次性下发并刷新。"""
    lib = _wininet()
    n = len(options)
    arr = (INTERNET_PER_CONN_OPTION * n)()
    # c_wchar_p 必须自己留引用：直接把临时对象 cast 成 c_void_p，表达式一结束
    # 缓冲区就被回收了，API 拿到的是野指针。
    keep: list[ctypes.c_wchar_p] = []
    for i, (opt_id, value, is_str) in enumerate(options):
        arr[i].dwOption = opt_id
        if is_str:
            w = ctypes.c_wchar_p(value)
            keep.append(w)
            arr[i].Value.pszValue = ctypes.cast(w, ctypes.c_void_p)
        else:
            arr[i].Value.dwValue = int(value)

    lst = INTERNET_PER_CONN_OPTION_LIST()
    lst.dwSize = ctypes.sizeof(lst)
    lst.pszConnection = None
    lst.dwOptionCount = n
    lst.dwOptionError = 0
    lst.pOptions = ctypes.cast(arr, ctypes.POINTER(INTERNET_PER_CONN_OPTION))

    ok = lib.InternetSetOptionW(None, INTERNET_OPTION_PER_CONNECTION_OPTION,
                                ctypes.byref(lst), ctypes.sizeof(lst))
    if not ok:
        raise CaptureError("proxy_enable_failed", f"InternetSetOption 失败 ({ctypes.get_last_error()})")
    if lst.dwOptionError:
        raise CaptureError("proxy_enable_failed",
                           f"第 {lst.dwOptionError} 个选项被拒 ({ctypes.get_last_error()})")
    # 刷新解析缓存 —— 少这两行，正在跑的进程还会按旧配置走（实测）
    lib.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    lib.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)


def enable_pac(pac_url: str) -> dict[str, Any]:
    """把系统代理设成 PAC。返回下发后的实际配置，便于核对。"""
    _apply([
        (INTERNET_PER_CONN_FLAGS, PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_DIRECT, False),
        (INTERNET_PER_CONN_AUTOCONFIG_URL, pac_url, True),
    ])
    return query()


def restore(state: dict[str, Any]) -> dict[str, Any]:
    """按快照还原。四个选项**全部**下发，即使是空串。

    为什么不能"有值才下发"：`InternetSetOption` 是逐项覆盖的，
    没下发的项 Windows 会**保留旧值**。只下发 FLAGS=DIRECT 而不下发
    AUTOCONFIG_URL，旧 PAC 串会原样留在 `DefaultConnectionSettings` 里 ——
    flags 说不启用，可那个 `http://127.0.0.1:8887/...pac` 还挂在那儿。
    某些客户端（CEF / WebView2 尤其）读的是那个串，不看 flags。

    2026-11-18 现场：每抓一次会话，收工后 `DefaultConnectionSettings`
    就多一条指向已死端口的 PAC。清掉一次，下次抓完又回来。
    """
    flags = int(state.get("flags", PROXY_TYPE_DIRECT))
    opts: list[tuple[int, Any, bool]] = [
        (INTERNET_PER_CONN_FLAGS, flags, False),
        (INTERNET_PER_CONN_PROXY_SERVER, str(state.get("proxy_server") or ""), True),
        (INTERNET_PER_CONN_PROXY_BYPASS, str(state.get("proxy_bypass") or ""), True),
        (INTERNET_PER_CONN_AUTOCONFIG_URL, str(state.get("pac_url") or ""), True),
    ]
    _apply(opts)
    return query()


class StateFile:
    """抓取栈的状态落盘。

    进程被杀之后系统代理还指着我们那个已经没了的端口 —— 那台机器就上不了网了。
    所以每次改动前后都写这个文件，下次启动第一件事就是读它并还原。
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text("utf-8"))
        except Exception:  # noqa: BLE001
            return {}

    def save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
