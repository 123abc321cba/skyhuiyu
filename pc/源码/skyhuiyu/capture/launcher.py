"""由本程序启动官方平台（零参数、工作目录 = exe 所在目录、输出丢弃）。

不给平台传任何代理配置：没有 `--proxy-server`，也不设 `HTTP_PROXY` /
`ALL_PROXY`。代理生效完全靠系统 PAC；多传一份反而可能让平台切到另一条
网络栈，登录流量就抓不到了。

那为什么非要由我们来启动？两个错误码把原因写明白了：

    official_pc_proxy_required     代理没起来就不让启动
    official_pc_launcher_missing   平台路径不存在

因为用户从桌面自己双击的那个实例，可能是在 PAC 下发**之前**就起来的，
它内部的连接池早就建立好了，后续请求不会再走 PAC。由我们启动能保证
"PAC 已经生效"和"平台首次联网"这两件事的先后顺序。

还有一个更实际的原因：这样我们才知道这个进程是我们拉起来的，
流量归属判断有据可依。

启动方式：用 `DETACHED_PROCESS` 让它彻底独立，抓取窗口关掉也不影响用户扫码。
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from pathlib import Path

log = logging.getLogger("skyhuiyu.capture.launcher")

# 平台主程序的可执行文件名，按可信度排序。
#
# 这台机器实测（2026-11-18）：
#   D:\Program Files\FeverGames\1.18.45.8\FeverGamesInstaller.exe   pid 15392  在跑
#   D:\Program Files\FeverGames\1.18.45.8\FeverGamesWeb.exe         pid 3956…   6 个 CEF 渲染进程
# `FeverGamesInstaller.exe` 虽然叫 Installer，实际就是用户点开的那个平台主界面；
# `FeverGamesWeb.exe` 是它的 CEF 子进程，单独启动没有意义。
PLATFORM_EXE_NAMES: tuple[str, ...] = (
    "FeverGamesInstaller.exe",
    "Fever.exe",
    "FeverGames.exe",
    "FeverGamesWeb.exe",
)

# 绝对不能当平台启动的东西。对应错误码 `official_pc_invalid_launcher`。
# 理由：sky.exe 是游戏本体，从它启动拿不到平台里的渠道登录入口；
# 而且游戏本体启动时读的是自己的登录票据，跟"平台里扫码"是两条路。
FORBIDDEN_EXE_NAMES: tuple[str, ...] = ("sky.exe",)

# 平台常见安装根，用 glob 展开。
_SEARCH_ROOTS: tuple[str, ...] = (
    r"D:\Program Files",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"D:\Program Files (x86)",
)


class LaunchError(RuntimeError):
    """平台启动失败。带一个稳定 code，方便上层翻译成用户看得懂的话。"""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def is_platform(path: Path | str) -> bool:
    """这个 exe 能不能当平台启动。"""
    p = Path(path)
    if p.name.lower() in FORBIDDEN_EXE_NAMES:
        return False
    return p.suffix.lower() == ".exe" and p.is_file()


def _version_key(name: str) -> tuple[int, ...]:
    """把目录名里的版本号变成可排序的 key，**降序**（新版排前面）。

    返回负数元组，这样在升序 sort 里数值越大反而越靠前。
    段数统一补到 4 段，避免 (1,18,45) 和 (1,18,45,8) 比较时长度不一致。
    """
    parts = [int(x) for x in re.findall(r"\d+", name)][:4]
    parts += [0] * (4 - len(parts))
    return tuple(-v for v in parts)


def _name_rank(name: str) -> int:
    try:
        return PLATFORM_EXE_NAMES.index(name)
    except ValueError:
        return 99


def find_candidates(extra: Path | str | None = None) -> list[Path]:
    """扫出可能作为平台的 exe。

    `extra` 是用户显式指定的路径，命中就排在最前面 —— 找不到时它是唯一希望。
    先按名字可信度排（Installer > Fever > Web），同名字下按版本号**从新到旧**。
    """
    found: list[Path] = []
    if extra:
        p = Path(extra)
        if p.is_file():
            found.append(p.resolve())
        else:
            raise LaunchError("official_pc_launcher_missing", f"指定的平台不存在：{p}")

    for root in _SEARCH_ROOTS:
        base = Path(root)
        if not base.is_dir():
            continue
        for name in PLATFORM_EXE_NAMES:
            # FeverGames\*\FeverGamesInstaller.exe
            for hit in base.glob(f"FeverGames/*/{name}"):
                if is_platform(hit):
                    found.append(hit.resolve())

    # 去重但保序：同一个 exe 可能被多个 root 命中
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in found:
        key = str(p).lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)

    # 显式指定的排最前，其余按 (名字可信度, 版本从新到旧)
    explicit = str(Path(extra).resolve()).lower() if extra else ""
    uniq.sort(key=lambda p: (
        0 if explicit and str(p).lower() == explicit else 1,
        _name_rank(p.name),
        _version_key(p.parent.name),
        str(p).lower(),
    ))
    return uniq


def _running_pids(exe_name: str) -> list[int]:
    """同名进程的 pid 列表。

    平台普遍是单实例的：已经在跑的时候，新起的那个会自己退掉。
    不先查一遍就会出现"API 说启动成功、实际上进程已经没了"这种谎报 ——
    跟徽章那句「魔法已存入」是同一类毛病，不能再来一次。

    用 Toolhelp32 快照而不是 `tasklist`：不拉子进程、不需要抓管道，
    在受限环境里也不会因为 stdio 被拦而失败。
    """
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (-1, 0xFFFFFFFF):
        return []
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    out: list[int] = []
    try:
        if not k32.Process32FirstW(snap, ctypes.byref(pe)):
            return []
        while True:
            if (pe.szExeFile or "").lower() == exe_name.lower():
                out.append(int(pe.th32ProcessID))
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                break
    finally:
        k32.CloseHandle(snap)
    return out


def launch(path: Path | str, *, wait_seconds: float = 1.0) -> dict[str, object]:
    """裸启平台，返回 {pid, exe, cwd, ...}。

    启动时加 `DETACHED_PROCESS`，让它不挂在抓取窗口下面。
    其余（零参数、工作目录 = exe 所在目录、输出丢弃）完全一致。

    平台是单实例的。已经在跑就直接告诉调用方 `already_running=True` 并给出
    现有 pid —— 这时候用户要做的就是切到那个窗口去扫码，不需要再起一个。
    """
    exe = Path(path)
    if exe.name.lower() in FORBIDDEN_EXE_NAMES:
        raise LaunchError(
            "official_pc_invalid_launcher",
            f"不能选 {exe.name} —— 要选平台程序（FeverGamesInstaller.exe / Fever.exe），"
            "不是游戏本体。渠道登录入口在平台里，游戏本体没有它。",
        )
    if not exe.is_file():
        raise LaunchError("official_pc_launcher_missing", f"文件不存在：{exe}")

    cwd = exe.parent

    # 先看看是不是已经在跑
    running = _running_pids(exe.name)
    if running:
        # 已经在跑的那个平台，是在我们下发 PAC **之前**启动的。
        # 它的网络栈（CEF 的 ProxyConfigService / 自己的 HTTP 客户端）早就初始化完，
        # 已建立的连接不会重建 —— 登录请求很可能一条都不经过我们的代理。
        # 用户从桌面自行启动的平台早于 PAC 下发，这里必须说清楚，
        # 不能报一句 already_running 就完事，那等于骗用户"能用了"。
        log.warning("平台已在运行 pid=%s，但它早于 PAC 下发启动，登录可能不走代理", running[0])
        return {"pid": running[0], "exe": str(exe), "cwd": str(cwd),
                "via": "existing", "already_running": True, "pids": running,
                "warning": "平台是这次抓取开始之前就启动的，它的网络连接早就建立了，"
                           "登录流量很可能不走代理。请先完全退出平台（托盘也要退），"
                           "再点「启动官方平台」，让它在我们接管网络之后再联网。"}

    # 0x00000008 DETACHED_PROCESS | 0x00000200 CREATE_NEW_PROCESS_GROUP
    flags = 0x00000008 | 0x00000200
    try:
        proc = subprocess.Popen(  # noqa: S603 - 路径来自用户显式选择
            [str(exe)],
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=flags,
        )
    except OSError as exc:
        # 平台有时要求管理员权限，Popen 会直接 EACCES。走 ShellExecuteEx 提权这一路。
        log.warning("Popen 启动平台失败(%s)，改用 ShellExecuteW 提权", exc)
        try:
            _shell_execute(exe, cwd)
        except OSError as exc2:
            raise LaunchError("official_pc_launch_failed",
                              f"两种方式都启动不了：{exc} / {exc2}") from exc2
        return {"pid": 0, "exe": str(exe), "cwd": str(cwd), "via": "shellexecute"}

    # 给平台一点时间把窗口拉起来，顺便观察有没有立刻崩掉或被单实例挡回来
    time.sleep(max(0.0, wait_seconds))
    code = proc.poll()
    if code is not None:
        # 起来了又立刻退出：要么撞上单实例，要么自己崩了。再查一遍谁在跑。
        still = _running_pids(exe.name)
        if still:
            log.info("平台由现有实例接管 pid=%s（新进程 exit=%s）", still[0], code)
            return {"pid": still[0], "exe": str(exe), "cwd": str(cwd),
                    "via": "existing", "already_running": True, "pids": still}
        raise LaunchError("official_pc_launch_failed",
                          f"平台启动后立刻退出，exit={code}，也没有其它实例在跑")

    log.info("平台已启动 pid=%s exe=%s", proc.pid, exe.name)
    return {"pid": proc.pid, "exe": str(exe), "cwd": str(cwd), "via": "popen",
            "already_running": False}


def _shell_execute(exe: Path, cwd: Path) -> None:
    """提权启动。只有 Popen 因权限失败时才走这里。"""
    import ctypes

    rc = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
        None, "open", str(exe), None, str(cwd), 1,
    )
    # ShellExecuteW 返回值 > 32 才算成功
    if rc <= 32:
        raise OSError(f"ShellExecuteW 返回 {rc}")


def pick(explicit: Path | str | None = None) -> Path:
    """挑一个平台 exe。挑不到就抛，不猜。"""
    cands = find_candidates(explicit)
    if not cands:
        raise LaunchError(
            "official_pc_launcher_missing",
            "没找到平台程序。请在面板里手动指定 FeverGamesInstaller.exe"
            "（形如 D:\\Program Files\\FeverGames\\<版本>\\FeverGamesInstaller.exe）。",
        )
    return cands[0]


if __name__ == "__main__":  # pragma: no cover - 手工排查用
    logging.basicConfig(level=logging.INFO)
    for c in find_candidates():
        print(c)
