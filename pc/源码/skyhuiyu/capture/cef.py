"""清 CEF 的解析缓存 —— PAC 明明正确却一直走直连时的关键一步。

现象：即使 PAC 完全正确，CEF 仍会用上一次缓存的解析结果走直连。
把缓存目录清掉之后，CEF 立刻重新读取我们的 PAC。

实测日志对得上：清完缓存后 `UA: FeverGamePlatform` 请求
`/local-access/desktop.pac`，随即 8887 出现 4 条连接。

要注意的是**不能整目录删**：`User Data` 里还有 Cookies / Local Storage，
删了等于把启动器的登录态一起删掉（用户得重新扫码）。这里只删缓存类目录，
以及 Chromium 那两份把证书验证结果缓存住的文件：

    Default/Network/TransportSecurity      ← 证书验证结果（含 HSTS/pinning）
    Default/Network/Network Persistent State

这两份不清，即使换了证书也还是 `unknown ca`。
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

# 缓存类目录：删了不影响登录态
CACHE_DIRS: tuple[str, ...] = (
    "Default/Cache",
    "Default/Code Cache",
    "Default/GPUCache",
    "Default/DawnGraphiteCache",
    "Default/DawnWebGPUCache",
    "Default/Service Worker/CacheStorage",
    "Default/Service Worker/ScriptCache",
    "GrShaderCache",
    "ShaderCache",
    "GPUCache",
)

# 只删这两份文件（不是整个 Network 目录，Cookies 在别处）
CACHE_FILES: tuple[str, ...] = (
    "Default/Network/TransportSecurity",
    "Default/Network/Network Persistent State",
)


def default_roots() -> list[Path]:
    """浏览器/WebView 的数据目录。

    两个都要：启动器那套是 Chromium（`%LOCALAPPDATA%\\CEF\\User Data`），
    游戏登录页跑的是 **WebView2**（`%USERPROFILE%\\AppData\\LocalLow\\webviewdata\\2\\EBWebView`）。
    只清前者的时候日志会一直说"缓存为空或目录不存在"，而真正缓存着证书判定结果的
    是后者 —— 这也是之前"PAC 明明对却一直走直连"的原因之一。

    可用 SKYHUIYU_CEF_ROOTS 覆盖（分号分隔）。
    """
    override = os.environ.get("SKYHUIYU_CEF_ROOTS", "")
    if override:
        return [Path(p) for p in override.split(";") if p.strip()]
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or ""
    roots: list[Path] = []
    if base:
        roots.append(Path(base) / "CEF" / "User Data")
    roots.append(Path.home() / "AppData" / "Local" / "CEF" / "User Data")
    # WebView2：LocalLow\webviewdata\<n>\EBWebView
    local_low = os.environ.get("USERPROFILE", str(Path.home())) + r"\AppData\LocalLow\webviewdata"
    wv = Path(local_low)
    if wv.exists():
        for child in sorted(wv.iterdir()):
            eb = child / "EBWebView"
            if eb.is_dir():
                roots.append(eb)
    # 去重且保持顺序
    seen: set[str] = set()
    uniq: list[Path] = []
    for r in roots:
        key = str(r).lower()
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq


def purge(roots: list[Path] | None = None, *, keep_session: bool = True) -> list[dict[str, str]]:
    """清理缓存。返回每一步的结果，调用方负责打日志。

    `keep_session=True` 时只删缓存目录与那两份缓存文件（默认）。
    传 False 会连 `User Data` 整个删掉 —— 只有"别的办法都不行"时才用。
    """
    out: list[dict[str, str]] = []
    for root in (roots or default_roots()):
        if not root.exists():
            out.append({"path": str(root), "result": "absent"})
            continue
        if not keep_session:
            try:
                shutil.rmtree(root, ignore_errors=False)
                out.append({"path": str(root), "result": "removed (全目录)"})
            except OSError as exc:
                out.append({"path": str(root), "result": f"error: {exc}"})
            continue
        for rel in CACHE_DIRS:
            p = root / rel
            if not p.exists():
                continue
            try:
                shutil.rmtree(p)
                out.append({"path": str(p), "result": "removed"})
            except OSError as exc:
                out.append({"path": str(p), "result": f"error: {exc}"})
        for rel in CACHE_FILES:
            p = root / rel
            if not p.exists():
                continue
            try:
                p.unlink()
                out.append({"path": str(p), "result": "removed"})
            except OSError as exc:
                out.append({"path": str(p), "result": f"error: {exc}"})
    return out


def summary(results: list[dict[str, str]]) -> str:
    removed = [r for r in results if r["result"].startswith("removed")]
    errors = [r for r in results if r["result"].startswith("error")]
    if errors:
        return f"清缓存部分失败：{len(errors)} 项（{errors[0]['path']}）"
    if not removed:
        return "CEF 缓存为空或目录不存在"
    return f"CEF 缓存已清 {len(removed)} 项（{time.strftime('%H:%M:%S')}）"
