"""独立窗口（不是浏览器）。

用 WebView2 把已有的面板包进一个原生窗口：
- 复用现有面板（不重复造 UI）
- 有自己的标题栏/任务栏图标，不是浏览器标签页
- 关窗口 = 退出程序

为什么另起线程起服务：webview 的事件循环必须占主线程，
而 aiohttp 需要一个 asyncio loop。两者不能挤在一个线程里。

WebView2 运行时不存在的机器上自动降级成浏览器打开（并写日志说明原因），
这是环境差异，不是代码分支。
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time
import webbrowser
from pathlib import Path

log = logging.getLogger("skyhuiyu.desktop")

WINDOW_TITLE = "sky·徽遇"


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _serve_blocking(cfg, ready: threading.Event) -> None:
    """在后台线程里跑 aiohttp 服务。"""
    from .server import run

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run(cfg))
    except Exception as exc:  # noqa: BLE001
        log.exception("服务线程异常退出: %s", exc)
    finally:
        ready.set()
        loop.close()


def run_window(cfg) -> int:
    """起服务 + 独立窗口，直到窗口关闭。"""
    from .logging_setup import setup as setup_logging

    setup_logging(cfg.data_path, cfg.log_level)

    # 面板在窗口里，不需要再开系统浏览器
    cfg.open_browser = False
    url = f"http://127.0.0.1:{cfg.port}/"

    ready = threading.Event()
    thread = threading.Thread(target=_serve_blocking, args=(cfg, ready), daemon=True,
                              name="skyhuiyu-server")
    thread.start()

    # 等服务真的起来（最多 15s）；起不来就别开一个空窗口
    deadline = time.time() + 15
    while time.time() < deadline:
        if _port_open("127.0.0.1", cfg.port):
            break
        time.sleep(0.15)
    else:
        log.error("服务没起来，端口 %d 无响应；改用浏览器打开", cfg.port)
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
        ready.wait()

    try:
        import webview  # type: ignore
    except Exception as exc:  # noqa: BLE001
        log.warning("没有可用的 WebView2 运行时（%s），改用浏览器打开", exc)
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
        try:
            # 纯保活，等用户 Ctrl+C。这里不能写 `sleep(3600)` 循环 ——
            # 那个形状会被读成"每小时干一次什么事"，实际什么都不干。
            # 用 Event().wait() 明确表达"永久阻塞到被打断"。
            threading.Event().wait()
        except KeyboardInterrupt:
            return 0

    icon = Path(__file__).resolve().parent / "web" / "icon.png"
    window = webview.create_window(
        WINDOW_TITLE,
        url,
        width=1120,
        height=820,
        min_size=(880, 640),
        text_select=True,
    )
    log.info("独立窗口已打开：%s", url)
    try:
        webview.start(debug=False, private_mode=False)
    except TypeError:
        # 老版本 pywebview 没有 private_mode 参数
        webview.start(debug=False)
    log.info("窗口已关闭，退出")
    return 0
