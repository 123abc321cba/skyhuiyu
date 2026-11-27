"""命令行入口。

    python -m skyhuiyu                 # 起服务（默认 0.0.0.0:8765，自动开面板）
    python -m skyhuiyu --port 9000     # 换端口
    python -m skyhuiyu --backend netease --account default
    python -m skyhuiyu --print-qr      # 终端里直接打 ASCII 二维码
    python -m skyhuiyu --check         # 只体检：密钥/数据库/会话/端口
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, lan_addresses


def _port_free(bind: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _ascii_qr(payload: str) -> str:
    import qrcode

    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    rows = []
    for row in qr.get_matrix():
        rows.append("".join("██" if cell else "  " for cell in row))
    return "\n".join(rows)


def _force_utf8_console() -> None:
    """中文 Windows 控制台默认 GBK，直接 print 中文会乱码。

    打包成 exe 后没有 `python -X utf8` 可用，所以这里自己把控制台切到 65001，
    再把 stdout/stderr 固定成 UTF-8。不是兜底，是把编码这一层定死。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:  # noqa: BLE001
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_console()
    ap = argparse.ArgumentParser(prog="skyhuiyu", description="sky·徽遇 PC 端")
    ap.add_argument("--bind", default=None, help="监听地址（默认取配置文件，首次 0.0.0.0）")
    ap.add_argument("--port", type=int, default=None, help="端口（默认 8765）")
    ap.add_argument("--data-dir", default=None, help="数据目录（数据库+配置）")
    ap.add_argument("--backend", choices=["local", "netease", "relay"], default=None,
                    help="收到徽章后干什么：local 只入库 / netease 打官方接口 / relay 交给本机外部服务")
    ap.add_argument("--account", default=None, help="netease 后端用哪个抓包账号")
    ap.add_argument("--advertise-host", default=None,
                    help="二维码里写死的 IP（多网卡/虚拟机网卡干扰时用）")
    ap.add_argument("--no-browser", action="store_true", help="不自动打开面板")
    ap.add_argument("--window", dest="window", action="store_true", default=None,
                    help="用独立窗口打开面板（默认行为）")
    ap.add_argument("--browser", dest="window", action="store_false",
                    help="改用系统浏览器打开面板")
    ap.add_argument("--log-level", default=None)
    ap.add_argument("--print-qr", action="store_true", help="打印 ASCII 二维码后退出")
    ap.add_argument("--badge-qr", type=int, default=None, metavar="ID",
                    help="把某条已入库徽章的 URL 渲染成二维码（给游戏扫码绑定用）")
    ap.add_argument("--check", action="store_true", help="体检模式")
    ap.add_argument("--capture", choices=["status", "enable", "disable"], default=None,
                    help="抓取栈：status 看状态 / enable 开 / disable 收工")
    ap.add_argument("--version", action="version", version=f"skyhuiyu {__version__}")
    args = ap.parse_args(argv)

    try:
        cfg = Config.load(Path(args.data_dir) / "config.json" if args.data_dir else None)
    except ConfigError as exc:
        # 配置坏了就明说，绝不带着默认值起来 —— 那样用户原来的后端/端口/账号
        # 会在下一次 save() 时被彻底覆盖，连痕迹都不剩。
        print(f"\n✘ {exc.detail}\n", file=sys.stderr)
        return 2
    if args.bind:
        cfg.bind = args.bind
    if args.port:
        cfg.port = args.port
    if args.backend:
        cfg.backend = args.backend
    if args.account:
        cfg.account = args.account
    if args.advertise_host:
        cfg.advertise_host = args.advertise_host
    if args.no_browser:
        cfg.open_browser = False
    if args.log_level:
        cfg.log_level = args.log_level
    cfg.save()

    if args.print_qr:
        from .crypto import CryptoBox, private_key_from_pem, new_private_key, private_key_to_pem
        from .qr import qr_payload
        from .store import Store

        store = Store(cfg.db_path)
        pem = store.meta_get("server_key_pem")
        key = private_key_from_pem(pem.encode()) if pem else new_private_key()
        if not pem:
            store.meta_set("server_key_pem", private_key_to_pem(key).decode())
        box = CryptoBox(private_key=key)
        payload = qr_payload(box.public_key_base64, cfg.advertise, cfg.port)
        print(f"指纹 {box.fingerprint}   地址 {cfg.advertise}:{cfg.port}")
        print(_ascii_qr(payload))
        print(payload)
        return 0

    if args.capture:
        from .capture.__main__ import main as capture_main

        return capture_main([args.capture])

    if args.badge_qr is not None:
        from .qr import qr_png
        from .store import Store

        store = Store(cfg.db_path)
        badge = store.get_badge(args.badge_qr)
        if badge is None:
            print(f"库里没有 id={args.badge_qr} 的徽章", file=sys.stderr)
            return 2
        out = cfg.data_path / f"badge-{badge.id}-qr.png"
        out.write_bytes(qr_png(badge.url, box_size=10, border=4))
        print(f"徽章 #{badge.id}  uid={badge.uid} counter={badge.counter}")
        print(f"URL      {badge.url}")
        print(f"二维码   {out}")
        print("\n用游戏内的扫码器扫这张图即可（PC 端 config.json 里 QRCodeScanner=1）。")
        print("扫完游戏会自己完成绑定，不需要我们调任何接口。")
        print()
        print(_ascii_qr(badge.url))
        return 0

    if args.check:
        from .capture import CaptureStack
        from .crypto import CryptoBox
        from .server import load_or_create_server_key
        from .store import Store

        store = Store(cfg.db_path)
        key = load_or_create_server_key(store)
        box = CryptoBox(private_key=key)
        sess = store.latest_session(cfg.account)
        print(f"版本        {__version__}")
        print(f"数据目录    {cfg.data_path}")
        print(f"数据库      {cfg.db_path}  ({cfg.db_path.stat().st_size} B)")
        print(f"服务器指纹  {box.fingerprint}")
        print(f"公钥        {box.public_key_base64}")
        print(f"监听        {cfg.bind}:{cfg.port}   可绑={_port_free(cfg.bind, cfg.port)}")
        print(f"广播地址    {cfg.advertise}   全部 {', '.join(lan_addresses())}")
        print(f"后端        {cfg.backend}")
        print(f"会话        {'有 user_id=' + str(sess.get('user_id')) if sess else '无（先跑 --capture enable）'}")
        print(f"徽章        {store.stats()}")
        st = CaptureStack(cfg, store).status()
        print(f"抓取栈      CA={'已装' if st['ca_installed'] else '未装'}  "
              f"代理:{st['proxy_port']}={'就绪' if st['local_proxy_ready'] else '未起'}  "
              f"PAC={'已下发' if st['proxy_owned'] else '未下发'}  "
              f"443={'就绪' if st['port443_ready'] else '未起'}  "
              f"hosts={'已加' if st['hosts_enabled'] else '未加'}")
        rew = st.get("config_rewrites", 0)
        print(f"配置改写    {rew} 次"
              + (f"   原值 {st['account_origin']} → {st['account_local_url']}"
                 if rew and st.get("account_origin") else "")
              + f"   票据让开={st.get('tickets_parked', 0)} 个")
        if st["recovery_error"]:
            print(f"            故障 {st['recovery_error']}")
        return 0

    from .server import run

    # 默认走独立窗口（WebView2），不是浏览器标签页。
    # --no-browser 明确表示"别开任何界面"，此时也不开窗口。
    use_window = (not args.no_browser) and (args.window is not False)
    try:
        if use_window:
            from .desktop import run_window

            return run_window(cfg)
    except KeyboardInterrupt:
        print("\n已停止")
        return 0

    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print("\n已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
