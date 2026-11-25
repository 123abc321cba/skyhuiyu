"""抓取栈命令行。

    python -m skyhuiyu.capture status [--json]
    python -m skyhuiyu.capture enable [--no-purge-cef]    # 开 + 前台常驻
    python -m skyhuiyu.capture disable [--uninstall-ca]
    python -m skyhuiyu.capture recover                    # 只做崩溃自愈

`enable` 会一直占着前台 —— 代理必须有个活着的进程，这是它不能"开完就退"的原因。
不想占终端就在面板上点（`/api/capture`），抓取栈会挂在徽章服务那个进程里。

`enable` 要写 hosts，必须管理员。退出码：0 成功，2 明确失败（带 error_code）。
"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import sys
import time

from ..config import Config
from ..logging_setup import setup as _setup_logging
from ..store import Store
from .ca import CaptureError
from .stack import CaptureStack


def _stack(args: argparse.Namespace) -> CaptureStack:
    cfg = Config.load()
    if getattr(args, "proxy_port", None):
        cfg.proxy_port = args.proxy_port
    # 抓取栈也必须落日志文件。以前这里什么都不配，`skyhuiyu.capture.*` 的输出
    # 只进控制台，窗口一滚就没了 —— 抓到会话了用户也不知道。
    _setup_logging(cfg.data_path)
    store = Store(cfg.db_path)
    return CaptureStack(cfg, store)


def _print_status(st: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(st, ensure_ascii=False, indent=2))
        return
    def yn(v: object) -> str:
        return "✅" if v else "❌"

    print(f"平台支持        {yn(st['supported'])}")
    print(f"CA 已装         {yn(st['ca_installed'])}  （{st['ca_scope']}）")
    if st.get("ca_sha256"):
        print(f"CA sha256       {st['ca_sha256']}")
    print(f"代理就绪        {yn(st['local_proxy_ready'])}  127.0.0.1:{st['proxy_port']}")
    print(f"PAC URL         {st['pac_url']}")
    print(f"PAC 已下发      {yn(st['proxy_owned'])}   （WinINet mode={st['wininet'].get('mode', '?')}）")
    print(f"443 透传        {yn(st['port443_ready'])}")
    print(f"hosts(ma75)     {yn(st['hosts_enabled'])}")
    rewrites = st.get("config_rewrites", 0)
    origin = st.get("account_origin") or ""
    print(f"配置改写        {rewrites} 次"
          + (f"   原值 {origin} → {st['account_local_url']}" if rewrites and origin else ""))
    print(f"登录票据        {'已让开 ' + str(st.get('tickets_parked')) + ' 个' if st.get('tickets_parked') else '未让开（游戏已登录时抓不到）'}")
    print(f"流量/抓取       {st['proxy_flows']} / {st['proxy_captured']}")
    if st.get("recovery_error"):
        print(f"故障            {st['recovery_error']}")
    if st.get("last_error"):
        print(f"最近错误        {st['last_error']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="skyhuiyu.capture",
                                 description="抓取栈：装 CA / 起代理 / 下发 PAC / 等登录")
    ap.add_argument("cmd", choices=["status", "enable", "disable", "recover",
                                    "install-ca", "uninstall-ca"])
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--no-purge-cef", action="store_true", help="不清 CEF 解析缓存")
    ap.add_argument("--keep-ticket", action="store_true",
                    help="不让开登录票据（游戏已登录时用它会直接跳过登录，抓不到东西）")
    ap.add_argument("--uninstall-ca", action="store_true", help="同时把 CA 从 CurrentUser\\ROOT 删掉")
    ap.add_argument("--proxy-port", type=int, default=None, help="代理端口（默认 8887）")
    ap.add_argument("--light", action="store_true",
                    help="轻量模式：不动 hosts、不开 443、不清 CEF 缓存、不让开票据、"
                         "不改 ACCOUNT_DOMAIN。靠启动官方平台 + 在平台里扫码登录来抓会话"
                         "（退出后机器上什么都不留）")
    ap.add_argument("--launch", action="store_true",
                    help="enable 之后由我们启动官方平台："
                         "零参数、工作目录=exe 所在目录、输出丢弃")
    ap.add_argument("--platform", default=None, metavar="EXE",
                    help="平台 exe 路径。不给就自动扫 "
                         "FeverGames/*/FeverGamesInstaller.exe（新版优先）")
    args = ap.parse_args(argv)

    stack = _stack(args)
    try:
        if args.cmd == "status":
            _print_status(stack.status(), args.json)
            return 0

        if args.cmd == "recover":
            msg = stack.recover()
            print(msg or "无需恢复")
            return 0

        if args.cmd == "install-ca":
            stack.ca.load_or_create()
            if stack.ca.is_installed():
                print("CA 已经装好了（CurrentUser\\ROOT），不会重复装，也不会再弹窗。")
                print(f"  指纹 sha256 {stack.ca.sha256}")
                return 0
            print("现在会弹一次 Windows「安全警告」（标题栏就是这么写的）：")
            print("  颁发者：Sky Huiyu Local Proxy CA")
            print("  作用：给 live-as-sky-merge.game.163.com 等域名签本机证书")
            print("  → 点「是(Y)」。只想这一次，装完不会再来。")
            stack.ca.install()
            print("装好了。" if stack.ca.is_installed() else "没装上，再看一眼弹窗是不是被点了「否」。")
            return 0 if stack.ca.is_installed() else 2

        if args.cmd == "uninstall-ca":
            removed = stack.ca.uninstall()
            print("已从 CurrentUser\\ROOT 删除" if removed else "本来就没装")
            return 0

        if args.cmd == "disable":
            out = stack.disable(uninstall_ca=args.uninstall_ca)
            if args.json:
                print(json.dumps(out, ensure_ascii=False, indent=2))
            else:
                print("；".join(out["done"]))
            return 0

        purge = not args.no_purge_cef
        light = bool(args.light)
        st = stack.enable(purge_cef=purge, park_ticket=not args.keep_ticket,
                          hijack_ma75=not light)
        _print_status(st, args.json)

        if light:
            print("\n下一步：在官方平台里扫码登录（渠道/第三方账号入口）。", file=sys.stderr)
            print("轻量模式没有劫持 ma75、没有动票据，也不改游戏配置 —— "
                  "游戏自己有缓存票据时不会重登，所以必须走平台登录。", file=sys.stderr)
            print("本进程仍要替平台提供代理，别关；Ctrl+C 会还原系统代理。", file=sys.stderr)
        else:
            print("\n下一步：启动启动器 → 扫码登录（票据已让开，必须重新登录）。", file=sys.stderr)
            print("抓到会打印「★ 会话已入库」，那一刻 hosts 会自动撤掉（劫持只为逼出这一次登录）。",
                  file=sys.stderr)
            print("本进程仍要替游戏提供代理，别关；"
                  "Ctrl+C 会还原系统代理、ACCOUNT_DOMAIN 与票据。", file=sys.stderr)

        # 由我们启动平台 —— 必须先让 PAC 生效再拉起进程，否则平台已有的连接池
        # 不会再走代理（错误码 official_pc_proxy_required 拦的就是这个）。
        if args.launch:
            from .launcher import LaunchError, launch as launch_platform, pick
            try:
                exe = pick(args.platform)
                print(f"\n启动官方平台：{exe}", file=sys.stderr)
                info = launch_platform(exe, wait_seconds=1.5)
                print(f"  已启动 pid={info['pid']} via={info['via']}"
                      f"  cwd={info['cwd']}", file=sys.stderr)
                logging.getLogger("skyhuiyu.capture").info(
                    "平台已启动 pid=%s exe=%s via=%s", info["pid"], exe, info["via"])
            except LaunchError as exc:
                print(f"  ! 平台启动失败 {exc.code}: {exc.detail}", file=sys.stderr)
                print("  平台没起来也不影响抓取 —— 你自己打开平台继续扫码即可。",
                      file=sys.stderr)

        _wait(stack, light=light)
        return 0
    except CaptureError as exc:
        print(f"失败 {exc.code}: {exc.detail}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n收工，还原系统代理与 hosts…", file=sys.stderr)
        stack.disable()
        return 0


def _set_title(text: str) -> None:
    """改窗口标题。滚屏再快，标题栏也跑不掉 —— 这是唯一不会被日志冲走的位置。"""
    if os.name != "nt":
        return
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(text)
    except Exception:  # noqa: BLE001
        pass


def _beep(times: int = 3) -> None:
    """响一声比打一行字有用：用户这时候眼睛在游戏上，不在这个窗口上。"""
    try:
        for _ in range(times):
            print("\a", end="", flush=True)
            time.sleep(0.18)
    except Exception:  # noqa: BLE001
        pass


def _wait(stack: CaptureStack, *, light: bool = False) -> None:
    """前台常驻。会话一入库：响铃 + 改标题 + 大字横幅 + 立刻收工。

    为什么抓到就收工，而不是继续常驻：
      抓到之后代理看到的每一条 `/account/...` 都会打一行日志，
      几秒钟就能把「★ 会话已抓取」冲出屏幕 —— 2026-11-18 两次现场
      （17:03:22 抓到 #4、17:11:28 抓到 #5）都是这么被埋掉的，
      用户以为没抓到，其实库里躺得好好的。

      一份会话够用了。抓到立刻 disable：代理停了流量就停、日志就停，
      系统代理和 hosts 也立刻干净，窗口最后只剩结论，
      不用用户去猜、也不用他记得按 Ctrl+C。
    """
    seen = len(stack.events)
    cap_log = logging.getLogger("skyhuiyu.capture")
    print("\n" + "=" * 62, file=sys.stderr)
    if light:
        print("  正在等平台登录 —— 在官方平台里扫码，进游戏画面就算成功", file=sys.stderr)
    else:
        print("  正在等游戏登录 —— 抓到会响铃并改窗口标题，别急着关", file=sys.stderr)
    print("=" * 62 + "\n", file=sys.stderr)
    cap_log.info("等待%s登录中（已有 %d 份登录态）",
                 "平台" if light else "游戏", seen)

    try:
        while len(stack.events) == seen:
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\n收工，还原系统代理与 hosts…", file=sys.stderr)
        stack.disable()
        return

    ev = stack.events[-1]
    s = ev.session
    cap_log.info("★ 会话已抓取 #%s user_id=%s level=%s build_key=%s",
                 ev.session_id, s.user_id,
                 "有" if s.level_id else "无",
                 "有" if s.build_access_key else "无")

    _beep(3)
    _set_title(f"✔ 会话已抓取 #{ev.session_id}  —— 可以关掉这个窗口了")

    print("\n" + "★" * 30, file=sys.stderr)
    print("★  会话已抓取！", file=sys.stderr)
    print(f"★  入库编号   #{ev.session_id}", file=sys.stderr)
    print(f"★  user_id    {s.user_id}", file=sys.stderr)
    print(f"★  等级/通行  level={'有' if s.level_id else '无'}"
          f"  build_key={'有' if s.build_access_key else '无'}", file=sys.stderr)
    print("★" * 30, file=sys.stderr)
    if not s.level_id or not s.build_access_key:
        print("  ! 这份会话缺字段，官方接口会回 423 —— 进一次地图再抓。",
              file=sys.stderr)

    # 立刻收工：停代理 -> 流量日志停 -> 上面这几十行就是窗口里最后的内容
    print("\n正在还原系统代理与 hosts…", file=sys.stderr)
    try:
        out = stack.disable()
        done = "；".join(out.get("done") or [])
        if done:
            print(f"  {done}", file=sys.stderr)
    except CaptureError as exc:
        print(f"  ! 还原失败 {exc.code}: {exc.detail}", file=sys.stderr)
        print("  重跑一次 `skyhuiyu.exe --capture disable` 即可。", file=sys.stderr)

    print("\n✔ 收工。回到面板点「体检」确认会话可用。\n", file=sys.stderr)
    _set_title("✔ SkyHuiyu 会话已抓取，可以关闭")


if __name__ == "__main__":
    sys.exit(main())
