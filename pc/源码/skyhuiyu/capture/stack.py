"""抓取栈 —— 把"装 CA → 起代理 → 下发 PAC → 等登录"这条链编排起来。

编排顺序：

    1. desktop.status        supported==true 且 recovery_error 为空，否则 official_pc_proxy_required
    2. ca_installed==false → desktop.ca_install → 再查status → 仍为false 则报错
    3. proxy.status  local_proxy_ready==false → proxy.start → 再查 → 仍为false 则报错
    4. proxy_owned==false 且 self_proxy_active==false → desktop.proxy_enable
    5. 最终判定 ca_installed && (proxy_owned || self_proxy_active) && local_proxy_ready

顺序不可调换：**系统代理指向的端口必须已经在监听**，否则客户端第一次取 PAC 就失败，
并把 "DIRECT" 缓存下来 —— 之后无论怎么改 PAC 都不生效（第 8 次失败的成因）。

在这五步之外，还有两个不写在流程里、但缺了就复现不了的动作：

  · hosts 写 `127.0.0.1 ma75.update.netease.com`（第九节的 ma75 常量与实测一致）
  · 清 CEF 的 PAC/证书解析缓存（第七节第 8 项）

这两步排在 "系统代理下发" 之前，因为它们决定客户端下次启动时看到什么。
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..config import Config
from ..store import Store
from . import cef as cef_mod
from . import hostsfile
from .authinfo import CapturedSession
from .ca import CaptureError, LocalCA
from .dnsx import RealResolver
from .proxy import CaptureProxy, free_port, listening
from .rewrite import TicketGate, reset_disk_account_domain
from .sni443 import Port443Listener
from .wininet import StateFile, enable_pac, query as wininet_query, restore as wininet_restore

LogFn = Callable[[str], None]

log = logging.getLogger("skyhuiyu.capture")


def _stderr_log(msg: str) -> None:
    """抓取栈的唯一出口：控制台 + 日志文件，两边都要写。

    只 print 是不够的。用户会把窗口最小化、被 `_print_status` 一口气刷掉十几行、
    或者干脆关掉再看——那时候"到底抓到没有"就只剩日志文件这一个证据。
    2026-11-18 那次就是这样：会话其实 17:03:22 已经入库（库里 #4 躺得好好的），
    但窗口里什么都没留下，用户以为没抓到。
    """
    print(f"[capture] {msg}", flush=True)
    log.info(msg)


@dataclass
class CaptureEvent:
    session: CapturedSession
    meta: dict[str, Any] = field(default_factory=dict)
    session_id: int = 0
    at: float = field(default_factory=time.time)


class CaptureStack:
    def __init__(self, cfg: Config, store: Store, *, log: LogFn | None = None) -> None:
        self.cfg = cfg
        self.store = store
        self.log: LogFn = log or _stderr_log
        self.ca = LocalCA(cfg.data_path / "ca")
        self.resolver = RealResolver()
        self.proxy = CaptureProxy(
            self.ca, self._on_capture,
            bind=cfg.capture_bind, port=cfg.proxy_port,
            resolver=self.resolver, log=self.log)
        self.listener443 = Port443Listener(
            self.ca, bind=cfg.capture_bind, port=443, proxy_port=cfg.proxy_port,
            resolver=self.resolver, log=self.log)
        self.state = StateFile(cfg.data_path / "capture-state.json")
        # 登录票据：有票游戏就不登录，抓不到东西，所以要先让开
        self.tickets = TicketGate(cfg.game_root or None)
        self.events: list[CaptureEvent] = []
        self.last_purge: list[dict[str, str]] = []
        self._error = ""

    # ------------------------------------------------------------------
    def _on_capture(self, session: CapturedSession, meta: dict[str, Any]) -> None:
        extra = session.as_extra()
        extra.update({"captured_from": "client_proxy", "capture_meta": meta, "at": time.time()})
        try:
            sid = self.store.save_session(
                account=self.cfg.account,
                user_id=session.user_id,
                session_token=session.session_token,
                level_id=session.level_id,
                build_access_key=session.build_access_key,
                user_agent=session.user_agent,
                game_version=session.game_version,
                extra=extra,
            )
        except Exception as exc:  # noqa: BLE001 - 落库失败不能中断抓包
            self.log(f"! 会话落库失败: {exc}")
            return
        ev = CaptureEvent(session=session, meta=meta, session_id=sid)
        self.events.append(ev)
        self.log(f"★ 会话已入库 #{sid}  user_id={session.user_id}  "
                 f"level_id={'有' if session.level_id else '无'}  "
                 f"build_key={'有' if session.build_access_key else '无'}")
        if not session.level_id or not session.build_access_key:
            self.log("  注意：这份会话缺 x-sky-level-id / x-sky-build-access-key，"
                     "官方接口会回 423。进一次地图再抓一次。")
        # 会话已经到手 —— hosts 的历史使命到此为止，立刻撤掉（见下）。
        self.release_login_hosts()

    # ------------------------------------------------------------------
    def release_login_hosts(self) -> bool:
        """抓到会话后立刻撤掉 hosts，因为它的职责已经完成。

        hosts 里那条 `127.0.0.1 ma75.update.netease.com` 只干一件事：
        让启动器的更新检查落到本机 443，从而逼出一次**真实登录**。
        会话一旦入库，这件事就结束了。继续留着它，代理一停启动器就钉在
        一个没人监听的端口上，报"无法连接 请检查网络并重试"——
        这正是 `hostsfile` 模块头里写过的那个后果。

        本方法在**代理线程**里被调用（proxy.on_exchange → sink），
        所以任何失败都只记日志，绝不把异常抛回抓包线程。

        幂等：hosts 本来就没开就直接返回 False，不写盘。
        """
        try:
            if not hostsfile.is_enabled():
                return False
            if not hostsfile.disable():
                return False
        except CaptureError as exc:
            self.log(f"! 撤 hosts 失败（{exc.code}）：{exc.detail}")
            return False
        # 落盘记录"hosts 已不在"，避免下次启动的 recover() 白跑一遍，
        # 也让面板的 hosts_enabled 与实测值对得上。
        st = self.state.load()
        if st:
            st["hosts_added"] = False
            st["hosts_released_at"] = time.time()
            self.state.save(st)
        self.log("hosts 已撤 —— 会话到手，不再劫持 ma75；启动器更新检查回直连")
        return True

    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        supported = os.name == "nt"
        ca_installed = False
        ca_err = ""
        if supported:
            try:
                if self.ca.cert_path.exists() and self.ca.key_path.exists():
                    ca_installed = self.ca.is_installed()
            except CaptureError as exc:
                ca_err = f"{exc.code}: {exc.detail}"
            except Exception as exc:  # noqa: BLE001
                ca_err = str(exc)

        win: dict[str, Any] = {}
        win_err = ""
        if supported:
            try:
                win = wininet_query()
            except Exception as exc:  # noqa: BLE001
                win_err = str(exc)

        pac_url = self.proxy.pac_url if self.proxy.ready else \
            f"http://127.0.0.1:{self.cfg.proxy_port}/local-access/desktop.pac"
        owned = bool(win) and win.get("mode") == "pac" and win.get("pac_url", "") == pac_url
        local_ready = self.proxy.ready and listening("127.0.0.1", self.proxy.port)
        port_now = self.proxy.port if self.proxy.ready else self.cfg.proxy_port
        local_base = f"http://127.0.0.1:{port_now}"
        domain = ""

        recovery = self._error or ca_err or win_err
        if not supported:
            recovery = "本功能只实现 Windows"
        elif not recovery:
            if not free_port(self.cfg.capture_bind, self.cfg.proxy_port) and not self.proxy.ready:
                recovery = f"端口 {self.cfg.proxy_port} 被占用"
            elif not free_port("0.0.0.0", 443) and not self.listener443.ready:
                recovery = "端口 443 被占用（其它代理在跑？先退出它）"

        return {
            "supported": supported,
            "recovery_error": recovery,
            "ca_installed": ca_installed,
            "ca_scope": "CurrentUser ROOT",
            "ca_sha256": self.ca.sha256 if ca_installed else "",
            "proxy_owned": owned,
            "self_proxy_active": owned,
            "local_proxy_ready": local_ready,
            "proxy_port": self.proxy.port if self.proxy.ready else self.cfg.proxy_port,
            "pac_url": pac_url,
            "port443_ready": self.listener443.ready,
            "hosts_enabled": hostsfile.is_enabled(),
            # 配置改写（与代理那条路共用 rewrite.apply）
            "config_rewrites": self.listener443.config_rewrites + self.proxy.config_rewrites,
            "account_origin": self.listener443.account_origin or self.proxy.account_origin,
            "account_local_url": local_base,
            "tickets_parked": len(self.tickets.parked()),
            "wininet": win,
            "proxy_flows": self.proxy.flows,
            # 经过代理的域名统计（mitm / blind）。排障全靠它分辨
            # "平台没走代理" 和 "走了但域名没匹配"。
            "proxy_hosts": self.proxy.host_report(),
            "proxy_captured": self.proxy.captured,
            "last_error": self.proxy.last_error or self.listener443.last_error,
            "enabled": bool(self.state.load().get("enabled")),
        }

    # ------------------------------------------------------------------ 开
    def enable(self, *, purge_cef: bool = True, install_ca: bool = True,
               park_ticket: bool = True, hijack_ma75: bool = True) -> dict[str, Any]:
        """按上面的顺序把整条链拉起来。每一步都复核，失败就抛，不装作成功。

        `hijack_ma75=False` 进**轻量模式**：跳过 ③443 透传、④hosts 劫持、
        ⑥票据让开（这三步都是为了逼游戏客户端重新登录、再去磁盘上捞新票据）。

        轻量模式走最短路径 —— 完全不碰游戏：只装 CA、起代理、下发 PAC，
        然后由我们启动官方平台，让登录流量自己经过代理，在
        `on_exchange` 里从请求头把 `x-session-token` 接住。

        代价：游戏自己有缓存票据时不会重登，所以**必须在平台里重新扫码登录**，
        等它自然产生账号请求。好处：`config.json` 不用改、CEF 缓存不用清、
        票据不用让开、游戏不用重启，退出后机器上什么都不留。
        """
        st = self.status()
        if not st["supported"]:
            raise CaptureError("unsupported_platform", "抓取栈只实现 Windows")
        if st["recovery_error"]:
            raise CaptureError("official_pc_proxy_required", st["recovery_error"])

        # 轻量模式关掉 ACCOUNT_DOMAIN 改写：那条改写是给"劫持 ma75 逼游戏重登"
        # 那条路用的，轻量模式不碰游戏，改写只会把官方返回的账号域名污染成本机端口。
        self.proxy.rewrite_config = hijack_ma75

        self.log("① 检查 CA")
        self.ca.load_or_create()
        if not st["ca_installed"]:
            if not install_ca:
                raise CaptureError("ca_not_installed", "CA 没装进 CurrentUser\\ROOT")
            self.log("   装 CA 进 CurrentUser\\ROOT —— 会弹一次 Windows「安全警告」，点「是(Y)」")
            self.log(f"   颁发者 Sky Huiyu Local Proxy CA，sha256 {self.ca.sha256[:16]}…")
            self.ca.install()
            st = self.status()
            if not st["ca_installed"]:
                raise CaptureError("official_pc_proxy_required", "CA 装完复核仍为未安装")

        self.log("② 起代理（PAC 与代理同端口）")
        if not st["local_proxy_ready"]:
            self.proxy.start()
            st = self.status()
            if not st["local_proxy_ready"]:
                raise CaptureError("official_pc_proxy_required", "代理起完复核仍不就绪")

        if hijack_ma75:
            self.log("③ 起 443 透传（ma75 更新检查）")
            if not self.listener443.ready:
                try:
                    self.listener443.start()
                except OSError as exc:
                    raise CaptureError("port_443_unavailable",
                                       f"443 起不来：{exc}（其它代理在跑就先退出它）") from exc

            self.log("④ 写 hosts（只加 ma75）")
            try:
                if hostsfile.enable():
                    self.log("   hosts 已加 127.0.0.1 ma75.update.netease.com")
                else:
                    self.log("   hosts 已存在，跳过")
            except CaptureError:
                raise
            # ★ 先落盘再往下走。hosts 是这条链里**唯一会残留到系统**的东西：
            #   ⑤ 清 CEF / ⑥ 让开票据任何一步抛异常，进程就此退出，
            #   如果这里没写 state，下次启动的 recover() 看不到任何痕迹，
            #   那条 hosts 就永久留在机器上。
            #   用 merge 而不是整体覆盖：⑦ 要复用已有 state 里的 wininet 原始快照，
            #   整体覆盖会把用户原本的系统代理配置丢掉。
            _st = self.state.load()
            _st.update({"enabled": True, "hosts_added": True, "updated_at": time.time()})
            self.state.save(_st)
        else:
            self.log("③④ 跳过 ma75 劫持（轻量模式：不动 hosts、不开 443、不改游戏）")

        if purge_cef and hijack_ma75:
            self.log("⑤ 清 CEF 解析缓存")
            self.last_purge = cef_mod.purge()
            self.log("   " + cef_mod.summary(self.last_purge))

        # ⑥ 让开登录票据。有票的话游戏直接连真实服务器，**根本不发登录请求**，
        #    日志里永远只有 ma75 的更新检查。
        #    轻量模式不让开：我们不逼游戏重登，靠的是平台自己发起的新登录。
        if park_ticket and hijack_ma75:
            moved = self.tickets.park()
            if moved:
                self.log(f"⑥ 票据已让开 {len(moved)} 个（{moved[0].name}），"
                         "这样游戏才会真的走一次登录")
            else:
                self.log("⑥ 没有票据要处理（本来就要登录）")
        elif hijack_ma75:
            self.log("⑥ 跳过票据让开（--keep-ticket）：如果游戏已登录，这次抓不到任何东西")
        else:
            self.log("⑥ 跳过票据让开（轻量模式不碰游戏票据）")

        self.log("⑦ 下发系统代理（WinINet，PAC 指向代理端口）")
        snap: dict[str, Any] = {}
        state = self.state.load()
        if state.get("wininet"):
            snap = state["wininet"]
        else:
            snap = wininet_query()
        # 先落盘再动手：下发之后任何一步炸掉，recover() 才有东西可还原。
        # 不先落盘的话，进程一死系统代理就指着一个已经不存在的端口，整机断网。
        self.state.save({
            "enabled": True,
            "proxy_port": st["proxy_port"],
            "pac_url": st["pac_url"],
            "wininet": snap,
            "hosts_added": hijack_ma75,
            "account_rewritten": bool(self.proxy.config_rewrites),
            "tickets_parked": bool(self.tickets.parked()),
            "updated_at": time.time(),
        })
        if not st["proxy_owned"]:
            applied = enable_pac(st["pac_url"])
            self.log(f"   PAC 已下发 → {st['pac_url']}（当前 mode={applied.get('mode')}）")
        else:
            self.log("   PAC 已经是我们这个了，跳过")

        st = self.status()
        ok = (st["ca_installed"]
              and (st["proxy_owned"] or st["self_proxy_active"])
              and st["local_proxy_ready"])
        if not ok:
            raise CaptureError("official_pc_proxy_required",
                               f"最终判定未通过: ca={st['ca_installed']} "
                               f"owned={st['proxy_owned']} ready={st['local_proxy_ready']}")

        self.state.save({
            "enabled": True,
            "proxy_port": st["proxy_port"],
            "pac_url": st["pac_url"],
            "wininet": snap,
            "hosts_added": hijack_ma75,
            "cef_purged_at": time.time() if (purge_cef and hijack_ma75) else 0,
            "light_mode": not hijack_ma75,
            "updated_at": time.time(),
        })
        st = self.status()
        if hijack_ma75:
            self.log("✔ 链路就绪：启动启动器 → 扫码登录 → 抓 authinfo")
        else:
            self.log("✔ 轻量链路就绪：启动官方平台 → 在平台里扫码登录 → 会话自动接住")
            self.log("   （不动 hosts、不开 443、不清缓存、不让票据、不改游戏配置）")
        return st

    # ------------------------------------------------------------------ 关
    def disable(self, *, uninstall_ca: bool = False) -> dict[str, Any]:
        st = self.state.load()
        done: list[str] = []
        if st.get("wininet"):
            try:
                wininet_restore(st["wininet"])
                done.append("系统代理已还原")
            except Exception as exc:  # noqa: BLE001
                done.append(f"系统代理还原失败: {exc}")
        try:
            # cleanup() 返回的是给人看的字符串，**永远非空**（没事做时返回"无需清理"）。
            # 原来写 `if hostsfile.cleanup():` 把"无需清理"也当成成功，
            # 于是日志永远说"hosts 已还原"——那是一条假报告，会掩盖真的写盘失败。
            what = hostsfile.cleanup()
            if what and what != "无需清理":
                done.append(f"hosts 已还原（{what}）")
        except CaptureError as exc:
            done.append(f"hosts 还原失败: {exc.detail}")
        # 游戏配置不用还原：我们不再改磁盘上的 config.json。
        # 启动器每次启动都会重新拉一份（那份在飞行中被我们改过），
        # 我们的代理一停，它下次拉到的就是官方原值。
        try:
            back = self.tickets.restore()
            if back:
                done.append(f"票据已还回 {len(back)} 个")
        except CaptureError as exc:
            done.append(f"票据还回失败: {exc.detail}")
        self.listener443.stop()
        self.proxy.stop()
        done.append("监听已停")
        if uninstall_ca:
            try:
                removed = self.ca.uninstall()
                done.append("CA 已从 CurrentUser\\ROOT 删除" if removed else "CA 本来就没装")
            except CaptureError as exc:
                done.append(f"CA 删除失败: {exc.detail}")
        self.state.clear()
        self._error = ""
        self.log("✔ 已收工：" + "；".join(done))
        return {"done": done, "status": self.status()}

    # ------------------------------------------------------ 崩了之后的恢复
    def recover(self) -> str:
        """进程被杀/断电之后的自愈：系统代理还指着已经不存在的端口时，机器是断网的。

        每次启动先跑这个。返回做了什么，空字符串表示无事可做。
        """
        st = self.state.load()
        if not st:
            return ""
        if self.proxy.ready or listening("127.0.0.1", int(st.get("proxy_port") or self.cfg.proxy_port)):
            return ""  # 上一份状态是活的，不碰
        actions: list[str] = []
        if st.get("wininet"):
            try:
                wininet_restore(st["wininet"])
                actions.append("系统代理已还原（上次没正常退出）")
            except Exception as exc:  # noqa: BLE001
                actions.append(f"系统代理还原失败: {exc}")
        try:
            if hostsfile.disable():
                actions.append("hosts 残留已清")
        except CaptureError:
            pass
        try:
            if self.tickets.restore():
                actions.append("票据已还回")
        except CaptureError:
            pass
        try:
            if reset_disk_account_domain(self.cfg.game_root or None):
                actions.append("游戏本地配置里的本机地址已还原官方")
        except Exception:  # noqa: BLE001 - 自愈不能因为这一步失败
            pass
        self.state.clear()
        msg = "；".join(actions)
        if msg:
            self.log("自愈：" + msg)
        return msg

    # ------------------------------------------------------------------
    def snapshot_for_ui(self) -> dict[str, Any]:
        st = self.status()
        st["events"] = [
            {
                "session_id": e.session_id,
                "user_id": e.session.user_id,
                "platform": e.session.platform,
                "game_version": e.session.game_version,
                "at": e.at,
            }
            for e in self.events[-10:]
        ]
        st["cef_purge"] = self.last_purge[-5:]
        return st

    def as_json(self) -> str:
        return json.dumps(self.snapshot_for_ui(), ensure_ascii=False, indent=2)


def port_owner_hint(port: int = 443) -> str:
    """给个能直接抄的命令：谁的 443 被谁占了。"""
    if os.name != "nt":
        return f"lsof -i :{port}"
    return f'Get-NetTCPConnection -LocalPort {port} | ForEach-Object {{ "{port}" ; (Get-Process -Id $_.OwningProcess).ProcessName }}'


__all__ = ["CaptureStack", "CaptureEvent", "CaptureError"]
