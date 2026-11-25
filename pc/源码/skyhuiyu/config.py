"""配置 —— JSON 落在用户目录，命令行可覆盖。

默认路径：
    Windows  %APPDATA%\\SkyHuiyu\\config.json
    macOS    ~/Library/Application Support/SkyHuiyu/config.json
    Linux    ~/.config/skyhuiyu/config.json
数据库同目录 skyhuiyu.db。
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("skyhuiyu.config")


class ConfigError(RuntimeError):
    """配置文件读不出来。带 code，方便入口处翻译成人话。"""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def default_home() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "SkyHuiyu"
    if os.uname().sysname == "Darwin":  # type: ignore[attr-defined]
        return Path.home() / "Library" / "Application Support" / "SkyHuiyu"
    return Path.home() / ".config" / "skyhuiyu"


def _ip_score(ip: str) -> int:
    """越小越像"手机能连到的那个地址"。

    家用/办公室 Wi-Fi 基本是 192.168.x 或 10.x；
    172.16-31.x 十有八九是 WSL / Hyper-V / Docker 的虚拟网卡，
    169.254.x 是没拿到 DHCP 的兜底地址 —— 这两类都排后面。
    """
    try:
        parts = [int(x) for x in ip.split(".")]
    except Exception:  # noqa: BLE001
        return 99
    if len(parts) != 4:
        return 99
    a, b = parts[0], parts[1]
    if ip.startswith("169.254."):
        return 90
    if a == 192 and b == 168:
        return 0
    if a == 10:
        return 1
    if a == 172 and 16 <= b <= 31:
        return 60
    if a == 127:
        return 95
    return 20


def lan_addresses() -> list[str]:
    """列出本机所有 IPv4，按"像真 LAN"的程度排序（第一个进二维码）。"""
    out: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in out:
                out.append(ip)
    except Exception:  # noqa: BLE001
        pass
    # 默认出口地址（UDP connect 不发包）
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(("223.5.5.5", 53))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip not in out:
            out.append(ip)
    except Exception:  # noqa: BLE001
        pass
    out = [ip for ip in out if not ip.startswith("127.")]
    out.sort(key=_ip_score)
    return out or ["127.0.0.1"]


def best_lan_ip() -> str:
    return lan_addresses()[0]


@dataclass
class Config:
    bind: str = "0.0.0.0"
    port: int = 8765
    # 广播给手机的地址；空 = 自动探测（第一个非环回 IPv4）
    advertise_host: str = ""
    data_dir: str = ""
    # 业务后端：local（只入库）/ netease（自己调官方接口）
    backend: str = "local"
    # netease 后端：抓到的会话用哪个 account 名
    account: str = "default"
    # netease 后端：验证成功后是否顺手 consume（默认为 False，存与用分离）
    auto_consume: bool = False
    # netease 后端：consume 回「库存不足」时，自动重新验章补货并重试。
    #
    # 实测事件顺序：use_started → out_of_stock → auto_store_started →
    # store_succeeded → use_succeeded。官方错误文案也写了：
    # "Not enough stock. Store this badge again before using it."
    #
    # 默认 False：这条链路会真的消耗魔法（不可撤销），得让用户自己开。
    auto_store: bool = False
    # 允许配对的手机指纹白名单；空 = 来者不拒（首次配对所有都收）
    allowed_fingerprints: list[str] = field(default_factory=list)
    # 每条 badge 应答的注入超时（秒）
    inject_timeout: float = 20.0
    # 是否开机自动打开浏览器面板
    open_browser: bool = True
    log_level: str = "INFO"
    # ---- 抓取栈 ----
    # 代理/PAC 共用的端口：443 被 ma75 的 hosts 劫持占着，8765 是徽章服务，
    # 8887 是它们中间的空位。
    proxy_port: int = 8887
    # 代理监听地址。只给本机用，不对外（手机那条链走 8765，不走这里）
    capture_bind: str = "127.0.0.1"
    # 游戏根目录（里面有 data/config.json 与票据）。空 = D:\FeverApps\sky
    game_root: str = ""

    def __post_init__(self) -> None:
        if not self.data_dir:
            self.data_dir = str(default_home())

    # --- 路径 ---
    @property
    def data_path(self) -> Path:
        p = Path(self.data_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def db_path(self) -> Path:
        return self.data_path / "skyhuiyu.db"

    @property
    def config_path(self) -> Path:
        return self.data_path / "config.json"

    @property
    def advertise(self) -> str:
        return self.advertise_host or best_lan_ip()

    # --- 读写 ---
    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        target = Path(path) if path else (default_home() / "config.json")
        cfg = cls(data_dir=str(target.parent))
        if target.exists():
            try:
                # utf-8-sig：Windows 记事本、以及一切用 `Set-Content -Encoding UTF8`
                # 存出来的文件都带 BOM。用 "utf-8" 读，json.loads 会在第一个字节
                # 上直接炸，而这里以前把异常整个吞掉回落默认值 —— 接着 save()
                # 又把默认值写回去：backend 从 netease 变 local（徽章验章静默失效）、
                # proxy_port 被打回 8887、open_browser 被打开。踩过一次，真丢配置。
                raw: dict[str, Any] = json.loads(target.read_text("utf-8-sig"))
            except (OSError, ValueError) as exc:
                # 坏配置不能静默变成默认配置再覆盖回去 —— 那样用户永远看不到自己丢了什么。
                # 先把原件挪到一边留证据，再把话说明白，让用户自己去修。
                broken = target.with_name(f"{target.name}.broken-{int(time.time())}")
                try:
                    target.replace(broken)
                except OSError:
                    broken = target
                log.error("配置解析失败(%s)，原件留在 %s", exc, broken)
                raise ConfigError(
                    "config_unreadable",
                    f"{target} 读不出来：{exc}\n"
                    f"原件已备份为 {broken.name}。修好它再启动，"
                    "否则你原来的设置（后端 / 端口 / 账号 / 自动存入）全都会回到默认值。",
                ) from exc
            known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
            for k, v in raw.items():
                if k in known:
                    setattr(cfg, k, v)
            # 只认 local / netease；旧配置里的其它值统一落到 netease（自己调官方）。
            if str(getattr(cfg, "backend", "")).lower() not in ("local", "netease"):
                log.warning("配置里的 backend=%r 已不再支持，改用 netease", cfg.backend)
                cfg.backend = "netease"
            cfg.data_dir = str(target.parent)
        return cfg

    def save(self) -> None:
        self.data_path.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            json.dumps(asdict(self), ensure_ascii=False, indent=2), "utf-8"
        )

    def as_public(self) -> dict[str, Any]:
        d = asdict(self)
        d["advertise"] = self.advertise
        d["lan_addresses"] = lan_addresses()
        return d
