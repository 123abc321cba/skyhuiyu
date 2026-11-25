"""PAC 生成 —— 单端口同时提供 PAC 与代理。

这段 PAC 很短，但里面有三个细节，缺一个就退回直连，全都实测过：

1. `host.toLowerCase().replace(/\\.$/, '')`
   WinINet 传进来的 host 可能大写、可能带尾点。不规范化 → `indexOf` 全不中 → DIRECT。
2. `ma75.update.netease.com` 必须在劫持表里
   启动器（CEF）启动第一件事是打更新检查，那条流量决定它后面走不走代理。
   只列账号域的结果是：整条链直连，代理日志一条游戏流量都没有。
3. `url.indexOf("http://127.0.0.1:<port>/account/")`
   覆盖「账号请求被改写成明文指向本机」的那条路径。

还有一条不是 PAC 内容、但同等重要：**PAC 必须和代理在同一个端口上提供**
（一个端口同时是 HTTP 代理和 PAC 服务）。分端口实测会退回直连，
因为客户端把「PAC 的来源」当成代理归属的一部分。
"""

from __future__ import annotations

# 劫持表：**进 PAC 的域名**。
#
# 前两个是实测确认必须进 PAC 的域名。
# 第三个 `live-auth-sky-merge` 是我们这条流程实测要的：登录请求会打到它，
# 不拦的话第一次登录拿不到会话。
#
# 注意：`service.mkey.163.com` **不在这里**。二进制里确实有那段
#   if (host === 'service.mkey.163.com' && /^https:\/\/service\.mkey\.163\.com.../i.test(url)
#       && new Date().getTime() < <ms>) return "PROXY 127.0.0.1:<port>";
# 但那是 ChannelLease（渠道登录专用通道，Java 侧 `proxy.channel_proxy_set` 激活）
# 的另一份 PAC，不是 desktop.pac —— 运行时抓下来对比过，desktop.pac 里没有它。
# 它只该进 MITM 表，见下面的 MITM_ONLY_HOSTS。
PAC_HOSTS: tuple[str, ...] = (
    "ma75.update.netease.com",
    "live-as-sky-merge.game.163.com",
    "live-auth-sky-merge.game.163.com",
)

# 只做 MITM、**不写进 PAC** 的域名。
#
# `service.mkey.163.com` 是网易 mpay 扫码登录网关，官方平台的第三方/渠道登录走它
# （`/mpay/api/qrcode/create_login`，响应里带 `uuid` 二维码 id）。
# 扫码登录第一步就是 `POST /mpay/api/qrcode/create_login`，响应里的 `uuid`
# 是二维码 id；不把 mkey 放进 PAC，这条请求在客户端那边就是 DIRECT，
# 渠道/第三方扫码的流量一条都看不到。
MITM_ONLY_HOSTS: tuple[str, ...] = (
    "service.mkey.163.com",
)

# 代理要 MITM 的全部域名 = PAC 表 + 只做 MITM 的表。
MITM_HOSTS: tuple[str, ...] = PAC_HOSTS + MITM_ONLY_HOSTS

# 后缀表：登录不是只有 `/account/auth/login` 一条路。实测这台机器上的登录页跑在
# WebView2 里，走的是启动器/SDK 那几个域；只拦前面三个域名，日志里就只会有 ma75。
#   webapp.163.com   ← 启动器 CEF 与登录页（loadingbaycn / loadingbaycn-websocket / fcount-api）
#   game.163.com     ← 账号、队列、websocket
#   matrix.netease.com ← UNISDK 登录网关
# 注意 **不放 unisdk.netease.com**：这个域名没有 A 记录，拦了只会让登录页拿到 502，
# 表现就是"无法连接 请检查网络并重试"（上一轮踩过）。
PAC_SUFFIXES: tuple[str, ...] = (
    "webapp.163.com",
    "game.163.com",
    "matrix.netease.com",
    "fever.163.com",
)

# 单端口同时提供 PAC 与代理时，客户端会来取这几个路径。
PAC_PATHS: tuple[str, ...] = (
    "/local-access/desktop.pac",
    "/local-access/proxy.pac",
    "/proxy.pac",
)

PAC_CONTENT_TYPE = "application/x-ns-proxy-autoconfig"

# 适配器与客户端的 path 大小写不一定一致（Chromium 小写、Windows 用原样），统一小写比较。
_PAC_PATHS_LOWER = tuple(p.lower() for p in PAC_PATHS)


def build_pac(proxy_addr: str, *, expires_at: float | None = None) -> str:
    """生成 PAC 文本。`proxy_addr` 形如 `127.0.0.1:8887`。

    `expires_at` 是 epoch 秒。给了就在 PAC 最前面加一条过期判断。

    为什么要这个：PAC 是写进注册表 `DefaultConnectionSettings` 的，进程被强杀、
    蓝屏、或者还原注册表那一步失败时，这条 PAC 会一直挂在那里。之前就因此
    出现过去光遇直接报 130（`ma75.update.netease.com` 被解析到 127.0.0.1 而
    监听早就没了）。把 `new Date().getTime() < <ms>` 写进 PAC，
    到点自动退回 DIRECT —— 这才是根本解法，比"记得还原"可靠得多。
    """
    # 注意这里用 MITM_HOSTS 而不是 PAC_HOSTS：PAC_HOSTS 只列账号域，
    # mkey（扫码登录网关）同样要交给代理，否则渠道登录拿不到二维码 id，
    # 登录完了还是"没抓到"。
    domains = ",".join(f'"{h}"' for h in MITM_HOSTS)
    suffixes = ",".join(f'"{h}"' for h in PAC_SUFFIXES)
    guard = ""
    if expires_at is not None:
        # 毫秒，和 JS 的 getTime() 对齐
        guard = f"  if (new Date().getTime() >= {int(expires_at * 1000)}) return 'DIRECT';\n"
    return (
        "function FindProxyForURL(url, host) {\n"
        "  host = host.toLowerCase().replace(/\\.$/, '');\n"
        f"{guard}"
        f"  var domains = [{domains}];\n"
        f"  var suffixes = [{suffixes}];\n"
        "  var hit = domains.indexOf(host) !== -1;\n"
        "  for (var i = 0; !hit && i < suffixes.length; i++) {\n"
        "    var s = suffixes[i];\n"
        "    if (host === s || host.slice(-(s.length + 1)) === '.' + s) hit = true;\n"
        "  }\n"
        f'  if (hit || url.indexOf("http://{proxy_addr}/account/") === 0) '
        f'return "PROXY {proxy_addr}";\n'
        "  return 'DIRECT';\n"
        "}\n"
    )


def host_matches(host: str) -> bool:
    """这个域名该不该走我们。

    PAC 与代理共用同一套规则，但两者范围不同：
    - PAC（客户端要不要把请求交给我们）= 精确表 + 后缀表
    - MITM（我们拿到 CONNECT 后要不要解密）= 上面两者 + MITM_ONLY_HOSTS
    分开的原因见 MITM_ONLY_HOSTS 的注释：mkey 是 ChannelLease 子通道的事，
    不该让客户端的 PAC 直接把 mkey 全量导过来。
    """
    h = (host or "").lower().rstrip(".")
    if h in MITM_HOSTS:
        return True
    return any(h == s or h.endswith("." + s) for s in PAC_SUFFIXES)


def is_pac_path(path: str) -> bool:
    """请求行里的路径是不是 PAC。带 query 也算（客户端有时会加 ?t=123）。"""
    return path.split("?", 1)[0].split("#", 1)[0].lower() in _PAC_PATHS_LOWER


def pac_url(proxy_port: int, host: str = "127.0.0.1") -> str:
    """系统代理里下发的 PAC URL，指向代理端口本身。"""
    return f"http://{host}:{proxy_port}/local-access/desktop.pac"
