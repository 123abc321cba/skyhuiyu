"""SkyHuiyu Bridge —— PC 端（Windows/macOS/Linux）。

与 iOS 端 `CryptoBox.swift` / `PCConnection.swift` 严格对齐的桥接服务：
手机 NFC 读章 → 二维码配对 → Wi-Fi 加密上传 → PC 解密并记住徽章。

协议常量集中在 `protocol.py`，密码学在 `crypto.py`，
持久化在 `store.py`，网络在 `server.py`。
"""

__version__ = "2.0.0"
PROTOCOL = "skyhuiyu-pc/1"
