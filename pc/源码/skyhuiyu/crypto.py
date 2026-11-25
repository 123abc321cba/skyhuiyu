"""密码学层 —— 与 iOS `CryptoBox.swift` 逐字节对齐。

对齐要点（任何一条改了都会导致解不开）：

1. 曲线        P-256 (secp256r1)，ECDH，密钥交换只用 X 坐标 32 字节
2. 公钥格式    SEC1 / X9.62 未压缩点 65 字节 = 0x04 || X(32) || Y(32)
3. 派生        HKDF-SHA256(ikm = 共享密钥, salt = b"SkyHuiyuProto2024",
                          info = b"session-key", len = 32)
4. 对称加密    AES-256-GCM
5. 封装        包体 = nonce(12) || ciphertext || tag(16)
6. nonce       发送方自增计数器 8 字节小端 + 4 字节随机  (struct.pack('<Q', n) + urandom(4))
7. 指纹        SHA256(公钥 65 字节) 前 8 字节的 hex

对应源码：
  Swift  SkyHuiyu/CryptoBox.swift:50-68  derive()
  Swift  SkyHuiyu/CryptoBox.swift:81-94  encrypt()
  Swift  SkyHuiyu/CryptoBox.swift:97-108 decrypt()
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import struct
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SALT = b"SkyHuiyuProto2024"
INFO = b"session-key"
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
MIN_PACKET = NONCE_LEN + TAG_LEN
PUBKEY_LEN = 65
PUBKEY_PREFIX = 0x04

_HEX130 = re.compile(r"^[0-9A-Fa-f]{130}$")


class CryptoError(Exception):
    """解密/派生失败。上层必须把它当成"这条消息不成立"，不能当成"重试"。"""


# --------------------------------------------------------------------------- #
# 编码自适应：iOS 三种写法都收（标准 base64 / urlsafe base64 / hex）
# 对应 Swift PCConnection.decodeKeyAny()  SkyHuiyu/PCConnection.swift:161-184
# --------------------------------------------------------------------------- #

def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64_pad(s: str) -> str:
    rem = len(s) % 4
    return s if rem == 0 else s + "=" * (4 - rem)


def b64d_any(value: str) -> bytes:
    """标准 base64 / urlsafe base64 / 缺 padding 全部接受。

    ★ 必须按字符表判断，不能"先试标准、失败再试 urlsafe"：
      base64.b64decode(validate=False) 遇到 - _ 这些非字母表字符**不报错**，
      而是静默丢弃。于是 urlsafe 的 65 字节公钥会被悄悄解成 63 字节，
      错误信息指向长度不对，根因完全对不上。
      Swift 侧 Data(base64Encoded:) 是严格解码，所以它那种两段式 fallback
      成立；这里必须显式换表 + validate=True。
    """
    t = (value or "").strip().strip("\"'").strip()
    if not t:
        raise CryptoError("空 base64")
    if "-" in t or "_" in t:
        t = t.replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(b64_pad(t), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError(f"base64 解析失败: {exc}") from exc


def decode_pubkey_any(value: str) -> bytes:
    """把 65 字节未压缩公钥从任意编码里解出来（hex / base64 / urlsafe）。"""
    t = (value or "").strip().strip("\"'").strip()
    if _HEX130.match(t):
        raw = bytes.fromhex(t)
    else:
        raw = b64d_any(t)
    if len(raw) != PUBKEY_LEN or raw[0] != PUBKEY_PREFIX:
        raise CryptoError(f"公钥格式不对: len={len(raw)} prefix={raw[:1].hex()}")
    return raw


# --------------------------------------------------------------------------- #
# 密钥对
# --------------------------------------------------------------------------- #

def new_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_bytes(priv: ec.EllipticCurvePrivateKey) -> bytes:
    """SEC1 未压缩点 65 字节。Swift 侧用 x963Representation。"""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def private_key_from_pem(pem: bytes) -> ec.EllipticCurvePrivateKey:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return load_pem_private_key(pem, password=None)


def private_key_to_pem(priv: ec.EllipticCurvePrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    return priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def fingerprint_of(pub_raw: bytes) -> str:
    """SHA256(65B) 前 8 字节 hex —— 与 Swift crypto.fingerprint 一致。"""
    return hashlib.sha256(pub_raw).digest()[:8].hex()


def derive_key(priv: ec.EllipticCurvePrivateKey, peer_raw: bytes) -> bytes:
    """ECDH → HKDF-SHA256 → 32 字节会话密钥。"""
    if len(peer_raw) != PUBKEY_LEN or peer_raw[0] != PUBKEY_PREFIX:
        raise CryptoError("对端公钥不是 65 字节未压缩点")
    try:
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_raw)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError(f"对端公钥非法: {exc}") from exc

    # cryptography 的 exchange(ECDH()) 返回的正是 X 坐标 32 字节，
    # 与 CryptoKit SharedSecret 的原始字节一致（这是对齐的关键点）。
    shared = priv.exchange(ec.ECDH(), peer)
    if len(shared) != 32:
        raise CryptoError(f"共享密钥长度异常: {len(shared)}")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=SALT,
        info=INFO,
    ).derive(shared)


# --------------------------------------------------------------------------- #
# 会话密码盒
# --------------------------------------------------------------------------- #

class CryptoBox:
    """一个连接一个实例，绑定发送计数器。线程使用：只在事件循环里调。"""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._priv = private_key or new_private_key()
        self._aead: AESGCM | None = None
        self._send_nonce = 0
        self._recv_nonce = 0

    # --- 公钥信息 ---
    @property
    def private_key(self) -> ec.EllipticCurvePrivateKey:
        return self._priv

    @property
    def public_key_bytes(self) -> bytes:
        return public_bytes(self._priv)

    @property
    def public_key_base64(self) -> str:
        return b64e(self.public_key_bytes)

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.public_key_bytes)

    @property
    def is_derived(self) -> bool:
        return self._aead is not None

    # --- 派生 ---
    def derive(self, peer_raw: bytes) -> None:
        self._aead = AESGCM(derive_key(self._priv, peer_raw))
        self._send_nonce = 0
        self._recv_nonce = 0

    def derive_from_any(self, peer_pubkey: str) -> None:
        self.derive(decode_pubkey_any(peer_pubkey))

    # --- 加解密 ---
    def encrypt(self, plaintext: bytes) -> bytes:
        if self._aead is None:
            raise CryptoError("尚未完成密钥交换")
        nonce = struct.pack("<Q", self._send_nonce) + os.urandom(4)
        self._send_nonce += 1
        ct_and_tag = self._aead.encrypt(nonce, plaintext, None)
        return nonce + ct_and_tag

    def decrypt(self, packet: bytes) -> bytes:
        if self._aead is None:
            raise CryptoError("尚未完成密钥交换")
        if len(packet) < MIN_PACKET:
            raise CryptoError(f"密文过短: {len(packet)}")
        nonce = packet[:NONCE_LEN]
        body = packet[NONCE_LEN:]
        try:
            return self._aead.decrypt(nonce, body, None)
        except Exception as exc:  # noqa: BLE001
            raise CryptoError(f"GCM 校验失败（密钥不一致或包被改）: {exc}") from exc

    def encrypt_json_str(self, obj: dict[str, Any]) -> str:
        import json

        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return b64e(self.encrypt(raw))

    def decrypt_json_str(self, blob: str) -> dict[str, Any]:
        import json

        plain = self.decrypt(b64d_any(blob))
        try:
            obj = json.loads(plain.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise CryptoError(f"明文不是 JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise CryptoError("明文不是 JSON 对象")
        return obj


def replay_nonce_seq(packet: bytes) -> tuple[int, str]:
    """调试用：把包里的 nonce 拆成 (计数器, 随机段 hex)。"""
    if len(packet) < NONCE_LEN:
        raise CryptoError("包太短")
    counter = struct.unpack("<Q", packet[:8])[0]
    return counter, packet[8:NONCE_LEN].hex()
