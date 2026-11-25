"""密码学对齐测试 —— 不依赖 pytest，直接跑。

    python tests/test_crypto.py

覆盖点（任何一条挂掉，手机和 PC 就连不上）：
  1. 公钥一定是 65 字节 0x04 开头
  2. 指纹 = SHA256(公钥)[:8].hex()
  3. ECDH 双向派生一致
  4. HKDF 参数（salt/info/长度）用独立实现复算一遍
  5. 包体长度 = 12 + len(pt) + 16；nonce 前 8 字节是自增计数器（小端）
  6. 任意 nonce 的包都能解开（接收方不看计数器）
  7. 篡改一个字节必须抛 CryptoError
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from skyhuiyu.crypto import (  # noqa: E402
    INFO,
    KEY_LEN,
    MIN_PACKET,
    NONCE_LEN,
    SALT,
    TAG_LEN,
    CryptoBox,
    CryptoError,
    b64d_any,
    b64e,
    decode_pubkey_any,
    derive_key,
    fingerprint_of,
    new_private_key,
    public_bytes,
    replay_nonce_seq,
)


def _manual_hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 的独立实现，用来验证 cryptography 那边参数没写错。"""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def test_pubkey_format() -> None:
    box = CryptoBox()
    raw = box.public_key_bytes
    assert len(raw) == 65, len(raw)
    assert raw[0] == 0x04, raw[:1].hex()
    assert decode_pubkey_any(box.public_key_base64) == raw
    assert decode_pubkey_any(box.public_key_hex) == raw
    assert decode_pubkey_any(box.public_key_base64.rstrip("=")) == raw  # 无 padding
    urlsafe = b64e(raw).replace("+", "-").replace("/", "_")
    assert decode_pubkey_any(urlsafe) == raw


def test_fingerprint() -> None:
    box = CryptoBox()
    assert box.fingerprint == hashlib.sha256(box.public_key_bytes).digest()[:8].hex()
    assert len(box.fingerprint) == 16


def test_ecdh_symmetric() -> None:
    a, b = CryptoBox(), CryptoBox()
    ka = derive_key(a.private_key, b.public_key_bytes)
    kb = derive_key(b.private_key, a.public_key_bytes)
    assert ka == kb
    assert len(ka) == KEY_LEN


def test_hkdf_params() -> None:
    """用独立 HKDF 复算，确认 salt="SkyHuiyuProto2024"、info="session-key"。"""
    from cryptography.hazmat.primitives.asymmetric import ec

    a, b = CryptoBox(), CryptoBox()
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b.public_key_bytes)
    shared = a.private_key.exchange(ec.ECDH(), peer)
    expect = _manual_hkdf(shared, SALT, INFO, KEY_LEN)
    assert expect == derive_key(a.private_key, b.public_key_bytes)
    assert SALT == b"SkyHuiyuProto2024"
    assert INFO == b"session-key"


def test_packet_layout_and_counter() -> None:
    a, b = CryptoBox(), CryptoBox()
    a.derive(b.public_key_bytes)
    b.derive(a.public_key_bytes)
    for i in range(3):
        pkt = a.encrypt(b"hello")
        assert len(pkt) == NONCE_LEN + len(b"hello") + TAG_LEN
        counter, rnd = replay_nonce_seq(pkt)
        assert counter == i, (counter, i)
        assert len(rnd) == 8
        assert b.decrypt(pkt) == b"hello"
        assert len(pkt) >= MIN_PACKET


def test_accepts_foreign_nonce() -> None:
    """接收方必须接受任意 nonce（手机重启后计数器归零也能用）。"""
    a, b = CryptoBox(), CryptoBox()
    a.derive(b.public_key_bytes)
    b.derive(a.public_key_bytes)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = derive_key(b.private_key, a.public_key_bytes)
    nonce = struct.pack("<Q", 999) + os.urandom(4)
    ct = AESGCM(key).encrypt(nonce, b'{"x":1}', None)
    assert b.decrypt(nonce + ct) == b'{"x":1}'


def test_tamper_detected() -> None:
    a, b = CryptoBox(), CryptoBox()
    a.derive(b.public_key_bytes)
    b.derive(a.public_key_bytes)
    pkt = bytearray(a.encrypt(b"payload"))
    pkt[-1] ^= 0xFF
    try:
        b.decrypt(bytes(pkt))
    except CryptoError:
        return
    raise AssertionError("篡改未被发现")


def test_b64_any() -> None:
    raw = os.urandom(40)
    std = b64e(raw)
    assert b64d_any(std) == raw
    assert b64d_any(std.rstrip("=")) == raw
    assert b64d_any(std.replace("+", "-").replace("/", "_")) == raw


def test_b64_urltoken_must_not_be_silently_shortened() -> None:
    """回归：urlsafe 的 - _ 曾被 validate=False 静默丢弃，65 字节变 63。

    这一条必须用**确定含 + / 的字节**，不能随机 —— 随机串有相当概率
    不含 + /，测试就成了薛定谔的。
    """
    raw = bytes(range(256))[:65]          # 0x00..0x40
    std = b64e(raw)
    assert "+" in std or "/" in std, "构造的样本没覆盖到 +/，这条测试失效"
    url = std.replace("+", "-").replace("/", "_")
    assert b64d_any(url) == raw, "urlsafe 解码丢了字符"
    assert b64d_any(url.rstrip("=")) == raw
    # 公钥路径同样要过
    pub = b"\x04" + bytes(range(1, 65))
    pub_std = b64e(pub)
    assert decode_pubkey_any(pub_std.replace("+", "-").replace("/", "_")) == pub


def test_b64_rejects_garbage() -> None:
    """非法字符必须报错，不能被静默丢弃后当成合法数据。"""
    for bad in ("!!!!", "AB$CD", "a b c", "@@@@"):
        try:
            b64d_any(bad)
        except CryptoError:
            continue
        raise AssertionError(f"{bad!r} 应被拒绝")


# 用纯整数 P-256 点乘算出来的已知答案，不经过 cryptography 的 exchange()。
# 这条是唯一能证明"ECDH 取 X 坐标 + HKDF 参数"整体正确的向量：
# 前 7 条都只说明 PC 跟自己一致，两侧用的是同一个库。
_KAT_D_A = 0x1111111111111111111111111111111111111111111111111111111111111111
_KAT_D_B = 0x2222222222222222222222222222222222222222222222222222222222222222
_KAT_PUB_A = bytes.fromhex(
    "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4"
    "ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e57" "94"
)
_KAT_PUB_B = bytes.fromhex(
    "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589c"
    "f350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c912" "85"
)
_KAT_SHARED_X = bytes.fromhex(
    "ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6"
)
_KAT_SESSION_KEY = bytes.fromhex(
    "3ddefda94455f107082fa8eb3e759240ca87fa15ecb24a9c506e3a92831b6bb5"
)
# 期望值 = HKDF-SHA256(shared_x, salt="SkyHuiyuProto2024", info="session-key", 32)。
# salt/info 一旦调整，这里必须同步重算 —— 它就是协议兼容性的锚点。


def test_known_answer_vector() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    a = ec.derive_private_key(_KAT_D_A, ec.SECP256R1())
    b = ec.derive_private_key(_KAT_D_B, ec.SECP256R1())
    assert public_bytes(a) == _KAT_PUB_A, "SEC1 编码不对（定长 65 / 04 前缀）"
    assert public_bytes(b) == _KAT_PUB_B
    # 会话密钥 = HKDF(ECDH 的 X 坐标)，X 坐标先单点验一次
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    x = a.exchange(_ec.ECDH(), b.public_key())
    assert x == _KAT_SHARED_X, f"ECDH 出来的不是 X 坐标: {x.hex()}"
    assert derive_key(a, _KAT_PUB_B) == _KAT_SESSION_KEY, "HKDF(salt/info/长度) 与预期不一致"
    assert derive_key(b, _KAT_PUB_A) == _KAT_SESSION_KEY, "双向派生不一致"


def test_json_roundtrip() -> None:
    a, b = CryptoBox(), CryptoBox()
    a.derive(b.public_key_bytes)
    b.derive(a.public_key_bytes)
    obj = {"type": "badge", "rid": 3, "uid": "A1B2", "counter": 7,
           "token": "tok+/=", "url": "https://sky.thatg.co/?s=t&c=A1B2x7"}
    blob = a.encrypt_json_str(obj)
    back = b.decrypt_json_str(blob)
    assert back == obj


def _run_all() -> int:
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
