"""游戏请求信封 —— 与官方接口互通的那层编码。

    请求 body = base64( RC4( json_bytes, key = session2 ) )
    响应 body = gzip( RC4( plain_json, key = session2 ) )

关键事实（2026-11-16 运行时实测确认）：

- 算法是 **RC4 + base64**，不是 AES。
- 密钥是登录响应**顶层**的 `session2`（32 个 hex 字符），不是 `session`、不是
  `authinfo.key`。把它当 RC4 密钥解抓到的 body，明文立刻出来。
- 响应是 `RC4` 再 gzip（gzip 帧，windowBits=31）。
- 外层还有一层 `{"user": <uuid>, "body": <base64>}` 的壳，和信封一起发。
"""

from __future__ import annotations

import base64
import gzip
import json
import zlib
from typing import Any


def rc4(key: bytes, data: bytes) -> bytes:
    """标准 RC4。key 用 session2 的 ASCII 字节。"""
    if not key:
        raise ValueError("RC4 需要非空密钥")
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for idx, ch in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[idx] = ch ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def _key(session2: str) -> bytes:
    if not session2:
        raise ValueError("缺 session2：信封的 RC4 密钥就是它，登录响应顶层那个字段")
    return session2.encode("ascii")


def seal(payload: Any, session2: str) -> str:
    """明文 JSON → 要放进外层 `body` 的 base64 字符串。"""
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(rc4(_key(session2), raw)).decode("ascii")


def open_body(body: bytes, session2: str) -> Any:
    """响应体（RC4 + gzip）→ Python 对象。"""
    plain = rc4(_key(session2), body)
    try:
        inflated = gzip.decompress(plain)
    except OSError:
        # 少数接口回的是裸 deflate
        try:
            inflated = zlib.decompress(plain, -zlib.MAX_WBITS)
        except zlib.error:
            inflated = plain
    return json.loads(inflated.decode("utf-8"))


def wrap(user_id: str, payload: Any, session2: str) -> dict[str, str]:
    """拼最终发出去的 JSON：`{"user": …, "body": <信封>}`。"""
    return {"user": user_id, "body": seal(payload, session2)}


def verify_payload(user_id: str, session_token: str, badge_url: str) -> dict[str, str]:
    """验章请求的字段（从抓到的真实请求解密得到，缺一个就是 423）。

    实测：`{"user","user_id","session","uri"}` 四件套，字段名是 `uri` 不是 `star_url`。
    """
    return {
        "user": user_id,
        "user_id": user_id,
        "session": session_token,
        "uri": badge_url,
    }


def base_payload(user_id: str, session_token: str) -> dict[str, str]:
    """只读类接口的最小载荷（get_consumables1 / star/get 等都吃这一套）。"""
    return {"user": user_id, "user_id": user_id, "session": session_token}
