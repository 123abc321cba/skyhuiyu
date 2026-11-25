"""协议常量与消息校验。

线上帧（明文，外层不加密）：
    server_hello   PC → 手机   {"type":"server_hello","pubkey":b64,"pubkey_hex":hex,
                                "fingerprint":8Bhex,"protocol":"skyhuiyu-pc/1",
                                "host":"192.168.x.x","port":8765}
    pairing        手机 → PC   {"phone_pubkey":b64,"data":b64(AESGCM({"type":"pairing",
                                "fingerprint":...,"proto":1}))}
    badge          手机 → PC   {"phone_pubkey":b64,"data":b64(AESGCM({"type":"badge",
                                "rid":N,"uid":...,"counter":N,"token":...,"url":...}))}
    ack            PC → 手机   {"status":"ok"|"error","message":str,
                                "inject":{"ok":bool,"action":str,"detail":str,...},
                                "record":{...}}

版本兼容（重要）：
    v1.0 客户端（src_extract 那版）的 pairing 明文里**没有** "proto" 字段，
    且它发完 pairing 之后**不读**应答 —— 它会直接把下一条收到的帧当成 badge 的应答。
    所以：明文里没有 "proto" 就**不能**回 pairing 的 ack，否则 v1.0 会错位。
    v1.1 客户端有 "proto" 且明确等 ack，此时必须回。

这条规则写在 `session.handle_pairing()` 里，别在别处再改。
"""

from __future__ import annotations

from typing import Any

PROTOCOL = "skyhuiyu-pc/1"
WS_PATH = "/badge"

ERR_BAD_FRAME = "bad_frame"
ERR_BAD_PUBKEY = "bad_pubkey"
ERR_CRYPTO = "crypto_failed"
ERR_BAD_JSON = "bad_json"
ERR_NOT_PAIRED = "not_paired"
ERR_BAD_BADGE = "bad_badge"
ERR_DUPLICATE = "duplicate"
ERR_INJECT = "inject_failed"
ERR_RATE = "rate_limited"
ERR_BUSY = "busy"

BADGE_URL_PREFIXES = ("https://sky.thatg.co/", "http://sky.thatg.co/", "https://sky.thatg.co")


def is_probable_badge_url(url: str) -> bool:
    u = (url or "").strip()
    return u.startswith(BADGE_URL_PREFIXES) and "s=" in u
