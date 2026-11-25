"""信封协议的单元测试 —— 用与真实抓包同结构的样本做断言。"""

from __future__ import annotations

import base64
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skyhuiyu import envelope  # noqa: E402

PASS = []
FAIL = []


def check(name: str, cond: bool, extra: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"   {extra}" if extra and not cond else ""))


# 合成样本：真实抓包在开源版里已替换成同结构的假数据（凭据是别人的，不能带走）
SESSION2 = "11111111111111111111111111111111"
USER = "00000000-0000-4000-8000-000000000001"
SESSION = "22222222222222222222222222222222"

# 上面三个值对应的信封（结构和真实抓包一致，凭据是合成的）
REAL_BODY_B64 = (
    "Gzi3HvI1yEhWDC2NeleQxGbcei1fH18HVoiTxp0MOYMRfR3cxNO9Qw2Ms6h1AK3dXiFR8tHMRgQk"
    "yQA871D/Qny4Pc+jcg7ngnbS/MBMmuTDaTJiMMT9NYmOFcQ7reHfXDSLlUVzfn8FhfeuIf0Cgk2A"
    "kB9LsUNbQDmdtyLNO4JxoGg1yilJhBa5wnHh"
)

def raises(fn) -> bool:
    try:
        fn()
    except Exception:  # noqa: BLE001
        return True
    return False


print("== RC4 与信封 ==")
check("RC4 空密钥必须报错", raises(lambda: envelope.rc4(b"", b"x")))
check("RC4 往返一致", envelope.rc4(b"k", envelope.rc4(b"k", b"hello")) == b"hello")
check("RC4 已知向量（key=Key, pt=Plaintext）",
      envelope.rc4(b"Key", b"Plaintext").hex() == "bbf316e8d940af0ad3")

wire = envelope.wrap(USER, {"user": USER, "user_id": USER, "session": SESSION}, SESSION2)
check("外层只有 user/body", set(wire) == {"user", "body"})
check("body 是 base64", base64.b64decode(wire["body"], validate=True) is not None)

plain = json.loads(envelope.rc4(SESSION2.encode(), base64.b64decode(wire["body"])))
check("自解回来字段一致",
      plain == {"user": USER, "user_id": USER, "session": SESSION})

print("\n== 真实样本解密 ==")
try:
    got = json.loads(envelope.rc4(SESSION2.encode(), base64.b64decode(REAL_BODY_B64)))
    check("样本信封能解出 JSON", isinstance(got, dict), str(got)[:80])
    check("解出的 user 与样本一致", got.get("user") == USER, str(got)[:80])
except Exception as exc:  # noqa: BLE001
    check("样本信封能解出 JSON", False, repr(exc))

print("\n== 响应解码（RC4 + gzip）==")
payload = {"result": "ok", "star_tag_def_name": "outfit_prop_jumbo_mischief_cat"}
# 真实顺序是 rc4(gzip(json))：先 gunzip 后 rc4 是错的，open_body 里 rc4 在 gunzip 之前
sealed = envelope.rc4(SESSION2.encode(), gzip.compress(json.dumps(payload).encode()))
check("响应能还原成 dict", envelope.open_body(sealed, SESSION2) == payload)

raw_json = envelope.rc4(SESSION2.encode(), json.dumps(payload).encode())
check("未压缩也能兜住", envelope.open_body(raw_json, SESSION2) == payload)

print("\n== 载荷字段 ==")
vp = envelope.verify_payload(USER, SESSION, "https://sky.thatg.co/?s=x&c=y")
check("验章四件套", set(vp) == {"user", "user_id", "session", "uri"})
check("字段名是 uri 而不是 star_url", "uri" in vp and "star_url" not in vp)
bp = envelope.base_payload(USER, SESSION)
check("只读载荷三件套", set(bp) == {"user", "user_id", "session"})

print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} 通过")
if FAIL:
    sys.exit(1)
