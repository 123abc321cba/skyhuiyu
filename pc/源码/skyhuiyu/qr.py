"""二维码生成 —— 内容就是 iOS `handleScan` 认的那个 JSON。

    {"pubkey":"<标准 base64 的 65 字节公钥>","host":"192.168.0.10","port":8765}

注意：必须是**标准带 padding 的 base64**（v1.0 客户端只认这个），
`port` 必须是 Int（Swift 里 `as? Int` 在 JSON 数字是整型时成立；
写字符串会挂）。所以这里手写 JSON，不走任何会改类型的序列化。
"""

from __future__ import annotations

import io
import json

try:  # Pillow 在就用 PNG，不在就回退 SVG（手机都能扫）
    from qrcode.image.pil import PilImage  # noqa: F401

    _HAS_PIL = True
except Exception:  # noqa: BLE001
    _HAS_PIL = False


def qr_payload(pubkey_b64: str, host: str, port: int) -> str:
    """手拼 JSON，保证字段顺序与类型（port 是数字，不是字符串）。"""
    return "{" + f'"pubkey":{json.dumps(pubkey_b64)},' f'"host":{json.dumps(host)},' f'"port":{int(port)}' + "}"


def qr_png(payload: str, box_size: int = 12, border: int = 3) -> bytes:
    import qrcode

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    if _HAS_PIL:
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    # 没有 Pillow：直接拼 SVG，浏览器/相机都能扫
    return qr_svg(payload, border).encode("utf-8")


def qr_svg(payload: str, border: int = 2) -> str:
    import qrcode
    import qrcode.image.svg

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=border, box_size=10)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")
