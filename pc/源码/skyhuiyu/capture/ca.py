"""本地 CA —— 签发叶子证书 + 装进 **CurrentUser\\ROOT**。

为什么是 CurrentUser 而不是 LocalMachine：游戏的 Schannel 链路（.NET/WinHTTP）
校验的是当前用户那份根存储，启动器的 CEF 又走自己的 root store 索引；
实测 LocalMachine 装了照样 `unknown ca`，装进 CurrentUser 后同一份证书
`Build=True`，含在线吊销检查也过。

这里不用 `certutil` 子进程：打包成 exe 后 PATH 不一定有它，而且多一次进程
启动就多一次被杀软盯上的机会。直接 crypt32。
"""

from __future__ import annotations

import ctypes
import datetime as _dt
import hashlib
import os
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CN = "Sky Huiyu Local Proxy CA"

# ---- crypt32 常量 ----
CERT_STORE_PROV_SYSTEM_W = ctypes.cast(10, ctypes.c_void_p)
CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
CERT_FIND_HASH = 0x00010000
CERT_STORE_ADD_REPLACE_EXISTING = 2


class CaptureError(RuntimeError):
    """抓取栈的显式错误：带稳定 code，方便上层翻译成人话。"""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class _CRYPT_HASH_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _crypt32():  # noqa: ANN202 - ctypes 句柄
    if os.name != "nt":
        raise CaptureError("ca_install_unsupported", "证书自动安装只实现 Windows")
    lib = ctypes.WinDLL("crypt32", use_last_error=True)
    lib.CertOpenStore.restype = ctypes.c_void_p
    lib.CertOpenStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, ctypes.c_void_p]
    lib.CertAddEncodedCertificateToStore.restype = wintypes.BOOL
    lib.CertAddEncodedCertificateToStore.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.c_char_p, wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    lib.CertFindCertificateInStore.restype = ctypes.c_void_p
    lib.CertFindCertificateInStore.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p]
    lib.CertDeleteCertificateFromStore.restype = wintypes.BOOL
    lib.CertDeleteCertificateFromStore.argtypes = [ctypes.c_void_p]
    lib.CertCloseStore.restype = wintypes.BOOL
    lib.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    lib.CertFreeCertificateContext.restype = wintypes.BOOL
    lib.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    return lib


@dataclass
class LeafCert:
    cert_pem: bytes
    key_pem: bytes
    host: str


class LocalCA:
    """一份长期 CA + 按域名签叶子证书（叶子复用一个 EC 私钥，签得快）。"""

    def __init__(self, cert_dir: str | Path) -> None:
        self.dir = Path(cert_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.dir / "ca-key.pem"
        self.cert_path = self.dir / "ca-cert.pem"
        self.leaf_key_path = self.dir / "leaf-key.pem"
        self._leaves: dict[str, LeafCert] = {}
        self._leaf_key = None

    # ---------------------------------------------------------------- 生成
    def load_or_create(self) -> None:
        if self.cert_path.exists() and self.key_path.exists():
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_CN),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SkyHuiyu Bridge"),
        ])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(digital_signature=False, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=True, crl_sign=True,
                              encipher_only=False, decipher_only=False),
                critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256())
        )
        self.key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    @property
    def cert(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.cert_path.read_bytes())

    @property
    def key(self):  # noqa: ANN201
        return serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)

    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.der()).hexdigest()

    @property
    def thumbprint_sha1(self) -> str:
        return self.cert.fingerprint(hashes.SHA1()).hex()

    # ---------------------------------------------------------------- 叶子
    def _shared_leaf_key(self):  # noqa: ANN202
        if self._leaf_key is not None:
            return self._leaf_key
        if self.leaf_key_path.exists():
            self._leaf_key = serialization.load_pem_private_key(
                self.leaf_key_path.read_bytes(), password=None)
            return self._leaf_key
        key = ec.generate_private_key(ec.SECP256R1())
        self.leaf_key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self._leaf_key = key
        return key

    def leaf(self, host: str) -> LeafCert:
        """给 host 签一张叶子证书（内存缓存）。"""
        hit = self._leaves.get(host)
        if hit is not None:
            return hit
        key = self._shared_leaf_key()
        now = _dt.datetime.now(_dt.timezone.utc)
        san: list[x509.GeneralName] = []
        try:
            import ipaddress

            san.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            san.append(x509.DNSName(host))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(hours=1))
            .not_valid_after(now + _dt.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.KeyUsage(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False, crl_sign=False,
                              encipher_only=False, decipher_only=False),
                critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.cert.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        out = LeafCert(
            cert_pem=cert.public_bytes(serialization.Encoding.PEM),
            key_pem=key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()),
            host=host,
        )
        self._leaves[host] = out
        return out

    # --------------------------------------------------- CurrentUser\ROOT
    def is_installed(self) -> bool:
        if os.name != "nt":
            return False
        lib = _crypt32()
        store = lib.CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, None,
            CERT_SYSTEM_STORE_CURRENT_USER, ctypes.c_wchar_p("ROOT"))
        if not store:
            raise CaptureError("ca_install_failed", f"打不开 CurrentUser\\ROOT ({ctypes.get_last_error()})")
        try:
            der = self.der()
            sha1 = self.cert.fingerprint(hashes.SHA1())
            buf = (ctypes.c_ubyte * len(sha1)).from_buffer_copy(sha1)
            blob = _CRYPT_HASH_BLOB(len(sha1), buf)
            found = lib.CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH,
                ctypes.byref(blob), None)
            if found:
                lib.CertFreeCertificateContext(found)
                return True
            return False
        finally:
            lib.CertCloseStore(store, 0)

    def install(self) -> bool:
        """装进 CurrentUser\\ROOT。已存在返回 False（不重复装）。"""
        if os.name != "nt":
            raise CaptureError("ca_install_unsupported", "证书自动安装只实现 Windows")
        if self.is_installed():
            return False
        lib = _crypt32()
        store = lib.CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, None,
            CERT_SYSTEM_STORE_CURRENT_USER, ctypes.c_wchar_p("ROOT"))
        if not store:
            raise CaptureError("ca_install_failed",
                               f"打不开 CurrentUser\\ROOT ({ctypes.get_last_error()})")
        try:
            der = self.der()
            ok = lib.CertAddEncodedCertificateToStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der, len(der),
                CERT_STORE_ADD_REPLACE_EXISTING, None)
            if not ok:
                raise CaptureError("ca_install_failed",
                                   f"CertAddEncodedCertificateToStore 失败 "
                                   f"({ctypes.get_last_error()})")
        finally:
            lib.CertCloseStore(store, 0)
        return True

    def uninstall(self) -> bool:
        """从 CurrentUser\\ROOT 删除（按 SHA1 精确找）。没有返回 False。"""
        if os.name != "nt":
            return False
        lib = _crypt32()
        store = lib.CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, None,
            CERT_SYSTEM_STORE_CURRENT_USER, ctypes.c_wchar_p("ROOT"))
        if not store:
            return False
        try:
            sha1 = self.cert.fingerprint(hashes.SHA1())
            buf = (ctypes.c_ubyte * len(sha1)).from_buffer_copy(sha1)
            blob = _CRYPT_HASH_BLOB(len(sha1), buf)
            found = lib.CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH,
                ctypes.byref(blob), None)
            if not found:
                return False
            try:
                return bool(lib.CertDeleteCertificateFromStore(found))
            finally:
                # CertDeleteCertificateFromStore 成功时会释放 context，失败时要自己放
                pass
        finally:
            lib.CertCloseStore(store, 0)
