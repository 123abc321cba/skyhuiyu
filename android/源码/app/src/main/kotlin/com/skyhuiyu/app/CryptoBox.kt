package com.skyhuiyu.app

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ECDH P-256 + HKDF-SHA256 + AES-256-GCM
 *
 * 与 PC 端 `skyhuiyu/crypto.py`、iOS 端 `CryptoBox.swift` 严格对齐，
 * **这几个常量一个都不能改**，否则 PC 解不开：
 *
 *   共享密钥 = ECDH 的 X 坐标 32B
 *   派生      = HKDF-SHA256(salt="SkyHuiyuProto2024", info="session-key", len=32)
 *   密文格式  = nonce(12) || ciphertext || tag(16)
 *   公钥格式  = SEC1 X9.62 未压缩点 65B（04||X||Y）
 *   nonce     = 8 字节小端自增计数器 + 4 字节随机
 */
class CryptoBox private constructor(private val keyPair: KeyPair) {

    private var aesKey: SecretKeySpec? = null
    private var sendNonce: Long = 0
    private var recvNonce: Long = 0
    private val random = SecureRandom()

    companion object {
        private const val CURVE = "secp256r1"
        private const val HKDF_SALT = "SkyHuiyuProto2024"
        private const val HKDF_INFO = "session-key"

        /**
         * 从持久化的 (PKCS#8 私钥, X.509 公钥) 恢复身份；任一缺失/损坏就新建一把。
         * 返回 (box, 是否是新建的)。
         */
        fun identity(privPkcs8: ByteArray?, pubX509: ByteArray?): Pair<CryptoBox, Boolean> {
            if (privPkcs8 != null && pubX509 != null) {
                val restored = runCatching {
                    val kf = KeyFactory.getInstance("EC")
                    val priv = kf.generatePrivate(PKCS8EncodedKeySpec(privPkcs8))
                    val pub = kf.generatePublic(X509EncodedKeySpec(pubX509))
                    CryptoBox(KeyPair(pub, priv))
                }.getOrNull()
                if (restored != null) return Pair(restored, false)
            }
            return Pair(generate(), true)
        }

        fun generate(): CryptoBox {
            val gen = KeyPairGenerator.getInstance("EC")
            gen.initialize(ECGenParameterSpec(CURVE))
            return CryptoBox(gen.generateKeyPair())
        }

        /** 65 字节未压缩点 → ECPoint */
        fun pointFrom(raw: ByteArray): ECPoint? {
            if (raw.size != 65 || raw[0] != 0x04.toByte()) return null
            val x = BigInteger(1, raw.copyOfRange(1, 33))
            val y = BigInteger(1, raw.copyOfRange(33, 65))
            return ECPoint(x, y)
        }

        /** 定长 32 字节大端 */
        fun fixed32(v: BigInteger): ByteArray {
            val b = v.toByteArray()
            return when {
                b.size == 32 -> b
                b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
                else -> ByteArray(32 - b.size) + b
            }
        }

        fun hkdfSha256(ikm: ByteArray, salt: String, info: String, length: Int): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(salt.toByteArray(Charsets.UTF_8), "HmacSHA256"))
            val prk = mac.doFinal(ikm)
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(info.toByteArray(Charsets.UTF_8))
            mac.update(0x01)
            return mac.doFinal().copyOf(length)
        }
    }

    val privateKeyEncoded: ByteArray get() = keyPair.private.encoded

    /** X.509 编码的公钥，只用于持久化后恢复身份，不参与协议。 */
    val publicKeyEncodedX509: ByteArray get() = keyPair.public.encoded

    /** SEC1 未压缩点 04||X||Y（65 字节） */
    val publicKeyBytes: ByteArray
        get() {
            val pub = keyPair.public as ECPublicKey
            val x = fixed32(pub.w.affineX)
            val y = fixed32(pub.w.affineY)
            return byteArrayOf(0x04) + x + y
        }

    /** 标准 base64（PC 端只认带 padding 的这个） */
    val publicKeyBase64: String
        get() = android.util.Base64.encodeToString(publicKeyBytes, android.util.Base64.NO_WRAP)

    /** SHA256(公钥 65B) 前 8 字节的 hex */
    val fingerprint: String
        get() {
            val d = java.security.MessageDigest.getInstance("SHA-256").digest(publicKeyBytes)
            return d.copyOf(8).joinToString("") { "%02x".format(it) }
        }

    val isDerived: Boolean get() = aesKey != null

    /** 用对方的 65 字节公钥完成密钥交换 */
    fun derive(peerRaw: ByteArray) {
        val point = pointFrom(peerRaw) ?: throw CryptoError.InvalidPublicKey
        val params = (keyPair.private as ECPrivateKey).params
        val kf = KeyFactory.getInstance("EC")
        val peerPub = kf.generatePublic(ECPublicKeySpec(point, params))

        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(keyPair.private)
        ka.doPhase(peerPub, true)
        val shared = ka.generateSecret() // P-256 的 X 坐标，32B

        aesKey = SecretKeySpec(hkdfSha256(shared, HKDF_SALT, HKDF_INFO, 32), "AES")
        sendNonce = 0
        recvNonce = 0
    }

    /** 加密 → nonce(12) || ct || tag(16) */
    fun encrypt(plain: ByteArray): ByteArray {
        val key = aesKey ?: throw CryptoError.NotDerived
        val nonce = ByteArray(12)
        var v = sendNonce
        for (i in 0 until 8) {
            nonce[i] = (v and 0xFF).toByte()
            v = v shr 8
        }
        sendNonce += 1
        val rnd = ByteArray(4)
        random.nextBytes(rnd)
        System.arraycopy(rnd, 0, nonce, 8, 4)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
        val sealed = cipher.doFinal(plain) // ct || tag
        return nonce + sealed
    }

    /** 解密 ← nonce(12) || ct || tag(16) */
    fun decrypt(packet: ByteArray): ByteArray {
        val key = aesKey ?: throw CryptoError.NotDerived
        if (packet.size < 28) throw CryptoError.InvalidB64
        val nonce = packet.copyOfRange(0, 12)
        val body = packet.copyOfRange(12, packet.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
        return cipher.doFinal(body)
    }

    fun encryptJson(obj: Map<String, Any?>): String {
        val json = Jsonx.encode(obj).toByteArray(Charsets.UTF_8)
        return android.util.Base64.encodeToString(encrypt(json), android.util.Base64.NO_WRAP)
    }

    fun decryptJson(s: String): Map<String, Any?> {
        val raw = decodeB64Any(s) ?: throw CryptoError.InvalidB64
        val plain = decrypt(raw).toString(Charsets.UTF_8)
        return Jsonx.decodeObject(plain) ?: throw CryptoError.InvalidJson
    }

    /** 枚举不能继承类，这里用 sealed class + object（Kotlin 不允许 enum : Exception） */
    sealed class CryptoError(message: String) : Exception(message) {
        object InvalidPublicKey : CryptoError("无效的 PC 公钥")
        object NotDerived : CryptoError("未完成密钥交换")
        object InvalidB64 : CryptoError("无效的 Base64 数据")
        object InvalidJson : CryptoError("无效的 JSON 数据")
    }
}

/** hex / 标准 base64 / urlsafe base64 全收 */
fun decodeB64Any(s: String): ByteArray? {
    val t = s.trim().trim('"', '\'')
    if (t.isEmpty()) return null
    val padded = if (t.length % 4 == 0) t else t + "=".repeat(4 - t.length % 4)
    runCatching {
        return android.util.Base64.decode(padded, android.util.Base64.DEFAULT)
    }
    val u = padded.replace('-', '+').replace('_', '/')
    return runCatching { android.util.Base64.decode(u, android.util.Base64.DEFAULT) }.getOrNull()
}

/** 65 字节公钥：hex(130) 或 base64 都收 */
fun decodeKeyAny(s: String): ByteArray? {
    val t = s.trim().trim('"', '\'')
    if (t.isEmpty()) return null
    if (t.length == 130 && t.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
        val out = ByteArray(65)
        for (i in 0 until 65) {
            out[i] = t.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }
    val d = decodeB64Any(t)
    return if (d != null && d.size == 65) d else null
}
