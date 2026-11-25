import CryptoKit
import Foundation
import Security

/// ECDH P-256 + HKDF-SHA256 + AES-256-GCM
/// 与 PC 端 skyhuiyu/crypto.py 严格对齐（**这几行常量一个都不能改**）：
///   共享密钥 = ECDH 的 X 坐标 32B
///   派生      = HKDF-SHA256(salt="SkyHuiyuProto2024", info="session-key", len=32)
///   密文格式  = nonce(12) || ciphertext || tag(16)
///   公钥格式  = SEC1 X9.62 未压缩点 65B（04||X||Y）
///   nonce     = 8 字节小端自增计数器 + 4 字节随机
///
/// v1.2 变更：
///   · 身份密钥可从 Keychain 恢复（CryptoBox.identity()），不再每次启动换钥匙
///   · 修正 deinit 的隔离问题（不再在 deinit 里碰 MainActor 状态）
class CryptoBox {
    private let privateKey: P256.KeyAgreement.PrivateKey
    private var sharedSecret: SharedSecret?
    private var symmetricKey: SymmetricKey?
    private var sendNonce: UInt64 = 0
    private var recvNonce: UInt64 = 0

    init() {
        self.privateKey = P256.KeyAgreement.PrivateKey()
    }

    init(privateKey: P256.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
    }

    /// 恢复持久身份；Keychain 不可用时退回临时身份，并把原因抛给调用方展示。
    static func identity() -> (box: CryptoBox, warning: String?) {
        if let raw = KeyVault.loadPrivateKeyRaw(),
           let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw) {
            return (CryptoBox(privateKey: key), nil)
        }
        let key = P256.KeyAgreement.PrivateKey()
        let status = KeyVault.savePrivateKeyRaw(key.rawRepresentation)
        if status == errSecSuccess {
            return (CryptoBox(privateKey: key), nil)
        }
        return (CryptoBox(privateKey: key),
                "身份密钥无法写入 Keychain（\(status)），重启后需要重新配对")
    }

    // MARK: - 公钥

    /// SEC1 未压缩点：04 || X(32) || Y(32) = 65 字节
    var publicKeyBytes: Data {
        privateKey.publicKey.x963Representation
    }

    /// 标准 base64（PC 端 v1.0 只认这个，必须带 padding）
    var publicKeyBase64: String {
        publicKeyBytes.base64EncodedString()
    }

    var publicKeyHex: String {
        publicKeyBytes.map { String(format: "%02x", $0) }.joined()
    }

    /// SHA256(公钥 65B) 前 8 字节
    var fingerprint: String {
        SHA256.hash(data: publicKeyBytes).prefix(8)
            .map { String(format: "%02x", $0) }.joined()
    }

    var isDerived: Bool { symmetricKey != nil }

    // MARK: - 派生

    func derive(peerRaw: Data) throws {
        guard peerRaw.count == 65, peerRaw[0] == 0x04 else {
            throw CryptoError.invalidPublicKey
        }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: peerRaw)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: peer)

        // CryptoKit 的 hkdfDerivedSymmetricKey 内部用 sharedSecret 的原始字节（X 坐标 32B）
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("SkyHuiyuProto2024".utf8),
            sharedInfo: Data("session-key".utf8),
            outputByteCount: 32
        )
        symmetricKey = key
        sharedSecret = shared
        sendNonce = 0
        recvNonce = 0
    }

    /// 兼容旧签名（传入 base64 公钥串）
    func derive(peerPubkeyBase64: String) throws {
        guard let raw = PCConnection.decodeKeyAny(peerPubkeyBase64) else {
            throw CryptoError.invalidPublicKey
        }
        try derive(peerRaw: raw)
    }

    // MARK: - 加解密

    /// 加密 -> nonce(12) || ciphertext || tag(16)
    func encrypt(plaintext: Data) throws -> Data {
        guard let key = symmetricKey else { throw CryptoError.notDerived }

        var nonceData = Data()
        nonceData.append(contentsOf: withUnsafeBytes(of: sendNonce.littleEndian) { Data($0) })
        var rnd = Data(count: 4)
        _ = rnd.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 4, $0.baseAddress!) }
        nonceData.append(rnd)
        sendNonce += 1

        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        return nonceData + sealed.ciphertext + sealed.tag
    }

    /// 解密 <- nonce(12) || ciphertext || tag(16)
    func decrypt(packet: Data) throws -> Data {
        guard let key = symmetricKey else { throw CryptoError.notDerived }
        guard packet.count >= 28 else { throw CryptoError.invalidB64 }

        let nonceData = packet.prefix(12)
        let ct = packet.dropFirst(12).dropLast(16)
        let tag = packet.suffix(16)

        let nonce = try AES.GCM.Nonce(data: nonceData)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        return try AES.GCM.open(box, using: key)
    }

    func encryptJSON(_ obj: [String: Any]) throws -> String {
        let json = try JSONSerialization.data(withJSONObject: obj)
        return try encrypt(plaintext: json).base64EncodedString()
    }

    /// base64 / urlsafe-base64 全收
    func decryptJSON(_ s: String) throws -> [String: Any] {
        guard let raw = PCConnection.decodeB64Any(s) else { throw CryptoError.invalidB64 }
        let plain = try decrypt(packet: raw)
        guard let obj = try JSONSerialization.jsonObject(with: plain) as? [String: Any] else {
            throw CryptoError.invalidJSON
        }
        return obj
    }
}

enum CryptoError: Error, LocalizedError {
    case invalidPublicKey
    case notDerived
    case invalidB64
    case invalidJSON

    var errorDescription: String? {
        switch self {
        case .invalidPublicKey: "无效的 PC 公钥"
        case .notDerived: "未完成密钥交换"
        case .invalidB64: "无效的 Base64 数据"
        case .invalidJSON: "无效的 JSON 数据"
        }
    }
}
