import CryptoKit
import Foundation
import Security

/// 手机身份密钥的持久化（Keychain）。
///
/// 为什么必须持久：PC 端把「设备」等同于「手机公钥的指纹」。
/// 每次启动都换密钥的话，PC 的设备列表会一天涨一条，白名单和回执全都对不上。
///
/// 如果 Keychain 不可用（极少数自签环境），这里返回 nil，
/// 上层会生成临时密钥并把真实原因显示在界面上 —— 不静默吞掉。
enum KeyVault {
    private static let service = "com.skyhuiyu.app"
    private static let account = "phone-identity-p256"

    static func loadPrivateKeyRaw() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data, data.count == 32 else {
            return nil
        }
        return data
    }

    @discardableResult
    static func savePrivateKeyRaw(_ data: Data) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil)
    }

    static func delete() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
