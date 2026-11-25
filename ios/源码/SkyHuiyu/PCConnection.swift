import Combine
import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// WebSocket 连接管理
/// 协议 (SkyHuiyu PC v1):
///   1. 连接 ws://host:port/badge
///   2. 收 server_hello {pubkey(base64), pubkey_hex, fingerprint, protocol, host, port}
///   3. 发 pairing {phone_pubkey(base64), data(base64)}
///   4. 发 badge  {phone_pubkey(base64), data(base64)}
///   5. 收单条应答 {status, message, inject, record}
///
/// v1.2 变更：
///   · 身份密钥持久化（Keychain），PC 端不会再把你当成新设备
///   · rid 跨启动递增并落盘，避免命中昨天的回执
///   · 校验 server_hello 的公钥是否等于二维码里的公钥（防中间人）
///   · 收应答时最多跳过 3 条非应答帧，防止将来 PC 推状态帧导致永久错位
///   · 真断了会按 1s/2s/4s 退避重连（最多 3 次），不再有假的重连字段
@MainActor
final class PCConnection: ObservableObject {
    @Published var status = "未连接"
    @Published var connected = false
    @Published var lastInject: [String: Any]?
    @Published var serverFingerprint = ""
    @Published var identityWarning: String?

    private var task: URLSessionWebSocketTask?
    private var session: URLSession?
    private var crypto: CryptoBox
    private var host = ""
    private var port = 8765
    private var pinnedPubkey = ""
    private var closedByUser = false
    private var reconnectTries = 0

    init() {
        let id = CryptoBox.identity()
        self.crypto = id.box
        self.identityWarning = id.warning
    }

    // MARK: - 连接

    func connect(url: URL, pcPubkey: String) async throws {
        closedByUser = false
        host = url.host ?? ""
        port = url.port ?? 8765
        pinnedPubkey = pcPubkey
        try await openSocket(url: url)
    }

    private func openSocket(url: URL) async throws {
        task?.cancel(with: .goingAway, reason: nil)
        session?.invalidateAndCancel()

        let cfg = URLSessionConfiguration.default
        cfg.waitsForConnectivity = false
        let s = URLSession(configuration: cfg)
        session = s
        let t = s.webSocketTask(with: url)
        task = t
        t.resume()

        status = "等待 PC 握手…"
        let helloMsg = try await receiveMessage()
        guard let hello = helloMsg,
              let pkRaw = hello["pubkey"] as? String else {
            throw ConnectionError.badHandshake
        }

        // 公钥解码：base64 / hex / urlsafe 全收
        guard let peerBytes = Self.decodeKeyAny(pkRaw), peerBytes.count == 65, peerBytes[0] == 0x04 else {
            throw ConnectionError.badHandshake
        }

        // 防中间人：二维码里的公钥就是唯一可信来源
        if !pinnedPubkey.isEmpty, let pinned = Self.decodeKeyAny(pinnedPubkey), pinned != peerBytes {
            throw ConnectionError.pubkeyMismatch
        }

        try crypto.derive(peerRaw: peerBytes)
        serverFingerprint = (hello["fingerprint"] as? String) ?? ""
        if let h = hello["host"] as? String, !h.isEmpty { host = h }
        if let p = hello["port"] as? Int {
            port = p
        } else if let p = hello["port"] as? Double {
            port = Int(p)
        }
        status = "密钥交换完成"

        let pairingPayload: [String: Any] = [
            "phone_pubkey": crypto.publicKeyBase64,
            "data": try crypto.encryptJSON([
                "type": "pairing",
                "fingerprint": crypto.fingerprint,
                "proto": 1,
                "device": Self.deviceName,
            ]),
        ]
        try await send(json: pairingPayload)

        let ack = try await receiveAck()
        guard let a = ack, (a["status"] as? String) == "ok" else {
            throw ConnectionError.badHandshake
        }
        connected = true
        reconnectTries = 0
        status = "已配对 ✓"
    }

    /// 断线后自动重连（用上次的地址与公钥）
    func reconnectIfPossible() async {
        guard !connected, !closedByUser, !host.isEmpty, !pinnedPubkey.isEmpty else { return }
        guard reconnectTries < 3 else { return }
        guard let url = URL(string: "ws://\(host):\(port)/badge") else { return }
        reconnectTries += 1
        status = "重连中（\(reconnectTries)/3）…"
        let secs = pow(2.0, Double(reconnectTries - 1))
        try? await Task.sleep(for: .seconds(secs))
        do {
            try await openSocket(url: url)
        } catch {
            status = "重连失败：\(error.localizedDescription)"
        }
    }

    // MARK: - 发送徽章

    /// 返回 (成功标志, 说明文字, 原始应答字典)
    func sendBadge(_ badge: BadgeRecord) async throws -> (Bool, String, [String: Any]?) {
        guard task != nil else { throw ConnectionError.notConnected }
        guard crypto.isDerived else { throw ConnectionError.badHandshake }

        // rid 必须跨启动递增：PC 的幂等键是 (device_id, rid)
        let myRid = PairStore.nextRid()

        let payload: [String: Any] = [
            "phone_pubkey": crypto.publicKeyBase64,
            "data": try crypto.encryptJSON([
                "type": "badge",
                "rid": myRid,
                "uid": badge.uid,
                "counter": badge.counter,
                "token": badge.token,
                "url": badge.rawURL,
            ]),
        ]
        try await send(json: payload)

        guard let a = try await receiveAck() else { throw ConnectionError.badAck }
        lastInject = a["inject"] as? [String: Any]

        let statusStr = (a["status"] as? String) ?? "error"
        let msg = (a["message"] as? String) ?? ""
        let injectObj = a["inject"] as? [String: Any]
        let injectOK = (injectObj?["ok"] as? Bool) ?? (statusStr == "ok")

        // 成功判据看 inject.ok，不看 status 字面量
        if statusStr == "ok", injectOK {
            return (true, msg.isEmpty ? "注入成功" : msg, a)
        }
        let detail = (injectObj?["detail"] as? String)
            ?? (injectObj?["error"] as? String)
            ?? msg
        return (false, detail.isEmpty ? "PC 处理失败" : detail, a)
    }

    // MARK: - 断开

    func disconnect() {
        closedByUser = true
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        session?.invalidateAndCancel()
        session = nil
        connected = false
        status = "已断开"
    }

    // MARK: - 底层收发

    private func send(json dict: [String: Any]) async throws {
        guard let t = task else { throw ConnectionError.notConnected }
        let data = try JSONSerialization.data(withJSONObject: dict)
        try await t.send(.data(data))
    }

    private func receiveMessage() async throws -> [String: Any]? {
        guard let t = task else { return nil }
        let msg = try await t.receive()
        switch msg {
        case .data(let d):
            return try JSONSerialization.jsonObject(with: d) as? [String: Any]
        case .string(let s):
            guard let d = s.data(using: .utf8) else { return nil }
            return try JSONSerialization.jsonObject(with: d) as? [String: Any]
        @unknown default:
            return nil
        }
    }

    /// 只取"应答帧"（带 status 字段）。最多跳过 3 条别的帧。
    private func receiveAck() async throws -> [String: Any]? {
        for _ in 0..<3 {
            guard let m = try await receiveMessage() else { return nil }
            if m["status"] != nil { return m }
        }
        return nil
    }

    // MARK: - 编码自适应

    static var deviceName: String {
        #if canImport(UIKit)
        return UIDevice.current.name
        #else
        return "iPhone"
        #endif
    }

    /// hex / 标准 base64 / urlsafe base64 全收，返回 65 字节未压缩点。
    /// 必须 nonisolated：CryptoBox 是普通类，它的同步方法在本类之外调用这三个函数，
    /// 不加就变成"从 nonisolated 上下文同步调用 MainActor 成员"，是硬编译错误。
    nonisolated static func decodeKeyAny(_ s: String) -> Data? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        if t.isEmpty { return nil }

        if t.count == 130, t.range(of: "^[0-9A-Fa-f]+$", options: .regularExpression) != nil {
            var d = Data(capacity: 65)
            var i = t.startIndex
            while i < t.endIndex {
                let j = t.index(i, offsetBy: 2)
                if let b = UInt8(t[i..<j], radix: 16) { d.append(b) }
                i = j
            }
            if d.count == 65 { return d }
        }
        if let d = decodeB64Any(t), d.count == 65 { return d }
        return nil
    }

    /// 标准 / urlsafe base64 都解，缺 padding 自动补
    nonisolated static func decodeB64Any(_ s: String) -> Data? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        if t.isEmpty { return nil }
        if let d = Data(base64Encoded: pad(t)) { return d }
        let u = t.replacingOccurrences(of: "-", with: "+")
                 .replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: pad(u))
    }

    nonisolated static func pad(_ s: String) -> String {
        let rem = s.count % 4
        return rem == 0 ? s : s + String(repeating: "=", count: 4 - rem)
    }
}

enum ConnectionError: Error, LocalizedError {
    case notConnected
    case badHandshake
    case badAck
    case pubkeyMismatch

    var errorDescription: String? {
        switch self {
        case .notConnected: "未连接到 PC"
        case .badHandshake: "PC 握手失败"
        case .badAck: "PC 响应异常"
        case .pubkeyMismatch: "公钥与二维码不一致（可能有中间人）"
        }
    }
}
