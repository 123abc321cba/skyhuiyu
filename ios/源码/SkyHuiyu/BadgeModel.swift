import Combine
import Foundation

// MARK: - 一枚徽章

struct BadgeRecord: Identifiable, Codable, Equatable {
    let id: UUID
    let uid: String
    var counter: Int
    let token: String
    let rawURL: String
    let timestamp: Date
    var status: Status
    /// PC 回来的 inject 说明（失败原因/官方判定），只用于展示
    var detail: String

    enum Status: String, Codable {
        case read
        case sending
        case sent
        case failed
    }

    init(uid: String, counter: Int, token: String, rawURL: String) {
        self.id = UUID()
        self.uid = uid
        self.counter = counter
        self.token = token
        self.rawURL = rawURL
        self.timestamp = Date()
        self.status = .read
        self.detail = ""
    }
}

// MARK: - 配对信息（扫码得到，持久化）

struct PairingInfo: Codable, Equatable {
    var host: String
    var port: Int
    /// PC 的 65 字节 SEC1 公钥，标准 base64
    var pubkey: String
    /// PC 指纹（SHA256 前 8 字节 hex），仅用于展示与防中间人
    var fingerprint: String

    var wsURL: URL? {
        URL(string: "ws://\(host):\(port)/badge")
    }

    var display: String { "\(host):\(port)" }
}

// MARK: - 全局状态（可持久化）

/// 故意不加 @MainActor：ContentView 里的同步调用点全在主线程，
/// 加了只会引入跨隔离诊断，不加更贴近原来能编译通过的结构。
final class AppState: ObservableObject {
    @Published var connectionStatus = "未连接"
    @Published var isConnected = false
    @Published var records: [BadgeRecord] = []
    @Published var lastError: String?
    @Published var pairing: PairingInfo?

    /// 记录上限：列表只留最近 200 条，避免 UserDefaults 无限膨胀
    private let maxRecords = 200

    init() {
        let saved = PairStore.load()
        self.pairing = saved.pairing
        self.records = saved.records
        if let p = saved.pairing {
            self.connectionStatus = "上次配对 \(p.display)"
        }
    }

    func addRecord(_ record: BadgeRecord) {
        records.insert(record, at: 0)
        if records.count > maxRecords {
            records = Array(records.prefix(maxRecords))
        }
        persist()
    }

    func updateStatus(_ id: UUID, status: BadgeRecord.Status, detail: String = "") {
        guard let i = records.firstIndex(where: { $0.id == id }) else { return }
        records[i].status = status
        if !detail.isEmpty { records[i].detail = detail }
        persist()
    }

    func setPairing(_ p: PairingInfo?) {
        pairing = p
        persist()
    }

    func clearHistory() {
        records = []
        persist()
    }

    func persist() {
        PairStore.save(pairing: pairing, records: records)
    }
}
