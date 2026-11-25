import Foundation

/// 本地持久化：配对信息 + 发送历史 + rid 计数器。
///
/// 为什么要 rid 落盘：PC 端的幂等键是 (device_id, rid)。
/// 如果 rid 每次启动都从 1 开始，第二天再发第一枚章就会命中昨天的回执，
/// 手机看到"成功"但 PC 根本没提交 —— 这是必须避免的静默错误。
enum PairStore {
    private static let pairKey = "skyhuiyu.pairing.v1"
    private static let recordsKey = "skyhuiyu.records.v1"
    private static let ridKey = "skyhuiyu.rid.v1"

    struct Snapshot {
        var pairing: PairingInfo?
        var records: [BadgeRecord]
    }

    static func load() -> Snapshot {
        let d = UserDefaults.standard
        var pairing: PairingInfo?
        if let raw = d.data(forKey: pairKey) {
            pairing = try? JSONDecoder().decode(PairingInfo.self, from: raw)
        }
        var records: [BadgeRecord] = []
        if let raw = d.data(forKey: recordsKey) {
            records = (try? JSONDecoder().decode([BadgeRecord].self, from: raw)) ?? []
        }
        return Snapshot(pairing: pairing, records: records)
    }

    static func save(pairing: PairingInfo?, records: [BadgeRecord]) {
        let d = UserDefaults.standard
        if let p = pairing, let raw = try? JSONEncoder().encode(p) {
            d.set(raw, forKey: pairKey)
        } else {
            d.removeObject(forKey: pairKey)
        }
        if let raw = try? JSONEncoder().encode(records) {
            d.set(raw, forKey: recordsKey)
        }
    }

    // MARK: - rid（跨启动单调递增）

    static func nextRid() -> Int {
        let d = UserDefaults.standard
        let n = d.integer(forKey: ridKey) + 1
        d.set(n, forKey: ridKey)
        return n
    }

    static var currentRid: Int {
        UserDefaults.standard.integer(forKey: ridKey)
    }

    static func resetAll() {
        let d = UserDefaults.standard
        d.removeObject(forKey: pairKey)
        d.removeObject(forKey: recordsKey)
        d.removeObject(forKey: ridKey)
    }
}
