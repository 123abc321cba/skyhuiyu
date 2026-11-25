import CoreNFC
import Foundation

/// NFC Forum URI 标识码表（0x00..0x23）。
/// 放在文件级而不是类里：类标了 @MainActor，静态属性会被隔离，
/// 而解析函数必须是 nonisolated 才能在 NFC 回调线程里用。
let kURIPrefixes: [UInt8: String] = [
    0x00: "", 0x01: "http://www.", 0x02: "https://www.", 0x03: "http://",
    0x04: "https://", 0x05: "tel:", 0x06: "mailto:",
    0x07: "ftp://anonymous:anonymous@", 0x08: "ftp://ftp.", 0x09: "ftps://",
    0x0A: "sftp://", 0x0B: "smb://", 0x0C: "nfs://", 0x0D: "ftp://",
    0x0E: "dav://", 0x0F: "news:", 0x10: "telnet://", 0x11: "imap:",
    0x12: "rtsp://", 0x13: "urn:", 0x14: "pop:", 0x15: "sip:",
    0x16: "sips:", 0x17: "tftp:", 0x18: "btspp://", 0x19: "btl2cap://",
    0x1A: "btgoep://", 0x1B: "tcpobex://", 0x1C: "irdaobex://",
    0x1D: "file://", 0x1E: "urn:epc:id:", 0x1F: "urn:epc:tag:",
    0x20: "urn:epc:pat:", 0x21: "urn:epc:raw:", 0x22: "urn:epc:",
    0x23: "urn:nfc:",
]

/// NFC NDEF 徽章读取器
///
/// 徽章里存的是 NDEF **URI 记录**，URL 形如：
///     https://sky.thatg.co/?s=TOKEN&c=UIDxCOUNTER
///
/// v1.2 关键修复（原来读不出章的根因）：
///   URI 记录的 payload 是 [URI 标识码 1 字节][后半段字符串]，
///   0x04 表示 "https://"、0x00 表示无前缀。
///   原代码直接 `String(data: payload)`，得到的是 "\u{04}sky.thatg.co/…"，
///   URLComponents 解不出 scheme，于是永远提示「未识别的徽章格式」。
///   现在按 NFC Forum URI Identifier Code 表把前缀补回去。
@MainActor
class NFCReader: NSObject, NFCTagReaderSessionDelegate {
    private var session: NFCTagReaderSession?
    private var onSuccess: ((BadgeRecord) -> Void)?
    private var onError: ((String) -> Void)?

    func scan(onSuccess: @escaping (BadgeRecord) -> Void, onError: @escaping (String) -> Void) {
        guard NFCTagReaderSession.readingAvailable else {
            onError("此设备不支持 NFC（或系统里未开启）")
            return
        }
        self.onSuccess = onSuccess
        self.onError = onError

        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
        session?.alertMessage = "把 NFC 徽章贴在手机顶部"
        session?.begin()
    }

    nonisolated func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    nonisolated func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        let msg: String?
        if let nfcError = error as? NFCReaderError,
           nfcError.code == .readerSessionInvalidationErrorFirstNDEFTagRead {
            msg = nil
        } else {
            msg = "NFC 会话结束：\(error.localizedDescription)"
        }
        Task { @MainActor in
            if let m = msg { self.onError?(m) }
        }
    }

    nonisolated func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let tag = tags.first else {
            session.invalidate(errorMessage: "未检测到标签")
            return
        }
        session.connect(to: tag) { error in
            if let error {
                session.invalidate(errorMessage: "连接失败：\(error.localizedDescription)")
                return
            }
            var ndefTag: NFCNDEFTag
            switch tag {
            case .miFare(let t): ndefTag = t
            case .iso7816(let t): ndefTag = t
            case .feliCa(let t): ndefTag = t
            case .iso15693(let t): ndefTag = t
            @unknown default:
                session.invalidate(errorMessage: "不支持的标签类型")
                return
            }

            ndefTag.queryNDEFStatus { status, _, error in
                if let error {
                    session.invalidate(errorMessage: "查询失败：\(error.localizedDescription)")
                    return
                }
                guard status == .readWrite || status == .readOnly else {
                    session.invalidate(errorMessage: "标签不支持 NDEF")
                    return
                }
                ndefTag.readNDEF { message, error in
                    if let error {
                        session.invalidate(errorMessage: "读取失败：\(error.localizedDescription)")
                        return
                    }
                    guard let message, let record = message.records.first else {
                        session.invalidate(errorMessage: "标签是空的")
                        return
                    }
                    guard let url = Self.urlString(from: record) else {
                        session.invalidate(errorMessage: "不是光遇徽章")
                        return
                    }
                    guard let parsed = Self.parseBadgeURL(url), parsed.valid else {
                        session.invalidate(errorMessage: "未识别的徽章格式：\(url.prefix(40))")
                        return
                    }

                    let badge = BadgeRecord(uid: parsed.uid, counter: parsed.counter,
                                            token: parsed.token, rawURL: parsed.url)
                    session.alertMessage = "读取成功：\(parsed.uid) #\(parsed.counter)"
                    session.invalidate()
                    Task { @MainActor in self.onSuccess?(badge) }
                }
            }
        }
    }

    // MARK: - NDEF → URL 字符串

    /// 把 URI 记录还原成完整 URL。兼容三种写法：
    ///   · 标准 URI 记录（首字节是标识码）
    ///   · 纯文本记录里直接写了完整 URL
    ///   · 首字节既不是合法标识码也不是可打印字符（厂商自定义）
    nonisolated static func urlString(from record: NFCNDEFPayload) -> String? {
        let raw = record.payload
        guard !raw.isEmpty else { return nil }

        // 1) 标准 URI 记录：首字节是标识码
        if let code = raw.first, let prefix = kURIPrefixes[code] {
            let rest = raw.dropFirst()
            if let s = String(data: rest, encoding: .utf8) {
                let joined = prefix + s
                if joined.lowercased().hasPrefix("http") { return joined }
                if !prefix.isEmpty { return joined }
            }
        }

        // 2) 整个 payload 就是字符串
        if let s = String(data: raw, encoding: .utf8) {
            let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.lowercased().hasPrefix("http") || trimmed.lowercased().hasPrefix("sky.") {
                return trimmed
            }
            // 3) 去掉不可打印首字节再试
            let cleaned = trimmed.drop { !$0.isLetter && !$0.isNumber }
            if !cleaned.isEmpty, cleaned.lowercased().hasPrefix("http") || cleaned.lowercased().hasPrefix("sky.") {
                return String(cleaned)
            }
        }
        return nil
    }

    // MARK: - 解析

    struct Parsed {
        var url: String
        var valid: Bool
        var uid: String
        var counter: Int
        var token: String
    }

    nonisolated static func parseBadgeURL(_ url: String) -> Parsed? {
        var cleaned = url.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        if cleaned.isEmpty { return nil }
        cleaned = cleaned.replacingOccurrences(of: "\u{00}", with: "")
        if cleaned.lowercased().hasPrefix("sky.") {
            cleaned = "https://" + cleaned
        }
        guard let comps = URLComponents(string: cleaned) else {
            return Parsed(url: cleaned, valid: false, uid: "", counter: 0, token: "")
        }
        var params: [String: String] = [:]
        for item in comps.queryItems ?? [] {
            params[item.name.lowercased()] = item.value ?? ""
        }
        let token = params["s"] ?? ""
        let cRaw = (params["c"] ?? "").trimmingCharacters(in: .whitespaces)

        let (uid, counter) = splitCounter(cRaw)
        let valid = !token.isEmpty && !uid.isEmpty
        return Parsed(url: cleaned, valid: valid, uid: uid, counter: counter, token: token)
    }

    /// "A1B2C3D4x1A" → ("A1B2C3D4", 26)；兼容大写 X、无 x、纯十进制/十六进制计数
    nonisolated static func splitCounter(_ raw: String) -> (String, Int) {
        let s = raw.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { return ("", 0) }

        // 从最后一个 x / X 处切开（UID 本身是十六进制，不会含 x）
        if let idx = s.lastIndex(where: { $0 == "x" || $0 == "X" }) {
            let uidPart = String(s[s.startIndex..<idx]).uppercased()
            let cntPart = String(s[s.index(after: idx)...])
            return (uidPart, Int(cntPart, radix: 16) ?? Int(cntPart) ?? 0)
        }
        // 没有分隔符：整个当 UID；若形如"前缀+数字"则退化为计数
        return (s.uppercased(), 0)
    }
}
