import Combine
import SwiftUI

struct ContentView: View {
    @StateObject private var state = AppState()
    @StateObject private var connection = PCConnection()

    private let nfcReader = NFCReader()
    @State private var showQRScanner = false
    @State private var isProcessing = false
    @State private var didAutoConnect = false

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                ScrollView {
                    VStack(spacing: 18) {
                        statusCard
                        actionRow

                        if let inj = connection.lastInject {
                            injectCard(inj)
                        }
                        if !state.records.isEmpty {
                            historyCard
                        }
                        if let error = state.lastError {
                            Text(error)
                                .font(.caption)
                                .foregroundColor(.red)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal)
                        }
                        if let warn = connection.identityWarning {
                            Text(warn)
                                .font(.caption2)
                                .foregroundColor(.orange)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal)
                        }
                    }
                    .padding()
                }
            }
            .sheet(isPresented: $showQRScanner) {
                QRScannerView(onScan: { code in handleScan(code) },
                              onDismiss: { showQRScanner = false })
                    .ignoresSafeArea()
            }
        }
        .onReceive(connection.$status) { newStatus in
            state.connectionStatus = newStatus
            state.isConnected = connection.connected
        }
        .task {
            // 启动时用上次配对自动重连（不用每次重新扫码）
            guard !didAutoConnect else { return }
            didAutoConnect = true
            if let p = state.pairing {
                await connect(pairing: p, silent: true)
            }
        }
    }

    // MARK: - 状态卡

    private var statusCard: some View {
        VStack(spacing: 8) {
            Image(systemName: connectionIcon)
                .font(.system(size: 42))
                .foregroundColor(connectionColor)
                .symbolEffect(.pulse, isActive: isProcessing)

            Text(connection.status)
                .font(.title3.bold())
                .foregroundColor(.white)

            Text(state.pairing.map { "已配对 \($0.display)" } ?? "扫描 PC 上的二维码开始")
                .font(.subheadline)
                .foregroundColor(.gray)

            if !connection.serverFingerprint.isEmpty {
                Text("PC 指纹 \(connection.serverFingerprint)")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(.gray.opacity(0.7))
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .background(Color.white.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 18))
    }

    // MARK: - 按钮

    private var actionRow: some View {
        HStack(spacing: 12) {
            tile(icon: "qrcode.viewfinder", title: "配对", bg: Color.blue.opacity(0.3)) {
                showQRScanner = true
            }
            tile(icon: "radiowaves.right", title: "扫描徽章",
                 bg: isProcessing ? Color.gray.opacity(0.4) : Color.orange.opacity(0.32),
                 disabled: isProcessing || !connection.connected) {
                scanBadge()
            }
            if connection.connected {
                tile(icon: "xmark.circle", title: "断开", bg: Color.red.opacity(0.28)) {
                    disconnect()
                }
            } else {
                tile(icon: "arrow.clockwise", title: "重连",
                     bg: Color.green.opacity(0.25),
                     disabled: state.pairing == nil) {
                    retryConnect()
                }
            }
        }
        .foregroundColor(.white)
    }

    private func tile(icon: String, title: String, bg: Color,
                      disabled: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 6) {
                Image(systemName: icon).font(.title)
                Text(title).font(.caption)
            }
            .frame(maxWidth: .infinity)
            .frame(height: 76)
            .background(bg)
            .clipShape(RoundedRectangle(cornerRadius: 14))
        }
        .buttonStyle(.plain)
        .disabled(disabled)
    }

    // MARK: - PC 应答

    private func injectCard(_ inj: [String: Any]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("PC 应答").font(.caption).foregroundColor(.gray)
            Text(prettify(inj))
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.green.opacity(0.9))
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(11)
        .background(Color.white.opacity(0.04))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - 历史

    private var historyCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("发送历史").font(.subheadline.bold()).foregroundColor(.gray)
                Spacer()
                Button("清空") { state.clearHistory() }
                    .font(.caption)
                    .foregroundColor(.gray)
            }
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(state.records) { record in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(record.uid)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundColor(.white)
                                Text("#\(record.counter) · \(record.timestamp, style: .time)")
                                    .font(.caption2).foregroundColor(.gray)
                                if !record.detail.isEmpty {
                                    Text(record.detail)
                                        .font(.caption2)
                                        .foregroundColor(.orange.opacity(0.85))
                                        .lineLimit(2)
                                }
                            }
                            Spacer()
                            if record.status == .failed {
                                Button("重发") { resend(record) }
                                    .font(.caption2)
                            }
                            statusBadge(record.status)
                        }
                        .padding(.vertical, 6)
                        Divider().background(Color.white.opacity(0.1))
                    }
                }
            }
        }
        .padding(12)
        .frame(maxHeight: 300)
        .background(Color.white.opacity(0.04))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var connectionIcon: String {
        if isProcessing { return "arrow.triangle.2.circlepath" }
        if connection.connected { return "checkmark.shield.fill" }
        return "wifi.slash"
    }

    private var connectionColor: Color {
        if isProcessing { return .orange }
        if connection.connected { return .green }
        return .gray
    }

    @ViewBuilder
    private func statusBadge(_ status: BadgeRecord.Status) -> some View {
        switch status {
        case .read:    Text("📖").font(.caption)
        case .sending: ProgressView().scaleEffect(0.7)
        case .sent:    Text("✅").font(.caption)
        case .failed:  Text("❌").font(.caption)
        }
    }

    private func prettify(_ d: [String: Any]) -> String {
        if let data = try? JSONSerialization.data(withJSONObject: d, options: [.sortedKeys, .prettyPrinted]),
           let s = String(data: data, encoding: .utf8) {
            return s
        }
        return "\(d)"
    }

    // MARK: - Actions

    /// 解析二维码：JSON / skyhuiyu:// / ws:// 三种都收
    private func handleScan(_ code: String) {
        state.lastError = nil
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        var pairing: PairingInfo?

        if let data = trimmed.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let pubkey = obj["pubkey"] as? String,
           let host = obj["host"] as? String {
            let port = (obj["port"] as? Int)
                ?? (obj["port"] as? Double).map { Int($0) }
                ?? (obj["port"] as? String).flatMap { Int($0) }
                ?? 8765
            pairing = PairingInfo(host: host, port: port, pubkey: pubkey,
                                  fingerprint: (obj["fingerprint"] as? String) ?? "")
        } else if let url = URLComponents(string: trimmed),
                  let host = url.host,
                  trimmed.hasPrefix("skyhuiyu://") || trimmed.hasPrefix("ws://") || trimmed.hasPrefix("http://") {
            var port = url.port ?? 8765
            var pk = ""
            for item in url.queryItems ?? [] where item.name == "pk" || item.name == "pubkey" {
                pk = item.value ?? ""
            }
            if let m = url.port, m > 0 { port = m }
            if !pk.isEmpty {
                pairing = PairingInfo(host: host, port: port, pubkey: pk, fingerprint: "")
            }
        }

        guard let p = pairing, !p.pubkey.isEmpty else {
            state.lastError = "无效的二维码：请在 PC 面板上扫 /pair.png 那张"
            return
        }

        state.setPairing(p)
        Task { await connect(pairing: p, silent: false) }
    }

    private func connect(pairing p: PairingInfo, silent: Bool) async {
        guard let ws = p.wsURL else {
            state.lastError = "无法构造 WebSocket 地址（检查 host/port）"
            return
        }
        do {
            state.lastError = nil
            try await connection.connect(url: ws, pcPubkey: p.pubkey)
        } catch {
            if !silent {
                state.lastError = "连接失败：\(error.localizedDescription)"
            } else {
                state.connectionStatus = "自动重连失败，点「重连」或重新扫码"
            }
        }
    }

    private func retryConnect() {
        guard let p = state.pairing else { return }
        Task { await connect(pairing: p, silent: false) }
    }

    private func scanBadge() {
        isProcessing = true
        state.lastError = nil

        nfcReader.scan { badge in
            state.addRecord(badge)
            let rid = badge.id
            Task { await send(badge, recordID: rid) }
        } onError: { error in
            state.lastError = error
            isProcessing = false
        }
    }

    private func send(_ badge: BadgeRecord, recordID: UUID) async {
        state.updateStatus(recordID, status: .sending)
        do {
            let (ok, detail, _) = try await connection.sendBadge(badge)
            state.updateStatus(recordID, status: ok ? .sent : .failed, detail: ok ? "" : detail)
            if !ok {
                state.lastError = "PC 返回：\(detail)"
            }
        } catch {
            state.updateStatus(recordID, status: .failed, detail: error.localizedDescription)
            state.lastError = "发送失败：\(error.localizedDescription)"
            await connection.reconnectIfPossible()
        }
        isProcessing = false
    }

    private func resend(_ record: BadgeRecord) {
        Task { await send(record, recordID: record.id) }
    }

    private func disconnect() {
        connection.disconnect()
        state.isConnected = false
    }
}
