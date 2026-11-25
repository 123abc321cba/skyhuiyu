import AVFoundation
import SwiftUI
import UIKit

/// QR 码扫描器 —— 获取 PC 服务器信息
/// 扫码内容支持三种形态（PC 端默认发第一种）：
///   1. JSON:   {"pubkey":"base64公钥","host":"192.168.x.x","port":8765}
///   2. URL:    skyhuiyu://192.168.x.x:8765?pk=<base64公钥>
///   3. URL:    ws://192.168.x.x:8765/badge?pk=<base64公钥>
struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void
    let onDismiss: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onScan: onScan, onDismiss: onDismiss)
    }

    func makeUIViewController(context: Context) -> ScannerVC {
        ScannerVC(delegate: context.coordinator)
    }

    func updateUIViewController(_ uiViewController: ScannerVC, context: Context) {}

    class Coordinator: NSObject, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
        let onScan: (String) -> Void
        let onDismiss: () -> Void
        private var fired = false

        init(onScan: @escaping (String) -> Void, onDismiss: @escaping () -> Void) {
            self.onScan = onScan
            self.onDismiss = onDismiss
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput,
                            didOutput metadataObjects: [AVMetadataObject],
                            from connection: AVCaptureConnection) {
            // 一次扫描只触发一次，避免连续回调造成多次连接
            guard !fired,
                  let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                  let code = obj.stringValue else { return }
            fired = true
            onScan(code)
            onDismiss()
        }
    }
}

final class ScannerVC: UIViewController {
    private let delegate: AVCaptureMetadataOutputObjectsDelegate
    private var session: AVCaptureSession?
    private var previewLayer: AVCaptureVideoPreviewLayer?

    init(delegate: AVCaptureMetadataOutputObjectsDelegate) {
        self.delegate = delegate
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        setupCamera()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        session?.stopRunning()
    }

    private func setupCamera() {
        // 没授权就主动要一次，别静默黑屏
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            break
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] ok in
                guard ok else { return }
                // 用 Task 跳主线程而不是 DispatchQueue.main.async：
                // 后者在 Swift 6 的 overlay 下被标 @Sendable，会丢掉主角隔离
                Task { @MainActor in self?.setupCamera() }
            }
            return
        default:
            showHint("相机权限被拒绝，去 设置 > SkyHuiyu 打开相机")
            return
        }

        let session = AVCaptureSession()
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            showHint("没有可用相机")
            return
        }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(delegate, queue: .main)
            output.metadataObjectTypes = [.qr]
        }

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.frame = view.bounds
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)
        previewLayer = preview
        self.session = session

        DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
    }

    private func showHint(_ text: String) {
        let label = UILabel()
        label.text = text
        label.textColor = .white
        label.numberOfLines = 0
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            label.widthAnchor.constraint(lessThanOrEqualTo: view.widthAnchor, multiplier: 0.8),
        ])
    }
}
