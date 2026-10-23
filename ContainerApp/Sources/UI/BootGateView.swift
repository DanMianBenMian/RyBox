import SwiftUI

/// RyBox first-run gate: the container cannot behave like a system until it
/// has (1) a signing identity and (2) a firmware to restore the environment
/// from. Both steps are MANDATORY — the desktop is not reachable before them.
///
///   1. 证书   : .p12 (+ password) + .mobileprovision  -> CertificateStore
///   2. 固件   : .ryboxenv (complete env package) or .ipsw (raw Apple archive)
///               -> FirmwareImporter unpacks into the virtual root
///   3. 进入系统 : Sileo is installed automatically right after.
struct BootGate {
    private static let key = "rybox.boot.completed"
    static var isCompleted: Bool { UserDefaults.standard.bool(forKey: key) }
    static func markCompleted() { UserDefaults.standard.set(true, forKey: key) }
}

struct BootGateView: View {
    let onFinish: () -> Void

    @ObservedObject private var cert = CertificateStore.shared
    @ObservedObject private var fw = FirmwareImporter.shared

    @State private var p12Password = ""
    @State private var p12Name = "未选择"
    @State private var provName = "未选择"
    @State private var stagedP12: Data?
    @State private var stagedProv: Data?
    @State private var message = ""
    @State private var busy = false

    private var certDone: Bool { cert.isConfigured }
    private var fwDone: Bool { fw.isSatisfied }

    var body: some View {
        ZStack {
            LinearGradient(colors: [Color(red: 0.06, green: 0.10, blue: 0.28),
                                    Color(red: 0.16, green: 0.28, blue: 0.62)],
                           startPoint: .topLeading, endPoint: .bottomTrailing)
                .ignoresSafeArea()

            ScrollView {
                VStack(spacing: 22) {
                    header
                    certCard
                    firmwareCard
                    enterButton
                    Spacer(minLength: 20)
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 30)
            }
        }
    }

    // MARK: Header

    private var header: some View {
        VStack(spacing: 8) {
            Image(systemName: "shippingbox.fill")
                .font(.system(size: 44))
                .foregroundStyle(.white)
            Text("RyBox 初始设置")
                .font(.title.bold())
                .foregroundStyle(.white)
            Text("需要先准备签名证书与系统固件，RyBox 才能还原出一个可用的系统环境。")
                .font(.footnote)
                .foregroundStyle(.white.opacity(0.75))
                .multilineTextAlignment(.center)
        }
        .padding(.bottom, 6)
    }

    // MARK: Step 1 — certificate

    private var certCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            stepHeader(index: 1, title: "签名证书", done: certDone)

            row(title: "证书（p12 / pfx）", value: p12Name) { pickP12() }
            SecureField("p12 密码（可为空）", text: $p12Password)
                .textFieldStyle(.roundedBorder)
            row(title: "描述文件（.mobileprovision）", value: provName) { pickProv() }
            Text("两栏都能选任意文件，RyBox 按内容自动判断它是证书还是描述文件。支持 OpenSSL 3 新式加密的 p12（PBES2 / AES-256-CBC），密码可为空。")
                .font(.caption2)
                .foregroundStyle(.white.opacity(0.6))
                .fixedSize(horizontal: false, vertical: true)

            Button {
                applyCert()
            } label: {
                HStack {
                    if busy { ProgressView().tint(.white) }
                    Text(certDone ? "重新应用证书" : "应用证书配置").bold()
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(stagedP12 == nil || stagedProv == nil)

            if certDone {
                Label("证书已就绪\(cert.teamIdentifier.map { " · Team \($0)" } ?? "")",
                      systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.footnote)
                if let info = cert.certificateInfo {
                    Text(info)
                        .font(.caption2)
                        .foregroundStyle(.white.opacity(0.7))
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if !message.isEmpty {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.white.opacity(0.9))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(18)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    // MARK: Step 2 — firmware

    private var firmwareCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            stepHeader(index: 2, title: "系统固件", done: fwDone)

            Text("导入 .ryboxenv 系统环境包（推荐，电脑上预处理好的完整 /usr /System 目录树），或直接导入 .ipsw 原厂固件（RyBox 会就地读取其中未加密的 manifest / kernelcache / trustcache）。")
                .font(.caption)
                .foregroundStyle(.white.opacity(0.72))
                .fixedSize(horizontal: false, vertical: true)

            Button {
                pickFirmware()
            } label: {
                Label(fwDone ? "重新导入固件" : "选择固件（.ryboxenv / .ipsw）",
                      systemImage: "square.and.arrow.down.on.square")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(fwDone ? .gray : .blue)

            if fw.phase == .scanning || fw.phase == .extracting {
                ProgressView(value: max(fw.progress, 0.05))
                    .progressViewStyle(.linear)
                Text(fw.message)
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.85))
            } else if let r = fw.report {
                VStack(alignment: .leading, spacing: 4) {
                    Label(r.kind == "ryboxenv" ? "系统环境已完整还原" : "固件已导入（部分）",
                          systemImage: r.aeaVolumes.isEmpty ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(r.aeaVolumes.isEmpty ? .green : .orange)
                    Text(FirmwareImporter.summary(r))
                        .font(.caption)
                        .foregroundStyle(.white.opacity(0.8))
                    ForEach(r.notes, id: \.self) { note in
                        Text(note)
                            .font(.caption2)
                            .foregroundStyle(.white.opacity(0.65))
                    }
                }
            } else if case .failed = fw.phase {
                Text(fw.message)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .padding(18)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    // MARK: Step 3 — enter

    private var enterButton: some View {
        VStack(spacing: 8) {
            Button {
                BootGate.markCompleted()
                onFinish()
            } label: {
                Label("进入系统", systemImage: "arrow.right.circle.fill")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)
            .tint(.green)
            .disabled(!(certDone && fwDone))

            if !(certDone && fwDone) {
                Text(certDone ? "还需导入固件" : "还需配置证书")
                    .font(.caption2)
                    .foregroundStyle(.white.opacity(0.7))
            }
        }
    }

    // MARK: Pieces

    private func stepHeader(index: Int, title: String, done: Bool) -> some View {
        HStack(spacing: 10) {
            ZStack {
                Circle()
                    .fill(done ? Color.green : Color.white.opacity(0.22))
                    .frame(width: 26, height: 26)
                if done {
                    Image(systemName: "checkmark").font(.system(size: 13, weight: .bold))
                        .foregroundStyle(.white)
                } else {
                    Text("\(index)").font(.system(size: 13, weight: .bold))
                        .foregroundStyle(.white)
                }
            }
            Text(title).font(.headline).foregroundStyle(.white)
            Spacer()
        }
    }

    private func row(title: String, value: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Text(title).foregroundStyle(.white)
                Spacer()
                Text(value).foregroundStyle(.white.opacity(0.65)).lineLimit(1)
                Image(systemName: "chevron.right").font(.caption)
                    .foregroundStyle(.white.opacity(0.5))
            }
            .padding(.vertical, 6)
        }
        .buttonStyle(.plain)
    }

    // MARK: Actions

    /// Pick a certificate file. The file's ROLE is detected from its CONTENT,
    /// not from its extension: .p12 / .pfx / .pem-converted / no-extension files
    /// all work, and picking a .mobileprovision here just fills the other slot
    /// instead of failing.
    private func pickP12() {
        message = "正在打开文件选择器…"
        DocPicker.present { result in
            switch result {
            case .success(let url): stageCertFile(url)
            case .failure(let e):
                message = "选择失败：\(e.localizedDescription)"
            }
        }
    }

    private func pickProv() {
        message = "正在打开文件选择器…"
        DocPicker.present { result in
            switch result {
            case .success(let url): stageCertFile(url)
            case .failure(let e):
                message = "选择失败：\(e.localizedDescription)"
            }
        }
    }

    private func stageCertFile(_ url: URL) {
        do {
            let data = try Data(contentsOf: url)
            let name = url.lastPathComponent
            if Self.looksLikeProvisioning(data) {
                stagedProv = data
                provName = name
                message = "已识别为描述文件：\(name)"
            } else {
                stagedP12 = data
                p12Name = name
                message = "已识别为证书：\(name)（\(data.count) 字节）"
            }
        } catch {
            message = "读取失败：\(error.localizedDescription)"
        }
    }

    private static func looksLikeProvisioning(_ data: Data) -> Bool {
        guard let s = String(data: data.prefix(1 << 20), encoding: .isoLatin1) else { return false }
        if s.contains("mobileprovision") { return true }
        if s.contains("<?xml"),
           (s.contains("TeamIdentifier") || s.contains("ProvisionedDevices")
            || s.contains("Entitlements") || s.contains("AppIDName")) { return true }
        return false
    }

    private func applyCert() {
        guard stagedP12 != nil else { message = "请先选择证书（p12 / pfx）"; return }
        guard stagedProv != nil else { message = "请先选择描述文件（.mobileprovision）"; return }
        let p12 = stagedP12!, prov = stagedProv!, pw = p12Password
        busy = true
        message = "正在导入证书…"
        DispatchQueue.global(qos: .userInitiated).async {
            let r12 = CertificateStore.shared.importP12(p12, password: pw)
            let rpv = CertificateStore.shared.importProvisioning(prov)
            DispatchQueue.main.async {
                self.busy = false
                switch r12 {
                case .success:
                    if case .failure(let m) = rpv {
                        self.message = "证书已就绪，但描述文件有问题：\(m)"
                    } else {
                        self.message = "证书已就绪（p12 导入成功）"
                    }
                case .failure(let m):
                    self.message = m
                }
            }
        }
    }

    private func pickFirmware() {
        message = "正在打开文件选择器…"
        // asCopy: TRUE is mandatory here. The open-in-place mode (asCopy:false)
        // looks better for a 10 GB IPSW, but on iPadOS 27 beta the picker never
        // delivers the selection, so the import silently stalls. The system
        // copies the file into our container instead.
        DocPicker.present(asCopy: true) { result in
            switch result {
            case .success(let url):
                // No extension gate: FirmwareImporter decides by CONTENT
                // (ryboxenv.json = env package, BuildManifest.plist = IPSW), so
                // an unknown suffix can never make a file un-pickable.
                self.fw.message = "已选择：\(url.lastPathComponent)"
                self.fw.ingest(url)
            case .failure(let e):
                self.fw.message = "选择失败：\(e.localizedDescription)"
                self.fw.phase = .failed
            }
        }
    }
}
