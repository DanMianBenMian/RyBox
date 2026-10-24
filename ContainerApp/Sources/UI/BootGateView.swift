import SwiftUI

/// RyBox first-run gate. The container needs a signing identity before it can
/// behave like a system — every guest (including the built-in Sileo) is signed
/// with the user's certificate, so the "进入系统" step is gated on that alone.
///
/// The virtual root (jbroot) is populated AUTOMATICALLY at launch from a bundled
/// Procursus bootstrap package (`Preinstalled/ProcursusBootstrap.zip`), so there
/// is no longer a manual "导入固件" step. The user never has to supply a system
/// image; RyBox ships a minimal, standard jbroot instead.
struct BootGate {
    private static let key = "rybox.boot.completed"
    static var isCompleted: Bool { UserDefaults.standard.bool(forKey: key) }
    static func markCompleted() { UserDefaults.standard.set(true, forKey: key) }
}

struct BootGateView: View {
    let onFinish: () -> Void

    @ObservedObject private var cert = CertificateStore.shared

    @State private var p12Password = ""
    @State private var p12Name = "未选择"
    @State private var provName = "未选择"
    @State private var stagedP12: Data?
    @State private var stagedProv: Data?
    @State private var message = ""
    @State private var busy = false

    private var certDone: Bool { cert.isConfigured }

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
                    jbrootCard
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
            Text("只需配置签名证书，RyBox 即会自带一个最小 jbroot（dpkg / apt / 标准 /usr /var 布局），无需再导入任何系统固件。")
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

    // MARK: Step 2 — jbroot (automatic, informational)

    private var jbrootCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            stepHeader(index: 2, title: "虚拟根（jbroot）", done: true)

            Label("启动时自动解压内置 Procursus bootstrap", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.footnote)

            Text("RyBox 不再从 IPSW / .ryboxenv 还原真实系统文件，而是自带一个最小、标准 jbroot（含 dpkg、apt、/usr、/var 与包管理数据库）。Sileo 打开后直接调用 jbroot 里的工具与数据库，无需任何手动步骤。")
                .font(.caption2)
                .foregroundStyle(.white.opacity(0.7))
                .fixedSize(horizontal: false, vertical: true)

            if let info = JbRoot.shared.statusLine {
                Text(info)
                    .font(.caption2)
                    .foregroundStyle(.white.opacity(0.85))
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
            .disabled(!certDone)

            if !certDone {
                Text("还需配置证书")
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
                        self.message = "证书已就绪，但描述文件有问题：\(m.message)"
                    } else {
                        self.message = "证书已就绪（p12 导入成功）"
                    }
                case .failure(let m):
                    self.message = m.message
                }
            }
        }
    }
}
