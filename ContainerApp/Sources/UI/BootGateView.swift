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

            row(title: "证书文件（.p12）", value: p12Name) { pickP12() }
            SecureField("p12 密码（可为空）", text: $p12Password)
                .textFieldStyle(.roundedBorder)
            row(title: "描述文件（.mobileprovision）", value: provName) { pickProv() }

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

    private func pickP12() {
        DocPicker.present { result in
            switch result {
            case .success(let url):
                guard url.pathExtension.lowercased() == "p12" else {
                    message = "请选择 .p12 文件（当前：\(url.lastPathComponent)）"
                    return
                }
                do {
                    stagedP12 = try Data(contentsOf: url)
                    p12Name = url.lastPathComponent
                    message = "已选择证书文件"
                } catch {
                    message = "读取失败：\(error.localizedDescription)"
                }
            case .failure(let e):
                message = "选择失败：\(e.localizedDescription)"
            }
        }
    }

    private func pickProv() {
        DocPicker.present { result in
            switch result {
            case .success(let url):
                guard url.pathExtension.lowercased() == "mobileprovision" else {
                    message = "请选择 .mobileprovision 文件（当前：\(url.lastPathComponent)）"
                    return
                }
                do {
                    stagedProv = try Data(contentsOf: url)
                    provName = url.lastPathComponent
                    message = "已选择描述文件"
                } catch {
                    message = "读取失败：\(error.localizedDescription)"
                }
            case .failure(let e):
                message = "选择失败：\(e.localizedDescription)"
            }
        }
    }

    private func applyCert() {
        guard let p12 = stagedP12, let prov = stagedProv else {
            message = "请先选择 p12 与 mobileprovision"
            return
        }
        busy = true
        message = "正在导入证书…"
        DispatchQueue.global(qos: .userInitiated).async {
            let okP12 = CertificateStore.shared.importP12(p12, password: p12Password)
            CertificateStore.shared.importProvisioning(prov)
            DispatchQueue.main.async {
                busy = false
                message = okP12
                    ? "证书已就绪（p12 导入成功）"
                    : "p12 导入失败：密码错误、文件损坏，或不是 PKCS#12 格式"
            }
        }
    }

    private func pickFirmware() {
        // asCopy: false — read the 10 GB IPSW in place instead of duplicating
        // it into our container.
        DocPicker.present(asCopy: false) { result in
            switch result {
            case .success(let url):
                let ext = url.pathExtension.lowercased()
                guard ext == "ryboxenv" || ext == "ipsw" else {
                    fw.message = "请选择 .ryboxenv 或 .ipsw 文件（当前：\(url.lastPathComponent)）"
                    fw.phase = .failed
                    return
                }
                fw.ingest(url)
            case .failure(let e):
                fw.message = "选择失败：\(e.localizedDescription)"
                fw.phase = .failed
            }
        }
    }
}
