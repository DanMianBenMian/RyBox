import SwiftUI
import UniformTypeIdentifiers

/// Certificate & provisioning setup.
/// The whole import→sign→run chain depends on this being configured first.
struct SettingsView: View {
    @State private var showP12 = false
    @State private var showProv = false
    @State private var p12Password = ""
    @State private var p12Name: String = "未选择"
    @State private var provName: String = "未选择"
    @State private var message: String = ""

    /// Staged file contents (imported only when the user taps "应用配置").
    @State private var stagedP12: Data?
    @State private var stagedProv: Data?

    @ObservedObject private var store = CertificateStore.shared

    var body: some View {
        NavigationView {
            Form {
                Section("签名身份（p12）") {
                    HStack {
                        Text("证书文件")
                        Spacer()
                        Text(p12Name).foregroundColor(.secondary)
                    }
                    SecureField("p12 密码", text: $p12Password)
                    Button("选择 .p12") { showP12 = true }
                        .buttonStyle(.bordered)
                }

                Section("描述文件（mobileprovision）") {
                    HStack {
                        Text("描述文件")
                        Spacer()
                        Text(provName).foregroundColor(.secondary)
                    }
                    Button("选择 .mobileprovision") { showProv = true }
                        .buttonStyle(.bordered)
                }

                Section {
                    Button {
                        apply()
                    } label: {
                        Text("应用配置").bold()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(stagedP12 == nil || stagedProv == nil || p12Password.isEmpty)
                }

                Section("状态") {
                    HStack {
                        Text("是否已配置")
                        Spacer()
                        if store.isConfigured {
                            Label("已配置", systemImage: "checkmark.circle.fill")
                                .foregroundColor(.green)
                        } else {
                            Label("未配置", systemImage: "exclamationmark.circle")
                                .foregroundColor(.orange)
                        }
                    }
                    if let team = store.teamIdentifier {
                        HStack {
                            Text("Team ID")
                            Spacer()
                            Text(team).foregroundColor(.secondary)
                        }
                    }
                    if store.isConfigured {
                        Text("支持分发证书（无 get-task-allow）：GUI 走 LiveContainer 重启模型，CLI 在微内核内直接运行。")
                            .font(.caption).foregroundColor(.secondary)
                    } else {
                        Text("请先选择 p12 与 mobileprovision 并点「应用配置」，否则导入 App 时会因未配置证书而失败。")
                            .font(.caption).foregroundColor(.secondary)
                    }
                }

                if !message.isEmpty {
                    Section { Text(message).font(.caption).foregroundColor(.secondary) }
                }
            }
            .navigationTitle("设置")
        }
        .fileImporter(isPresented: $showP12, allowedContentTypes: [UTType(filenameExtension: "p12") ?? .data]) { result in
            handle(result, isP12: true)
        }
        .fileImporter(isPresented: $showProv, allowedContentTypes: [UTType(filenameExtension: "mobileprovision") ?? .data]) { result in
            handle(result, isP12: false)
        }
    }

    private func handle(_ result: Result<URL, Error>, isP12: Bool) {
        switch result {
        case .success(let url):
            let ok = url.startAccessingSecurityScopedResource()
            defer { if ok { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url) else {
                message = "读取文件失败"
                return
            }
            if isP12 {
                stagedP12 = data
                p12Name = url.lastPathComponent
            } else {
                stagedProv = data
                provName = url.lastPathComponent
            }
            message = "已暂存，点「应用配置」完成导入"
        case .failure(let e):
            message = "选择失败：\(e.localizedDescription)"
        }
    }

    private func apply() {
        guard let p12 = stagedP12, let prov = stagedProv else {
            message = "请先选择 p12 与 mobileprovision"
            return
        }
        guard !p12Password.isEmpty else {
            message = "请输入 p12 密码"
            return
        }
        let okP12 = store.importP12(p12, password: p12Password)
        store.importProvisioning(prov)
        message = okP12 ? "配置成功：证书 + 描述文件已就绪" : "p12 导入失败（密码错误或格式不符）"
    }
}
