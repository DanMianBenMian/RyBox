import SwiftUI
import UniformTypeIdentifiers

/// iOS-style Settings: inset grouped lists, chevron rows, toggles.
/// Hosts the signing identity (p12 + mobileprovision) the import→sign→run
/// chain depends on, plus desktop/Dock customization and about info.
struct SettingsView: View {
    @State private var showP12 = false
    @State private var showProv = false
    @State private var p12Password = ""
    @State private var p12Name: String = "未选择"
    @State private var provName: String = "未选择"
    @State private var message: String = ""
    @State private var stagedP12: Data?
    @State private var stagedProv: Data?

    @ObservedObject private var store = CertificateStore.shared
    @ObservedObject private var desktop = DesktopStore.shared
    @EnvironmentObject private var env: RuntimeEnvironment

    var body: some View {
        Form {
            signingSection
            desktopSection
            aboutSection
        }
        .navigationTitle("设置")
        .fileImporter(isPresented: $showP12, allowedContentTypes: [.item]) { handle($0, isP12: true) }
        .fileImporter(isPresented: $showProv, allowedContentTypes: [.item]) { handle($0, isP12: false) }
    }

    // MARK: 签名身份

    private var signingSection: some View {
        Section {
            HStack {
                Text("证书文件（.p12）")
                Spacer()
                Text(p12Name)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
            .contentShape(Rectangle())
            .onTapGesture { showP12 = true }

            SecureField("p12 密码", text: $p12Password)

            HStack {
                Text("描述文件")
                Spacer()
                Text(provName)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
            .contentShape(Rectangle())
            .onTapGesture { showProv = true }

            Button {
                apply()
            } label: {
                if stagedP12 == nil || stagedProv == nil || p12Password.isEmpty {
                    Text("应用配置（需先选择证书与描述文件）").foregroundColor(.secondary)
                } else {
                    Text("应用配置").bold()
                }
            }
            .disabled(stagedP12 == nil || stagedProv == nil || p12Password.isEmpty)

            HStack {
                Text("状态")
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
        } header: {
            Text("签名身份")
        } footer: {
            Text(store.isConfigured
                 ? "支持分发证书（无 get-task-allow）：GUI 走 LiveContainer 进程内模型，CLI 在微内核内直接运行。"
                 : "请先选择 p12 与 mobileprovision 并点「应用配置」，否则导入 App 时会因未配置证书而失败。")
        }
    }

    // MARK: 桌面与 Dock

    private var desktopSection: some View {
        Section {
            NavigationLink {
                DockEditorView()
            } label: {
                Label("自定义 Dock", systemImage: "square.grid.3x3.square")
            }

            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("图标大小")
                    Spacer()
                    Text("\(Int(desktop.iconScale * 100))%")
                        .foregroundColor(.secondary)
                        .monospacedDigit()
                }
                Slider(value: Binding(get: { desktop.iconScale },
                                      set: { desktop.iconScale = $0 }),
                       in: 0.8...1.3, step: 0.05)
            }

            Button(role: .destructive) {
                desktop.resetLayout()
                message = "桌面布局已重置"
            } label: {
                Label("重置桌面布局", systemImage: "arrow.counterclockwise")
            }
        } header: {
            Text("桌面与 Dock")
        } footer: {
            Text("长按桌面图标进入编辑模式：拖动调整位置、拖到 Dock 添加、点 − 删除。")
        }
    }

    // MARK: 关于

    private var aboutSection: some View {
        Section {
            HStack {
                Text("版本")
                Spacer()
                Text("0.1.0 (1)").foregroundColor(.secondary)
            }
            HStack {
                Text("Bundle ID")
                Spacer()
                Text("com.rybox.RyBox")
                    .foregroundColor(.secondary)
                    .font(.system(.caption, design: .monospaced))
            }
            HStack {
                Text("运行模式")
                Spacer()
                Text(env.mode == .jailbroken ? "越狱环境" : "受限沙箱")
                    .foregroundColor(.secondary)
            }
            HStack {
                Text("虚拟根目录")
                Spacer()
                Text(VirtualRoot.shared.rootURL.lastPathComponent)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
        } header: {
            Text("关于 RyBox")
        } footer: {
            if !message.isEmpty { Text(message) }
        }
    }

    // MARK: Picker handling

    private func handle(_ result: Result<URL, Error>, isP12: Bool) {
        switch result {
        case .success(let url):
            let ok = url.startAccessingSecurityScopedResource()
            defer { if ok { url.stopAccessingSecurityScopedResource() } }
            let ext = url.pathExtension.lowercased()
            let want = isP12 ? "p12" : "mobileprovision"
            guard ext == want else {
                message = "请选择 .\(want) 文件（当前：\(url.lastPathComponent)）"
                return
            }
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

/// Dock editor: reorder (Edit mode), swipe to remove, add from all apps.
struct DockEditorView: View {
    @ObservedObject private var desktop = DesktopStore.shared

    var body: some View {
        Form {
            Section {
                ForEach(desktop.dockItems) { item in
                    Label(item.name, systemImage: item.symbol)
                }
                .onMove { desktop.moveDock(from: $0, to: $1) }
                .onDelete { offsets in
                    let snapshot = desktop.dockItems
                    for i in offsets { desktop.removeFromDock(snapshot[i].id) }
                }
            } header: {
                Text("Dock 中的应用")
            } footer: {
                Text("点「编辑」可拖动排序；左滑移除。桌面图标在编辑模式下拖到 Dock 也会自动添加。")
            }

            Section("全部应用") {
                ForEach(desktop.allItems) { item in
                    HStack {
                        Label(item.name, systemImage: item.symbol)
                        Spacer()
                        if desktop.isInDock(item.id) {
                            Image(systemName: "checkmark")
                                .foregroundStyle(.tint)
                        } else {
                            Button("添加") { desktop.addToDock(item.id) }
                                .buttonStyle(.borderless)
                        }
                    }
                }
            }
        }
        .navigationTitle("Dock")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { EditButton() }
    }
}
