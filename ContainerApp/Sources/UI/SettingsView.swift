import SwiftUI
import UniformTypeIdentifiers

/// iOS-style Settings: inset grouped lists, chevron rows, toggles.
/// Hosts the signing identity (p12 + mobileprovision) the import→sign→run
/// chain depends on, plus desktop/Dock customization and about info.
struct SettingsView: View {
    @State private var p12Password = ""
    @State private var p12Name: String = "未选择"
    @State private var provName: String = "未选择"
    @State private var message: String = ""

    /// Staged file contents (imported only when the user taps "应用配置").
    @State private var stagedP12: Data?
    @State private var stagedProv: Data?

    @ObservedObject private var store = CertificateStore.shared
    @ObservedObject private var desktop = DesktopStore.shared
    @ObservedObject private var firm = FirmwareImporter.shared
    @ObservedObject private var theme = ThemeEngine.shared
    @EnvironmentObject private var env: RuntimeEnvironment

    var body: some View {
        Form {
            signingSection
            firmwareSection
            desktopSection
            themeSection
            aboutSection
        }
        .navigationTitle("设置")
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
            .onTapGesture { pickP12() }

            SecureField("p12 密码（无密码可直接留空）", text: $p12Password)

            HStack {
                Text("描述文件")
                Spacer()
                Text(provName)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
            .contentShape(Rectangle())
            .onTapGesture { pickProv() }

            Button {
                apply()
            } label: {
                if stagedP12 == nil || stagedProv == nil {
                    Text("应用配置（需先选择证书与描述文件）").foregroundColor(.secondary)
                } else {
                    Text("应用配置").bold()
                }
            }
            // NOTE: an EMPTY password is allowed — plenty of distribution p12
            // files are exported without one, and requiring text here used to
            // silently block the whole configuration step.
            .disabled(stagedP12 == nil || stagedProv == nil)

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

    // MARK: 系统固件（系统环境来源）

    private var firmwareSection: some View {
        Section {
            HStack {
                Text("状态")
                Spacer()
                Label(firm.phase.label,
                      systemImage: firm.isSatisfied ? "checkmark.circle.fill"
                                                    : "exclamationmark.circle")
                    .foregroundStyle(firm.isSatisfied ? Color.green : Color.orange)
                    .font(.footnote)
            }

            if let r = firm.report {
                HStack {
                    Text("来源")
                    Spacer()
                    Text(r.source).foregroundColor(.secondary).lineLimit(1)
                }
                if let v = r.version {
                    HStack {
                        Text("系统版本")
                        Spacer()
                        Text("\(v)\(r.build.map { " (\($0))" } ?? "")")
                            .foregroundColor(.secondary)
                    }
                }
                HStack {
                    Text("已还原")
                    Spacer()
                    Text("\(r.installedFiles) 个文件 / \(Self.mb(r.installedBytes)) MB")
                        .foregroundColor(.secondary)
                }
                ForEach(r.notes, id: \.self) { note in
                    Text(note).font(.caption).foregroundColor(.secondary)
                }
            }

            if firm.phase == .scanning || firm.phase == .extracting {
                ProgressView(value: max(firm.progress, 0.05))
                Text(firm.message).font(.caption).foregroundColor(.secondary)
            } else if case .failed = firm.phase {
                Text(firm.message).font(.caption).foregroundColor(.red)
            }

            Button {
                pickFirmware()
            } label: {
                Label(firm.isSatisfied ? "重新导入固件" : "导入固件（.ryboxenv / .ipsw）",
                      systemImage: "square.and.arrow.down.on.square")
            }
        } header: {
            Text("系统固件")
        } footer: {
            Text("固件不打包进 IPA（否则会变成数 GB）。.ryboxenv 是电脑上预处理好的系统环境包（已解密 AEA / DMG / APFS），导入即完整还原 /usr /System；直接导入 .ipsw 时 RyBox 就地读取其中未加密的 manifest、kernelcache 与 trustcache。")
        }
    }

    private static func mb(_ bytes: Int64) -> String {
        String(format: "%.1f", Double(bytes) / 1024 / 1024)
    }

    private func pickFirmware() {
        // asCopy: TRUE — open-in-place (asCopy:false) never delivers the
        // selection on iPadOS 27 beta, which is why firmware picking stalled.
        DocPicker.present(asCopy: true) { result in
            switch result {
            case .success(let url):
                // No extension gate — FirmwareImporter decides by content.
                firm.message = "已选择：\(url.lastPathComponent)"
                firm.ingest(url)
            case .failure(let e):
                firm.message = "选择失败：\(e.localizedDescription)"
                firm.phase = .failed
            }
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
            Text("长按桌面空白处进入编辑模式：拖动调整位置、两个应用叠放建文件夹、拖到 Dock 添加、点 − 删除。长按应用图标可打开菜单。")
        }
    }

    // MARK: 主题（/Library/Themes）

    private var themeSection: some View {
        Section {
            if theme.themes.isEmpty {
                Text("还没有主题。把 .theme 目录或主题 zip 放进 /Library/Themes，或在下面导入。")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            } else {
                ForEach(theme.themes) { t in
                    HStack(spacing: 10) {
                        Image(systemName: theme.isEnabled(t.id)
                              ? "checkmark.circle.fill" : "circle")
                            .foregroundStyle(theme.isEnabled(t.id) ? .green : .secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(t.name).font(.system(size: 15))
                            if let a = t.author {
                                Text(a).font(.caption).foregroundColor(.secondary)
                            }
                        }
                        Spacer()
                        if let img = theme.icon(forBundleID: "com.rybox.sileo"),
                           theme.isEnabled(t.id) {
                            Image(uiImage: img)
                                .resizable()
                                .frame(width: 26, height: 26)
                                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { theme.setEnabled(t.id, enabled: !theme.isEnabled(t.id)) }
                }
            }

            Button { pickTheme() } label: {
                Label("导入主题（zip）", systemImage: "square.and.arrow.down.on.square")
            }

            Button {
                SpringBoardController.shared.reloadLibrary()
                message = "资源库已刷新"
            } label: {
                Label("注销资源库", systemImage: "arrow.triangle.2.circlepath")
            }

            Button(role: .destructive) {
                SpringBoardController.shared.respring()
                message = "正在注销 SpringBoard…"
            } label: {
                Label("注销 SpringBoard", systemImage: "power")
            }
        } header: {
            Text("主题与资源库")
        } footer: {
            Text("主题格式与 WinterBoard / SnowBoard 一致：IconBundles/<bundle id>.png、Bundles/<bundle id>/、UIImages/（DockBackground、FolderBackground…）、HomeWallpaper.png、LockWallpaper.png。多个主题可叠加，越靠后优先级越高。「注销资源库」重新扫描并清空图标缓存，「注销 SpringBoard」则会像真机注销一样重建外壳并回到锁屏。")
        }
    }

    private func pickTheme() {
        message = "正在打开文件选择器…"
        DocPicker.present { result in
            switch result {
            case .success(let url):
                switch ThemeEngine.shared.importTheme(from: url) {
                case .success(let t): message = "已导入并启用主题：\(t.name)"
                case .failure(let e): message = "主题导入失败：\(e.localizedDescription)"
                }
            case .failure(let e):
                message = "选择失败：\(e.localizedDescription)"
            }
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

    private func pickP12() {
        DocPicker.present { result in
            switch result {
            case .success(let url):
                handle(url, isP12: true)
            case .failure(let e):
                message = "选择失败：\(e.localizedDescription)"
            }
        }
    }

    private func pickProv() {
        DocPicker.present { result in
            switch result {
            case .success(let url):
                handle(url, isP12: false)
            case .failure(let e):
                message = "选择失败：\(e.localizedDescription)"
            }
        }
    }

    /// The file's ROLE is detected from its CONTENT, not its extension — p12 /
    /// pfx / extension-less files all work, and picking a profile in the cert
    /// row simply fills the other slot.
    private func handle(_ url: URL, isP12: Bool) {
        do {
            let data = try Data(contentsOf: url)
            let name = url.lastPathComponent
            if looksLikeProvisioning(data) {
                stagedProv = data
                provName = name
                message = "已识别为描述文件：\(name)"
            } else {
                stagedP12 = data
                p12Name = name
                message = "已识别为证书：\(name)（\(data.count) 字节）"
            }
        } catch {
            message = "读取文件失败：\(error.localizedDescription)"
        }
    }

    private func looksLikeProvisioning(_ data: Data) -> Bool {
        guard let s = String(data: data.prefix(1 << 20), encoding: .isoLatin1) else { return false }
        if s.contains("mobileprovision") { return true }
        if s.contains("<?xml"),
           (s.contains("TeamIdentifier") || s.contains("ProvisionedDevices")
            || s.contains("Entitlements") || s.contains("AppIDName")) { return true }
        return false
    }

    private func apply() {
        guard let p12 = stagedP12, let prov = stagedProv else {
            message = "请先选择 p12 与 mobileprovision"
            return
        }
        switch store.importP12(p12, password: p12Password) {
        case .success:
            switch store.importProvisioning(prov) {
            case .success:
                message = "配置成功：证书 + 描述文件已就绪"
            case .failure(let m):
                message = "证书已就绪，但描述文件有问题：\(m.message)"
            }
        case .failure(let m):
            message = m.message      // detailed diagnosis (key-only cert / PEM / OpenSSL 3 p12 / wrong password)
        }
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
