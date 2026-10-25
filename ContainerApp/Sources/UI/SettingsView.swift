import SwiftUI
import UniformTypeIdentifiers

/// iOS-style Settings: inset grouped lists, chevron rows, toggles.
/// Hosts the signing identity (p12 + mobileprovision) the import→sign→run
/// chain depends on, plus desktop/Dock customization and about info.
struct SettingsView: View {
    @State private var message: String = ""
    @State private var themeToDelete: RyTheme?
    /// Mirrors the floating ball's on/off state so the toggle stays in sync
    /// (the ball is a plain singleton, not an ObservableObject).
    @State private var floatBallOn = FloatingLogBall.shared.isVisible

    @ObservedObject private var store = CertificateStore.shared
    @ObservedObject private var desktop = DesktopStore.shared
    @ObservedObject private var theme = ThemeEngine.shared
    @ObservedObject private var log = RyLog.shared
    @EnvironmentObject private var env: RuntimeEnvironment
    /// Which launch model a guest app uses (see GuestLaunchMode).
    @AppStorage("rybox.guestLaunchMode") private var launchModeRaw = GuestLaunchMode.inProcessDylib.rawValue

    var body: some View {
        Form {
            signingSection
            launchSection
            entitlementSection
            jbrootSection
            logSection
            desktopSection
            themeSection
            aboutSection
        }
        .navigationTitle("设置")
        .onChange(of: floatBallOn) { on in
            if on {
                FloatingLogBall.shared.show()
            } else {
                FloatingLogBall.shared.hide()
            }
        }
        .alert("删除主题？", isPresented: Binding(
            get: { themeToDelete != nil },
            set: { if !$0 { themeToDelete = nil } }
        )) {
            Button("删除", role: .destructive) {
                if let t = themeToDelete {
                    if ThemeEngine.shared.deleteTheme(t.id) {
                        message = "已删除主题：\(t.name)"
                    } else {
                        message = "主题删除失败：\(t.name)"
                    }
                }
                themeToDelete = nil
            }
            Button("取消", role: .cancel) { themeToDelete = nil }
        } message: {
            Text("将从 /Library/Themes 永久移除「\(themeToDelete?.name ?? "")」，此操作不可撤销。")
        }
        .alert("重置并重新解压 jbroot？", isPresented: $showJbrootResetAlert) {
            Button("重置并解压", role: .destructive) {
                JbRoot.shared.reset()
                JbRoot.shared.bootstrap()
                message = "已重置虚拟根，正在后台重新解压 jbroot…"
            }
            Button("取消", role: .cancel) { }
        } message: {
            Text("会清空整个虚拟根目录（已安装的 deb 包、Sileo 源列表都会丢失），然后用当前 bootstrap 包重新解压。RyBox 自身的数据不受影响。")
        }
    }

    /// Confirmation for the destructive jbroot re-extract.
    @State private var showJbrootResetAlert = false

    // MARK: 签名身份（状态只读，证书在「初始设置」中配置）

    private var signingSection: some View {
        Section {
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
            if let info = store.certificateInfo {
                VStack(alignment: .leading, spacing: 4) {
                    Text("证书信息").font(.caption).foregroundColor(.secondary)
                    Text(info)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } header: {
            Text("签名身份")
        } footer: {
            Text("证书与描述文件在首次启动的「初始设置」中配置，并会自动保存；重新进入 RyBox 无需再次导入。如需更换，请在初始设置中重新导入。")
        }
    }

    // MARK: 启动方式（MH_EXECUTE 进程 / 进程内动态库）

    private var launchSection: some View {
        Section {
            Picker("方式", selection: $launchModeRaw) {
                ForEach(GuestLaunchMode.allCases) { mode in
                    Text(mode.title).tag(mode.rawValue)
                }
            }
            .pickerStyle(.segmented)

            Text(GuestLaunchMode(rawValue: launchModeRaw)?.detail ?? "")
                .font(.caption)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        } header: {
            Text("启动方式")
        } footer: {
            Text("两种方式走的是完全不同的签名校验体系：动态库要过 transmute 和 library validation，可执行文件只按 DR 校验证书链。切换后立即生效，便于对照真机日志。")
        }
    }

    // MARK: 特殊权限分配（签名剥离、RyBox 接管）

    private var entitlementSection: some View {
        Section {
            NavigationLink {
                EntitlementManagerView()
            } label: {
                HStack {
                    Label("特殊权限分配", systemImage: "switch.2")
                    Spacer()
                    let total = EntitlementPolicy.shared.takenOver.values
                        .reduce(0) { $0 + $1.count }
                    if total > 0 {
                        Text("\(total) 项接管中")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
        } header: {
            Text("特殊权限")
        } footer: {
            Text("RyBox 里的 App 不需要（也用不了）签名里的特殊权限：它们以 in-process 方式跑在 RyBox 进程里，权限查询由 RyBox 代为回答。导入 App 时，platform-application、com.apple.private.* 等特殊权限会从签名中剥掉并打上标记，改由这里按 App 分配——关掉开关，该 App 查询对应权限就会得到「未授权」。")
        }
    }

    // MARK: 虚拟根（jbroot，自动解压）

    private var jbrootSection: some View {
        Section {
            HStack {
                Text("状态")
                Spacer()
                let done = JbRoot.shared.isBootstrapped
                Label(done ? "已就绪" : "未解压",
                      systemImage: done ? "checkmark.circle.fill" : "exclamationmark.circle")
                    .foregroundStyle(done ? Color.green : Color.orange)
                    .font(.footnote)
            }

            if let info = JbRoot.shared.statusLine {
                Text(info)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if JbRoot.shared.hasImportedBootstrap {
                HStack {
                    Text("当前源")
                    Spacer()
                    Text("导入的 jbroot 包")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            if !JbRoot.shared.isBootstrapped {
                Button {
                    JbRoot.shared.bootstrap()
                } label: {
                    Label("立即解压 jbroot", systemImage: "arrow.down.circle")
                }
            }

            Button {
                pickJbroot()
            } label: {
                Label("导入 jbroot 包（zip）", systemImage: "square.and.arrow.down.on.square")
            }

            if JbRoot.shared.hasImportedBootstrap {
                Button(role: .destructive) {
                    JbRoot.shared.removeImportedBootstrap()
                    message = "已删除导入的 jbroot 包，回到内置 bootstrap"
                } label: {
                    Label("删除导入的 jbroot 包", systemImage: "trash")
                }
            }

            if JbRoot.shared.isBootstrapped {
                Button(role: .destructive) {
                    showJbrootResetAlert = true
                } label: {
                    Label("重置并重新解压", systemImage: "arrow.counterclockwise")
                }
            }
        } header: {
            Text("虚拟根（jbroot）")
        } footer: {
            Text("RyBox 不再从 IPSW / .ryboxenv 还原真实系统文件，而是启动后自动从一个最小 Procursus bootstrap 解压出标准 jbroot（dpkg / apt / 标准 /usr /var 布局与包管理数据库）。如果内置 bootstrap 太小或太旧，可以在电脑上用 make_jbroot.py 生成新的 zip，在这里导入——导入后点「重置并重新解压」生效（会清空虚拟根里已安装的包）。")
        }
    }

    private static func mb(_ bytes: Int64) -> String {
        String(format: "%.1f", Double(bytes) / 1024 / 1024)
    }

    // MARK: 日志与浮窗（实时诊断）

    private var logSection: some View {
        Section {
            NavigationLink {
                LogConsoleView()
            } label: {
                Label("实时日志", systemImage: "text.alignleft")
            }

            Toggle(isOn: $floatBallOn) {
                Label("悬浮球浮窗", systemImage: "circle.circle.fill")
            }

            HStack {
                Text("已记录日志")
                Spacer()
                Text("\(log.entries.count) 行")
                    .foregroundColor(.secondary)
                    .monospacedDigit()
            }

            if !entitlementRows.isEmpty {
                ForEach(entitlementRows, id: \.bundleID) { row in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(row.bundleID)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                        Text(row.summary)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        } header: {
            Text("日志与诊断")
        } footer: {
            Text("实时日志记录容器的每一步真实动作（导入、签名、Entitlements、补丁、dlopen、scene 驱动）。打开悬浮球浮窗后，日志球会浮在所有界面之上——包括 guest App 运行时——点一下即可展开查看。\n\nEntitlements 一栏显示每个已导入 App 原本声明的能力：签名里放的是你证书描述文件授权的内容（AMFI 会校验），原始能力则由容器代为「放行」。")
        }
    }

    /// Per-app entitlement summary (original capabilities vs. signed set).
    private struct EntitlementRow {
        let bundleID: String
        let summary: String
    }

    private var entitlementRows: [EntitlementRow] {
        EntitlementPolicy.shared.original.keys.sorted().map { bid in
            let original = EntitlementPolicy.shared.original[bid] ?? [:]
            let simulated = EntitlementPolicy.simulatedEntitlements(
                original: original,
                profile: EntitlementPolicy.shared.profile)
            let diff = EntitlementPolicy.diff(original: original,
                                             profile: EntitlementPolicy.shared.profile)
            return EntitlementRow(
                bundleID: bid,
                summary: "原始 \(original.count) 项 · 放行 \(simulated.count) 项 · 身份键改用证书 \(diff.dropped.count) 项")
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
                    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                        Button(role: .destructive) { themeToDelete = t } label: {
                            Label("删除", systemImage: "trash")
                        }
                    }
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

    /// Import a jbroot zip the user made on a PC (make_jbroot.py). The file is
    /// copied into the container; the destructive re-extract is a separate,
    /// confirmed step.
    private func pickJbroot() {
        message = "正在打开文件选择器…"
        DocPicker.present { result in
            switch result {
            case .success(let url):
                switch JbRoot.shared.importBootstrap(from: url) {
                case .success(let note): message = note
                case .failure(let reason): message = "jbroot 导入失败：\(reason.localizedDescription)"
                }
            case .failure(let e):
                message = "选择失败：\(e.localizedDescription)"
            }
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
