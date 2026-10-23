import SwiftUI

/// RyBox's home screen — an iOS-style SpringBoard.
/// Shows imported guest apps as icons and a Dock of built-in tools. Tapping a
/// guest icon launches it (in-process for GUI, spawn for CLI). Tapping a Dock
/// tool opens it as a panel. The virtual Home button (HomeButtonWindow) returns
/// here at any time.
///
/// Layout adapts to size class: on iPad (regular width) it uses a 6-column grid,
/// larger icons, a wider Dock, and a rounded "device bezel" frame so it reads as
/// an iPad home screen rather than a blown-up iPhone one.
struct SpringBoardView: View {
    @ObservedObject private var importer = AppImporter.shared
    @EnvironmentObject private var env: RuntimeEnvironment
    @Environment(\.horizontalSizeClass) private var hSize
    @Environment(\.verticalSizeClass) private var vSize

    @State private var presentedTool: BuiltinTool?

    // iPad (regular) gets a denser grid + bigger icons than iPhone (compact).
    private var columns: [GridItem] {
        let count = (hSize == .regular) ? 6 : 4
        return Array(repeating: GridItem(.flexible(), spacing: hSize == .regular ? 24 : 18), count: count)
    }
    private var iconSize: CGFloat { hSize == .regular ? 76 : 60 }
    private var isIPad: Bool { hSize == .regular }

    var body: some View {
        GeometryReader { geo in
            ZStack {
                // Wallpaper
                LinearGradient(colors: isIPad
                               ? [Color(red: 0.13, green: 0.22, blue: 0.55),
                                  Color(red: 0.30, green: 0.45, blue: 0.80)]
                               : [Color(red: 0.10, green: 0.18, blue: 0.42),
                                  Color(red: 0.20, green: 0.32, blue: 0.66)],
                               startPoint: .top, endPoint: .bottom)
                    .ignoresSafeArea()

                VStack(spacing: 0) {
                    statusBar
                    if isIPad {
                        iPadTopBar
                    }
                    Spacer(minLength: 8)
                    appGrid
                    Spacer()
                    dock
                }
                .padding(.bottom, isIPad ? 84 : 70) // room for the floating Home button
                // iPad: clip into a rounded "bezel" so it reads as a tablet home.
                .clipShape(RoundedRectangle(cornerRadius: isIPad ? 28 : 0, style: .continuous))
                .padding(isIPad ? 10 : 0)
            }
        }
        .ignoresSafeArea()
        .onReceive(NotificationCenter.default.publisher(for: SpringBoardController.goHomeNotification)) { _ in
            presentedTool = nil
        }
        .sheet(item: $presentedTool) { tool in
            tool.view
        }
    }

    // MARK: - Status bar (fake iOS status bar)
    private var statusBar: some View {
        HStack {
            Text("9:41")
                .font(.system(size: 15, weight: .semibold))
            Spacer()
            Image(systemName: "wifi")
            Image(systemName: "battery.100")
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 22)
        .padding(.top, 8)
        .font(.system(size: 14))
    }

    // MARK: - iPad top bar (model hint + running-guest indicator)
    private var iPadTopBar: some View {
        HStack {
            Label("iPad", systemImage: "ipad")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.white.opacity(0.85))
            Spacer()
            Text("RyBox 容器")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.white.opacity(0.85))
        }
        .padding(.horizontal, 28)
        .padding(.top, 4)
    }

    // MARK: - Guest app grid
    private var appGrid: some View {
        ScrollView {
            LazyVGrid(columns: columns, spacing: isIPad ? 26 : 22) {
                ForEach(importer.importedApps) { app in
                    AppIcon(name: app.name, isGUI: app.isGUI, size: iconSize) {
                        launch(app)
                    }
                }
            }
            .padding(.horizontal, isIPad ? 40 : 26)
        }
    }

    // MARK: - Dock (built-in tools)
    private var dock: some View {
        HStack(spacing: isIPad ? 30 : 22) {
            ForEach(BuiltinTool.allCases) { tool in
                AppIcon(name: tool.title, systemImage: tool.icon, isGUI: false, size: iconSize) {
                    presentedTool = tool
                }
            }
        }
        .padding(.vertical, isIPad ? 18 : 14)
        .padding(.horizontal, isIPad ? 36 : 22)
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: isIPad ? 32 : 24, style: .continuous))
        .padding(.horizontal, isIPad ? 30 : 12)
    }

    private func launch(_ app: ImportedApp) {
        if app.isGUI {
            RyLaunchCoordinator.shared.requestRun(app)
        } else {
            _ = RyLaunchCoordinator.shared.runCLIGuest(app)
        }
    }
}

/// A single SpringBoard icon (rounded squircle).
struct AppIcon: View {
    let name: String
    var systemImage: String?
    let isGUI: Bool
    var size: CGFloat = 60
    let action: () -> Void

    init(name: String, systemImage: String? = nil, isGUI: Bool, size: CGFloat = 60, action: @escaping () -> Void) {
        self.name = name
        self.systemImage = systemImage
        self.isGUI = isGUI
        self.size = size
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            VStack(spacing: 6) {
                RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                    .fill(isGUI ? Color.accentColor : Color(uiColor: .secondarySystemBackground))
                    .frame(width: size, height: size)
                    .overlay {
                        Image(systemName: systemImage ?? "app.fill")
                            .font(.system(size: size * 0.5))
                            .foregroundStyle(isGUI ? .white : .primary)
                    }
                    .shadow(color: .black.opacity(0.18), radius: 4, y: 2)
                Text(name)
                    .font(.system(size: isGUI ? 12 : 11))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .frame(width: size + 6)
            }
        }
        .buttonStyle(.plain)
    }
}

/// Built-in tools shown in the Dock (RyBox's own UI panels).
enum BuiltinTool: String, CaseIterable, Identifiable {
    case terminal, files, packages, settings, `import`
    var id: String { rawValue }

    var title: String {
        switch self {
        case .terminal: return "终端"
        case .files: return "文件"
        case .packages: return "包管理"
        case .settings: return "设置"
        case .`import`: return "导入"
        }
    }
    var icon: String {
        switch self {
        case .terminal: return "terminal"
        case .files: return "folder"
        case .packages: return "shippingbox"
        case .settings: return "gearshape"
        case .`import`: return "square.and.arrow.down"
        }
    }
    @ViewBuilder var view: some View {
        switch self {
        case .terminal: TerminalView()
        case .files: FilesystemView()
        case .packages: PackageManagerView()
        case .settings: SettingsView()
        case .`import`: ImportView()
        }
    }
}
