import SwiftUI

/// Full-screen app page. Tapping a desktop/dock icon zooms this in over the
/// SpringBoard.
///
/// There is NO close button: the floating liquid-glass Home key rendered by
/// SpringBoardView sits above this page and always returns home.
///
/// `onOpenItem` lets a page swap itself for another item (a folder opening one
/// of its members, exactly like iOS). `onDismiss` closes the page from inside
/// (a folder that just dissolved).
struct FullScreenAppView: View {
    let item: DesktopItem
    var onOpenItem: ((DesktopItem) -> Void)? = nil
    var onDismiss: (() -> Void)? = nil

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(isFolder ? "" : item.name)
                .navigationBarTitleDisplayMode(.inline)
                .toolbarBackground(.visible, for: .navigationBar)
        }
    }

    private var isFolder: Bool {
        if case .folder = item.kind { return true }
        return false
    }

    @ViewBuilder
    private var content: some View {
        switch item.kind {
        case .builtin(let b):
            switch b {
            case .sileo: SileoView()
            case .settings: SettingsView()
            case .files: FilesystemView()
            case .terminal: TerminalView()
            case .import: ImportView()
            }
        case .guest(let app):
            GuestLaunchView(app: app)
        case .folder(let f):
            FolderView(folderID: f.id,
                       onOpenMember: { member in onOpenItem?(member) },
                       onDismiss: { onDismiss?() })
        }
    }
}

/// Full-screen page for an imported guest app: info + launch controls.
/// GUI guests launch in-process (LiveContainer model) and take over the screen;
/// CLI guests run inside the microkernel (output in Terminal).
struct GuestLaunchView: View {
    let app: ImportedApp
    @State private var status = ""
    @State private var busy = false

    var body: some View {
        VStack(spacing: 22) {
            Spacer()
            Image(systemName: app.isGUI ? "macwindow.on.rectangle" : "terminal.fill")
                .font(.system(size: 64))
                .foregroundStyle(DesktopItem.color(for: app.bundleIdentifier))
            Text(app.name)
                .font(.title2.bold())
            Text(app.bundleIdentifier)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            if let note = app.signNote {
                Text("未签名：\(note)")
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            Text(app.isGUI
                 ? "GUI App 将以 LiveContainer 模式在 RyBox 进程内启动。启动成功后本容器界面会被 guest 窗口接管，用悬浮「主屏」键返回。"
                 : "CLI 工具在微内核内以子进程运行，输出见「终端」。")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            if busy { ProgressView() }
            Button(app.isGUI ? "启动" : "在终端运行") { run() }
                .buttonStyle(.borderedProminent)
                .disabled(busy)
            if !status.isEmpty {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            Spacer()
        }
        .padding()
    }

    private func run() {
        busy = true
        status = "启动中…"
        DispatchQueue.main.async {
            if app.isGUI {
                GuestRuntime.launchInProcess(app)
                status = "已请求启动。若失败会自动落入沙箱视图。"
            } else {
                status = RyLaunchCoordinator.shared.runCLIGuest(app) != nil
                    ? "已在微内核内运行，输出见「终端」。"
                    : "启动失败：进程无法创建。"
            }
            busy = false
        }
    }
}
