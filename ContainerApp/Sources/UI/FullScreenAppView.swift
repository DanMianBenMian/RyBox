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
            case .logs: LogConsoleView()
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

/// Full-screen page for an imported guest app. The app launches automatically
/// once this page appears — the open animation already played, so there is no
/// "启动 / start" button to press (the user asked for exactly that: tap the
/// icon → open animation → straight to the app).
///
/// GUI guests launch in-process (LiveContainer model) and take over the screen;
/// CLI guests run inside the microkernel (output in Terminal).
struct GuestLaunchView: View {
    let app: ImportedApp
    @State private var status = ""
    @State private var busy = false
    /// Guards against re-launching on every SwiftUI body evaluation — we only
    /// fire once when the page first appears.
    @State private var launched = false

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: app.isGUI ? "macwindow.on.rectangle" : "terminal.fill")
                .font(.system(size: 60))
                .foregroundStyle(DesktopItem.color(for: app.bundleIdentifier))
            Text(app.name)
                .font(.title3.bold())
            Text(app.bundleIdentifier)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            if busy { ProgressView() }
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
        .onAppear { runIfNeeded() }
    }

    private func runIfNeeded() {
        guard !launched else { return }
        launched = true
        busy = true
        status = "正在启动…"
        DispatchQueue.main.async {
            if app.isGUI {
                GuestRuntime.launchInProcess(app)
                // The guest UI covers this page via its own window; only show a
                // status if the launch fell back to the scaffold path.
                status = ""
            } else {
                status = RyLaunchCoordinator.shared.runCLIGuest(app) != nil
                    ? "已在微内核内运行，输出见「终端」。"
                    : "启动失败：进程无法创建。"
            }
            busy = false
        }
    }
}
