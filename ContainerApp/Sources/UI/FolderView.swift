import SwiftUI

/// Full-screen folder page (opened by tapping a folder icon on the desktop):
/// the iOS folder UI — a blurred panel with the member grid.
///
///  - Tap a member  -> opens that app (the folder closes, exactly like iOS).
///  - Long-press EMPTY space -> edit mode: icons jiggle (per-icon phase) and a
///    − badge removes the member back to the desktop.
///  - Removing the last member dissolves the folder and closes this page.
///  - The pencil in the toolbar renames the folder.
struct FolderView: View {
    let folderID: String
    var onOpenMember: (DesktopItem) -> Void
    var onDismiss: () -> Void

    @ObservedObject private var store = DesktopStore.shared
    @State private var editMode = false
    @State private var renameText = ""
    @State private var showRename = false

    /// The LIVE folder from the store (the passed-in copy is a snapshot).
    private var folder: RyFolder? { store.folders.first { $0.id == folderID } }
    private var members: [DesktopItem] {
        guard let f = folder else { return [] }
        return store.members(of: f)
    }

    private var columns: [GridItem] {
        Array(repeating: GridItem(.flexible(), spacing: 20), count: 4)
    }
    private var iconSize: CGFloat { 62 }

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                // Folder title (editable)
                HStack(spacing: 8) {
                    Text(folder?.name ?? "文件夹")
                        .font(.title2.bold())
                        .foregroundStyle(.white)
                    if editMode {
                        Button { showRename = true } label: {
                            Image(systemName: "pencil.circle.fill")
                                .font(.system(size: 18))
                                .foregroundStyle(.white.opacity(0.85))
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.top, 6)

                grid
                    .padding(.horizontal, 22)
                    .padding(.bottom, 30)
            }
        }
        .background(
            folderBackground
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
        )
        // Long-press EMPTY space -> edit mode (same rule as the desktop).
        .contentShape(Rectangle())
        .onLongPressGesture(minimumDuration: 0.5) {
            withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) { editMode = true }
        }
        .onTapGesture {
            if editMode {
                withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) { editMode = false }
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if editMode {
                    Button("完成") {
                        withAnimation { editMode = false }
                    }
                } else {
                    Button { showRename = true } label: {
                        Image(systemName: "pencil")
                    }
                }
            }
        }
        .alert("重命名文件夹", isPresented: $showRename) {
            TextField("文件夹名称", text: $renameText)
            Button("保存") {
                store.renameFolder(folderID, to: renameText)
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("给文件夹起个名字")
        }
        .onAppear { renameText = folder?.name ?? "文件夹" }
        // The folder dissolved (last member removed) -> close this page.
        .onChange(of: store.folders.count) { _ in
            if folder == nil { onDismiss() }
        }
    }

    /// Themes may ship a `FolderBackground` image; otherwise it is the usual
    /// blurred panel.
    ///
    /// The panel must be DARK: the folder title and the member names are drawn
    /// in white on top of it, so a plain `.ultraThinMaterial` (which is nearly
    /// white over a light wallpaper) makes the text unreadable — the
    /// "文件夹背景太白了，看不清文字" report. We therefore use the regular
    /// material plus an explicit dark tint, which keeps the blur (毛玻璃) and
    /// restores the contrast.
    @ViewBuilder
    private var folderBackground: some View {
        if let img = ThemeEngine.shared.uiImage("FolderBackground") {
            Image(uiImage: img)
                .resizable()
                .scaledToFill()
                .clipShape(RoundedRectangle(cornerRadius: 34, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 34, style: .continuous)
                        .fill(Color.black.opacity(0.45))
                )
        } else {
            RoundedRectangle(cornerRadius: 34, style: .continuous)
                .fill(.regularMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 34, style: .continuous)
                        .fill(Color.black.opacity(0.42))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 34, style: .continuous)
                        .strokeBorder(.white.opacity(0.18), lineWidth: 0.5)
                )
        }
    }

    // MARK: Member grid

    private var grid: some View {
        LazyVGrid(columns: columns, spacing: 22) {
            ForEach(Array(members.enumerated()), id: \.element.id) { idx, item in
                FolderMemberIcon(item: item,
                                 size: iconSize,
                                 editMode: editMode,
                                 phase: idx,
                                 onOpen: { if !editMode { onOpenMember(item) } },
                                 onRemove: { remove(item) })
            }
        }
    }

    private func remove(_ item: DesktopItem) {
        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
            store.removeFromFolder(item.id)
        }
    }
}

/// One icon inside the folder: per-icon jiggle phase + − badge in edit mode.
private struct FolderMemberIcon: View {
    let item: DesktopItem
    let size: CGFloat
    let editMode: Bool
    let phase: Int
    var onOpen: () -> Void
    var onRemove: () -> Void

    @State private var jiggle = false

    var body: some View {
        VStack(spacing: 6) {
            ZStack(alignment: .topTrailing) {
                // Themed icons apply inside folders too — same IconArtwork the
                // home screen uses.
                IconArtwork(item: item, size: size)

                if editMode {
                    Button(action: onRemove) {
                        Image(systemName: "minus.circle.fill")
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, Color(red: 0.92, green: 0.26, blue: 0.30))
                            .font(.system(size: size * 0.27))
                            .contentShape(Circle())
                    }
                    .buttonStyle(.plain)
                    .frame(width: size * 0.34, height: size * 0.34)
                    .offset(x: size * 0.15, y: -size * 0.15)
                }
            }
            Text(item.name)
                .font(.system(size: 11.5, weight: .medium))
                .foregroundStyle(.white)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
                .frame(width: size + 14)
        }
        .contentShape(Rectangle())
        .rotationEffect(.degrees(editMode ? (jiggle ? 1.2 : -1.2) : 0), anchor: .center)
        .animation(editMode
                   ? .easeInOut(duration: 0.075 + 0.022 * Double(phase % 6))
                       .repeatForever(autoreverses: true)
                   : .default,
                   value: jiggle)
        .onChange(of: editMode) { on in jiggle = on }
        .onTapGesture { onOpen() }
    }
}
