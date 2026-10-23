import SwiftUI

/// RyBox's home screen — an iOS-style desktop.
///
///  - Installed guest apps (AppImporter) AND built-ins (Sileo is preinstalled)
///    show as icons on the desktop, alongside folders.
///  - Long-press EMPTY SPACE → edit mode: icons jiggle (each with its own
///    phase), drag to reposition (grid-snapped), drag onto the Dock to add,
///    drag one icon ONTO another to create a folder, tap − to delete.
///  - Long-press an ICON → context menu (open / dock / delete / rename).
///  - Tapping an icon opens a FULL-SCREEN app page (FullScreenAppView).
///  - The Home key is a square liquid-glass button rendered INSIDE this window
///    (no separate always-on overlay window — that used to swallow every touch
///    in the container, including document pickers and sheets). In edit mode
///    it doubles as "完成".
///  - Dock membership/order, icon layout and folders persist across launches.
struct SpringBoardView: View {
    @ObservedObject private var store = DesktopStore.shared
    @ObservedObject private var importer = AppImporter.shared
    @Environment(\.horizontalSizeClass) private var hSize

    @State private var activeApp: DesktopItem?
    @State private var desktopFrame: CGRect = .zero
    @State private var dockFrame: CGRect = .zero
    @State private var desktopArea: CGSize = .zero
    @State private var draggingID: String?
    @State private var folderTargetID: String?
    @State private var showBuiltinAlert = false
    @State private var renameTarget: RyFolder?
    @State private var renameText = ""

    private var isIPad: Bool { hSize == .regular }
    private var iconSize: CGFloat { (isIPad ? 72 : 60) * CGFloat(store.iconScale) }
    private var dockIconSize: CGFloat { (isIPad ? 58 : 50) * CGFloat(store.iconScale) }
    private var cellSize: CGSize { CGSize(width: iconSize + 8, height: iconSize + 24) }
    private var pitch: CGSize {
        CGSize(width: cellSize.width + (isIPad ? 26 : 16),
               height: cellSize.height + (isIPad ? 24 : 16))
    }

    var body: some View {
        GeometryReader { geo in
            ZStack {
                wallpaper

                VStack(spacing: 0) {
                    desktop
                    dock
                }
                .padding(.top, geo.safeAreaInsets.top)
                .padding(.bottom, geo.safeAreaInsets.bottom)

                if let app = activeApp {
                    // No ✕ inside: the floating Home key above this page IS the
                    // way out. onOpenItem lets a folder open one of its members.
                    FullScreenAppView(item: app,
                                      onOpenItem: { newItem in open(newItem) },
                                      onDismiss: { closeActiveApp() })
                        .transition(.scale(scale: 0.82).combined(with: .opacity))
                        .zIndex(2)
                }

                homeKey(geo)
                    .zIndex(3)

                if store.editMode {
                    editHint
                        .zIndex(4)
                        .transition(.opacity)
                }
            }
            .coordinateSpace(name: "root")
        }
        .ignoresSafeArea()
        .animation(.spring(response: 0.35, dampingFraction: 0.85), value: activeApp != nil)
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: store.editMode)
        .onReceive(NotificationCenter.default.publisher(for: SpringBoardController.goHomeNotification)) { _ in
            closeActiveApp()
            store.editMode = false
        }
        // A folder that just dissolved (last member removed) closes its page.
        .onChange(of: store.folders.count) { _ in
            guard let app = activeApp, case .folder(let f) = app.kind else { return }
            if !store.folders.contains(where: { $0.id == f.id }) { closeActiveApp() }
        }
        .alert("内置应用", isPresented: $showBuiltinAlert) {
            Button("好", role: .cancel) {}
        } message: {
            Text("内置应用不可删除。Dock 中的应用可以从 Dock 移除。")
        }
        .alert("重命名文件夹", isPresented: Binding(
            get: { renameTarget != nil },
            set: { if !$0 { renameTarget = nil } }
        )) {
            TextField("文件夹名称", text: $renameText)
            Button("保存") {
                if let f = renameTarget { store.renameFolder(f.id, to: renameText) }
                renameTarget = nil
            }
            Button("取消", role: .cancel) { renameTarget = nil }
        } message: {
            Text("给文件夹起个名字")
        }
    }

    // MARK: Wallpaper

    private var wallpaper: some View {
        ZStack {
            LinearGradient(colors: [Color(red: 0.10, green: 0.16, blue: 0.42),
                                    Color(red: 0.23, green: 0.37, blue: 0.76)],
                           startPoint: .topLeading, endPoint: .bottomTrailing)
                .ignoresSafeArea()
            Circle()
                .fill(Color(red: 0.48, green: 0.32, blue: 0.88).opacity(0.32))
                .frame(width: 460).blur(radius: 95).offset(x: -150, y: -240)
            Circle()
                .fill(Color(red: 0.16, green: 0.66, blue: 0.88).opacity(0.26))
                .frame(width: 400).blur(radius: 95).offset(x: 170, y: 280)
        }
    }

    // MARK: Desktop (icon grid)

    private var desktop: some View {
        GeometryReader { dg in
            ScrollView(.vertical, showsIndicators: false) {
                ZStack(alignment: .topLeading) {
                    ForEach(Array(store.allItems.enumerated()), id: \.element.id) { idx, item in
                        iconCell(item, index: idx, area: dg.size)
                    }
                }
                .frame(width: dg.size.width,
                       height: contentHeight(area: dg.size),
                       alignment: .topLeading)
                .overlay {
                    if store.allItems.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "square.and.arrow.down.on.square")
                                .font(.system(size: 40))
                            Text("导入 App 后会显示在这里")
                                .font(.system(size: 14, weight: .medium))
                        }
                        .foregroundStyle(.white.opacity(0.65))
                    }
                }
            }
            // In edit mode the scroll must yield to icon drags.
            .scrollDisabled(store.editMode)
            // Long-press EMPTY SPACE enters edit mode; long-pressing an icon
            // shows that icon's context menu instead (child gesture wins).
            .contentShape(Rectangle())
            .onLongPressGesture(minimumDuration: 0.5) {
                withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) { store.editMode = true }
            }
            .onTapGesture {
                if store.editMode {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) { store.editMode = false }
                }
            }
        }
        .background(
            GeometryReader { g in
                Color.clear.preference(key: FramePreferenceKey.self,
                                       value: g.frame(in: .named("root")))
            }
        )
        .onPreferenceChange(FramePreferenceKey.self) { desktopFrame = $0 }
    }

    private func contentHeight(area: CGSize) -> CGFloat {
        let cols = max(1, Int((area.width + 8) / pitch.width))
        let rows = max(1, (store.allItems.count + cols - 1) / cols)
        return max(area.height, CGFloat(rows) * pitch.height + 8)
    }

    private func iconCell(_ item: DesktopItem, index: Int, area: CGSize) -> some View {
        let pos = store.position(for: item.id)
            ?? store.defaultPosition(index: index, area: area, pitch: pitch, cell: cellSize)
        return AppIconView(
            item: item,
            size: iconSize,
            editMode: store.editMode,
            draggable: true,
            isDragging: draggingID == item.id,
            isFolderTarget: folderTargetID == item.id,
            inDock: store.isInDock(item.id),
            phase: index,
            position: pos,
            cell: cellSize,
            pitch: pitch,
            area: area,
            folderMembers: folderMembers(for: item),
            onOpen: { open(item) },
            onDragMove: { center in dragMoved(item, center: center) },
            onDrop: { center in drop(item, center: center) },
            onDelete: { delete(item) },
            onAddToDock: { store.addToDock(item.id) },
            onRemoveFromDock: { store.removeFromDock(item.id) },
            onRename: {
                if case .folder(let f) = item.kind {
                    renameTarget = f
                    renameText = f.name
                }
            },
            onDeleteFolder: {
                if case .folder(let f) = item.kind { store.deleteFolder(f.id) }
            }
        )
    }

    private func folderMembers(for item: DesktopItem) -> [DesktopItem] {
        if case .folder(let f) = item.kind { return store.members(of: f) }
        return []
    }

    // MARK: Dock (customizable)

    private var dock: some View {
        HStack(spacing: isIPad ? 26 : 18) {
            ForEach(store.dockItems) { item in
                AppIconView(
                    item: item,
                    size: dockIconSize,
                    editMode: false,
                    draggable: false,
                    isDragging: false,
                    isFolderTarget: false,
                    inDock: true,
                    phase: 0,
                    position: .zero,
                    cell: CGSize(width: dockIconSize + 8, height: dockIconSize + 18),
                    pitch: pitch,
                    area: .zero,
                    folderMembers: [],
                    onOpen: { open(item) },
                    onDragMove: { _ in },
                    onDrop: { _ in },
                    onDelete: {},
                    onAddToDock: {},
                    onRemoveFromDock: { store.removeFromDock(item.id) },
                    onRename: {},
                    onDeleteFolder: {}
                )
                .contextMenu {
                    if store.dockItems.count > 1 {
                        Button(role: .destructive) {
                            store.removeFromDock(item.id)
                        } label: {
                            Label("从 Dock 移除", systemImage: "minus.circle")
                        }
                    }
                }
            }
        }
        .padding(.vertical, isIPad ? 12 : 10)
        .padding(.horizontal, isIPad ? 26 : 16)
        .background(.ultraThinMaterial,
                    in: RoundedRectangle(cornerRadius: isIPad ? 30 : 24, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: isIPad ? 30 : 24, style: .continuous)
                .strokeBorder(store.dockHighlighted ? Color.accentColor : Color.white.opacity(0.20),
                              lineWidth: store.dockHighlighted ? 2 : 0.5)
        )
        .shadow(color: .black.opacity(store.dockHighlighted ? 0.4 : 0.25),
                radius: store.dockHighlighted ? 16 : 10,
                y: store.dockHighlighted ? 6 : 4)
        .scaleEffect(store.dockHighlighted ? 1.04 : 1.0)
        .animation(.spring(response: 0.25, dampingFraction: 0.7), value: store.dockHighlighted)
        .padding(.horizontal, isIPad ? 28 : 10)
        .padding(.bottom, 56)   // room for the floating Home key
        .background(
            GeometryReader { g in
                Color.clear.preference(key: DockFramePreferenceKey.self,
                                       value: g.frame(in: .named("root")))
            }
        )
        .onPreferenceChange(DockFramePreferenceKey.self) { dockFrame = $0 }
    }

    // MARK: Square liquid-glass Home key (doubles as 完成 in edit mode)

    private func homeKey(_ geo: GeometryProxy) -> some View {
        VStack {
            Spacer()
            Button(action: goHome) {
                Image(systemName: store.editMode ? "checkmark" : "house.fill")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(.primary)
                    .frame(width: 46, height: 46)
                    .background(.ultraThinMaterial,
                                in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 13, style: .continuous)
                            .strokeBorder(.white.opacity(0.30), lineWidth: 0.6)
                    )
                    .shadow(color: .black.opacity(0.28), radius: 9, y: 3)
            }
            .buttonStyle(.plain)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)
        .padding(.bottom, geo.safeAreaInsets.bottom + 4)
    }

    // MARK: Edit-mode hint (minimal, non-blocking)

    private var editHint: some View {
        VStack {
            Spacer()
            Text("松开即放下 · 叠放建文件夹 · 拖到底部 Dock 添加")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.white.opacity(0.75))
                .padding(.horizontal, 14)
                .padding(.vertical, 7)
                .background(.ultraThinMaterial, in: Capsule())
                .padding(.bottom, 76)
            Spacer()
        }
        .allowsHitTesting(false)
    }

    // MARK: Drag & drop

    private func dragMoved(_ item: DesktopItem, center: CGPoint) {
        if draggingID != item.id { draggingID = item.id }
        store.dockHighlighted = dockFrame.contains(center)

        // Nearest OTHER icon within a small radius → folder drop target.
        var bestID: String?
        var bestDist = pitch.width * 0.6
        for (i, other) in store.allItems.enumerated() where other.id != item.id {
            let p = store.position(for: other.id)
                ?? store.defaultPosition(index: i, area: desktopArea, pitch: pitch, cell: cellSize)
            let c = CGPoint(x: p.x + cellSize.width / 2, y: p.y + cellSize.height / 2)
            let d = hypot(center.x - c.x, center.y - c.y)
            if d < bestDist { bestDist = d; bestID = other.id }
        }
        folderTargetID = bestID
    }

    private func drop(_ item: DesktopItem, center: CGPoint) {
        defer {
            draggingID = nil
            folderTargetID = nil
            store.dockHighlighted = false
        }
        if dockFrame.contains(center) {
            store.addToDock(item.id)
            return
        }
        if let target = folderTargetID, target != item.id {
            if target.hasPrefix("folder.") {
                store.addToFolder(item.id, folderID: String(target.dropFirst(7)))
            } else {
                store.createFolder(with: [target, item.id])
            }
        }
    }

    // MARK: Actions

    private func open(_ item: DesktopItem) {
        withAnimation(.spring(response: 0.38, dampingFraction: 0.82)) { activeApp = item }
    }

    private func closeActiveApp() {
        withAnimation(.spring(response: 0.32, dampingFraction: 0.85)) { activeApp = nil }
    }

    private func goHome() {
        closeActiveApp()
        store.editMode = false
    }

    private func delete(_ item: DesktopItem) {
        guard item.isDeletable else {
            showBuiltinAlert = true
            return
        }
        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
            store.editMode = false
            switch item.kind {
            case .guest(let app):
                AppImporter.shared.remove(app)
                store.positions.removeValue(forKey: item.id)
            case .folder(let f):
                store.deleteFolder(f.id)
            case .builtin:
                break
            }
        }
    }
}

/// A single desktop/dock icon: squircle + label, per-icon jiggle phase,
/// − badge in edit mode, drag-to-reposition with grid snapping (desktop only),
/// long-press context menu, and a 2×2 mini preview for folders.
struct AppIconView: View {
    let item: DesktopItem
    let size: CGFloat
    let editMode: Bool
    let draggable: Bool
    let isDragging: Bool
    let isFolderTarget: Bool
    let inDock: Bool
    let phase: Int
    let position: CGPoint          // committed top-left (desktop-area coords)
    let cell: CGSize
    let pitch: CGSize
    let area: CGSize
    let folderMembers: [DesktopItem]
    var onOpen: () -> Void
    var onDragMove: (CGPoint) -> Void
    var onDrop: (CGPoint) -> Void
    var onDelete: () -> Void
    var onAddToDock: () -> Void
    var onRemoveFromDock: () -> Void
    var onRename: () -> Void
    var onDeleteFolder: () -> Void

    @State private var drag: CGSize = .zero
    @State private var jiggle = false

    var body: some View {
        VStack(spacing: 5) {
            ZStack(alignment: .topTrailing) {
                iconBody
                    .overlay(
                        RoundedRectangle(cornerRadius: size * 0.225, style: .continuous)
                            .strokeBorder(isFolderTarget ? Color.accentColor : Color.clear,
                                          lineWidth: isFolderTarget ? 2.5 : 0)
                    )
                    .scaleEffect(isFolderTarget ? 1.12 : (isDragging ? 1.06 : 1.0))

                if editMode {
                    Button(action: onDelete) {
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
                .frame(width: cell.width)
        }
        .frame(width: cell.width, height: cell.height)
        .contentShape(Rectangle())
        .offset(x: position.x + drag.width, y: position.y + drag.height)
        // Per-icon jiggle phase: different durations + alternating direction,
        // so the whole desktop wobbles organically instead of in lockstep.
        .rotationEffect(.degrees(editMode ? (jiggle ? Double(phase % 2 == 0 ? 11 : -11) / 10
                                                  : Double(phase % 2 == 0 ? -11 : 11) / 10) : 0),
                        anchor: .center)
        .animation(editMode
                   ? .easeInOut(duration: 0.075 + 0.022 * Double(phase % 6))
                       .repeatForever(autoreverses: true)
                   : .default,
                   value: jiggle)
        .onChange(of: editMode) { on in jiggle = on }
        .onTapGesture { if !editMode { onOpen() } }
        .contextMenu {
            Button { onOpen() } label: {
                Label("打开", systemImage: "arrow.up.right.square")
            }
            if !inDock {
                Button { onAddToDock() } label: {
                    Label("添加到 Dock", systemImage: "plus.square.on.square")
                }
            } else {
                Button { onRemoveFromDock() } label: {
                    Label("从 Dock 移除", systemImage: "minus.square")
                }
            }
            if item.isGuest {
                Button(role: .destructive) { onDelete() } label: {
                    Label("删除 App", systemImage: "trash")
                }
            }
            if case .folder = item.kind {
                Button { onRename() } label: {
                    Label("重命名", systemImage: "pencil")
                }
                Button(role: .destructive) { onDeleteFolder() } label: {
                    Label("解散文件夹", systemImage: "folder.badge.minus")
                }
            }
        }
        .simultaneousGesture(
            DragGesture(minimumDistance: 6)
                .onChanged { v in
                    guard editMode && draggable else { return }
                    drag = v.translation
                    let center = CGPoint(x: position.x + v.translation.width + cell.width / 2,
                                         y: position.y + v.translation.height + cell.height / 2)
                    onDragMove(center)
                }
                .onEnded { v in
                    guard editMode && draggable else { return }
                    let snapped = snap(CGPoint(x: position.x + v.translation.width,
                                               y: position.y + v.translation.height))
                    onDrop(CGPoint(x: snapped.x + cell.width / 2, y: snapped.y + cell.height / 2))
                    drag = .zero
                }
        )
        .zIndex(isDragging ? 10 : 0)
    }

    // MARK: Icon artwork

    @ViewBuilder
    private var iconBody: some View {
        if case .folder(let folder) = item.kind {
            folderIcon(folder)
        } else {
            RoundedRectangle(cornerRadius: size * 0.225, style: .continuous)
                .fill(LinearGradient(colors: [item.tint.opacity(0.92), item.tint],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
                .frame(width: size, height: size)
                .overlay(
                    Image(systemName: item.symbol)
                        .font(.system(size: size * 0.44, weight: .medium))
                        .foregroundStyle(.white)
                )
                .shadow(color: .black.opacity(0.22), radius: 5, y: 3)
        }
    }

    /// Folder squircle with a 2×2 mini preview of its members.
    private func folderIcon(_ folder: RyFolder) -> some View {
        let previews = Array(folderMembers.prefix(4))
        return RoundedRectangle(cornerRadius: size * 0.225, style: .continuous)
            .fill(.ultraThinMaterial)
            .frame(width: size, height: size)
            .overlay(
                RoundedRectangle(cornerRadius: size * 0.225, style: .continuous)
                    .strokeBorder(.white.opacity(0.25), lineWidth: 0.5)
            )
            .overlay(
                VStack(spacing: size * 0.045) {
                    ForEach(0..<2, id: \.self) { row in
                        HStack(spacing: size * 0.045) {
                            ForEach(0..<2, id: \.self) { col in
                                let idx = row * 2 + col
                                ZStack {
                                    RoundedRectangle(cornerRadius: size * 0.08, style: .continuous)
                                        .fill(previews.indices.contains(idx)
                                              ? previews[idx].tint
                                              : Color.white.opacity(0.18))
                                        .frame(width: size * 0.32, height: size * 0.32)
                                    if previews.indices.contains(idx) {
                                        Image(systemName: previews[idx].symbol)
                                            .font(.system(size: size * 0.13))
                                            .foregroundStyle(.white)
                                    }
                                }
                            }
                        }
                    }
                }
            )
            .shadow(color: .black.opacity(0.22), radius: 5, y: 3)
    }

    private func snap(_ raw: CGPoint) -> CGPoint {
        let x = (raw.x / pitch.width).rounded() * pitch.width
        let y = (raw.y / pitch.height).rounded() * pitch.height
        return CGPoint(x: max(4, min(area.width - cell.width - 4, x)),
                       y: max(4, min(area.height - cell.height - 4, y)))
    }
}

// MARK: - Preference keys (desktop / dock frames in the shared "root" space)

private struct FramePreferenceKey: PreferenceKey {
    static var defaultValue: CGRect = .zero
    static func reduce(value: inout CGRect, nextValue: () -> CGRect) { value = nextValue() }
}

private struct DockFramePreferenceKey: PreferenceKey {
    static var defaultValue: CGRect = .zero
    static func reduce(value: inout CGRect, nextValue: () -> CGRect) { value = nextValue() }
}
