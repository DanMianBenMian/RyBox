import SwiftUI

/// RyBox's home screen — an iOS-style desktop.
///
///  - Installed guest apps (AppImporter) AND built-ins (Sileo is preinstalled)
///    show as icons on the desktop.
///  - Long-press → edit mode: icons jiggle, drag to reposition (grid-snapped),
///    drag onto the Dock to add, tap − to delete guest apps.
///  - Tapping an icon opens a FULL-SCREEN app page (FullScreenAppView).
///  - The floating Home key is a liquid-glass pill rendered INSIDE this window
///    (no separate always-on overlay window — that used to swallow every touch
///    in the container, including document pickers and sheets).
///  - Dock membership/order and icon layout persist across launches.
struct SpringBoardView: View {
    @ObservedObject private var store = DesktopStore.shared
    @ObservedObject private var importer = AppImporter.shared
    @Environment(\.horizontalSizeClass) private var hSize

    @State private var activeApp: DesktopItem?
    @State private var desktopFrame: CGRect = .zero
    @State private var dockFrame: CGRect = .zero

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
                    FullScreenAppView(item: app)
                        .transition(.scale(scale: 0.82).combined(with: .opacity))
                        .zIndex(2)
                }

                homePill(geo)
                    .zIndex(3)

                if store.editMode {
                    editBar
                        .zIndex(4)
                        .transition(.move(edge: .top).combined(with: .opacity))
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
        }
        .background(
            GeometryReader { g in
                Color.clear.preference(key: FramePreferenceKey.self,
                                       value: g.frame(in: .named("root")))
            }
        )
        .onPreferenceChange(FramePreferenceKey.self) { desktopFrame = $0 }
    }

    /// Content height of the icon grid (grows past the visible area so the
    /// ScrollView can reach every icon).
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
            position: pos,
            cell: cellSize,
            pitch: pitch,
            area: area,
            onOpen: { open(item) },
            onCommit: { store.savePosition($0, for: item.id) },
            onDropInDock: { topLeft in
                let center = CGPoint(x: desktopFrame.minX + topLeft.x + cellSize.width / 2,
                                     y: desktopFrame.minY + topLeft.y + cellSize.height / 2)
                if dockFrame.contains(center) { store.addToDock(item.id) }
            },
            onDelete: { delete(item) },
            onLongPress: {
                withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) { store.editMode = true }
            }
        )
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
                    position: .zero,
                    cell: CGSize(width: dockIconSize + 8, height: dockIconSize + 18),
                    pitch: pitch,
                    area: .zero,
                    onOpen: { open(item) },
                    onCommit: { _ in },
                    onDropInDock: { _ in },
                    onDelete: {},
                    onLongPress: {}
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
                .strokeBorder(.white.opacity(0.20), lineWidth: 0.5)
        )
        .shadow(color: .black.opacity(0.25), radius: 10, y: 4)
        .padding(.horizontal, isIPad ? 28 : 10)
        .padding(.bottom, 56)   // room for the floating Home pill
        .background(
            GeometryReader { g in
                Color.clear.preference(key: DockFramePreferenceKey.self,
                                       value: g.frame(in: .named("root")))
            }
        )
        .onPreferenceChange(DockFramePreferenceKey.self) { dockFrame = $0 }
    }

    // MARK: Floating liquid-glass Home key

    private func homePill(_ geo: GeometryProxy) -> some View {
        VStack {
            Spacer()
            Button(action: goHome) {
                HStack(spacing: 7) {
                    Image(systemName: "house.fill")
                        .font(.system(size: 13, weight: .semibold))
                    Text("主屏")
                        .font(.system(size: 13.5, weight: .semibold))
                }
                .foregroundStyle(.primary)
                .padding(.horizontal, 16)
                .padding(.vertical, 9)
                .background(.ultraThinMaterial, in: Capsule())
                .overlay(Capsule().strokeBorder(.white.opacity(0.30), lineWidth: 0.6))
                .shadow(color: .black.opacity(0.28), radius: 9, y: 3)
            }
            .buttonStyle(.plain)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)
        .padding(.bottom, geo.safeAreaInsets.bottom + 4)
    }

    // MARK: Edit-mode top bar

    private var editBar: some View {
        VStack(spacing: 0) {
            HStack {
                Text("编辑桌面")
                    .font(.system(size: 16, weight: .semibold))
                Spacer()
                Button("完成") {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.75)) { store.editMode = false }
                }
                .font(.system(size: 15, weight: .semibold))
                .tint(.accentColor)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 11)
            .background(.ultraThinMaterial)
            Text("拖动图标调整位置 · 拖到 Dock 栏添加 · 点 − 删除应用")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
                .padding(.top, 5)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
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
        guard case .guest(let app) = item.kind else { return }
        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
            store.editMode = false
            AppImporter.shared.remove(app)
            store.positions.removeValue(forKey: item.id)
        }
    }
}

/// A single desktop/dock icon: squircle + label, jiggle + − badge in edit mode,
/// drag-to-reposition with grid snapping (desktop only).
struct AppIconView: View {
    let item: DesktopItem
    let size: CGFloat
    let editMode: Bool
    let draggable: Bool
    let position: CGPoint          // committed top-left (desktop-area coords)
    let cell: CGSize
    let pitch: CGSize
    let area: CGSize
    var onOpen: () -> Void
    var onCommit: (CGPoint) -> Void
    var onDropInDock: (CGPoint) -> Void
    var onDelete: () -> Void
    var onLongPress: () -> Void

    @State private var drag: CGSize = .zero
    @State private var jiggle = false

    var body: some View {
        VStack(spacing: 5) {
            ZStack(alignment: .topTrailing) {
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

                if editMode && item.isGuest {
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
        .rotationEffect(.degrees(editMode ? (jiggle ? 1.5 : -1.5) : 0), anchor: .center)
        .animation(editMode ? .easeInOut(duration: 0.13).repeatForever(autoreverses: true) : .default,
                   value: jiggle)
        .onChange(of: editMode) { on in jiggle = on }
        .onTapGesture { if !editMode { onOpen() } }
        .simultaneousGesture(
            LongPressGesture(minimumDuration: 0.45).onEnded { _ in onLongPress() }
        )
        .simultaneousGesture(
            DragGesture(minimumDistance: 6)
                .onChanged { v in if editMode && draggable { drag = v.translation } }
                .onEnded { v in
                    guard editMode && draggable else { return }
                    let snapped = snap(CGPoint(x: position.x + v.translation.width,
                                               y: position.y + v.translation.height))
                    onCommit(snapped)
                    onDropInDock(snapped)
                    drag = .zero
                }
        )
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
