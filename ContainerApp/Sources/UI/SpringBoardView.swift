import SwiftUI
import Combine

/// RyBox's home screen — an iOS-style desktop rendered as a paged SpringBoard.
///
/// Layout model matches the real thing rather than a free-form canvas:
///  * icons live in a strict grid (page / row / col — see `IconSlot`),
///  * pages swipe horizontally with page dots below,
///  * the page after the last one is the App Library,
///  * the Dock is a separate strip and themable,
///  * cold start and every respring land on the lock screen.
///
/// Theming: everything visual is routed through `ThemeEngine` (icon artwork,
/// wallpaper, dock/folder backgrounds), so a WinterBoard/SnowBoard package
/// dropped into `/Library/Themes` applies without code changes.
///
/// Editing: long-press empty space → jiggle mode; drag to reposition, drop onto
/// another icon to create a folder, drag to the Dock to pin. Tap − to delete.
struct SpringBoardView: View {
    @ObservedObject private var store = DesktopStore.shared
    @ObservedObject private var importer = AppImporter.shared
    @ObservedObject private var theme = ThemeEngine.shared
    @Environment(\.horizontalSizeClass) private var hSize

    @State private var activeApp: DesktopItem?
    @State private var page = 0
    @State private var locked = true
    @State private var respringing = false
    @State private var dockFrame: CGRect = .zero
    /// The grid's origin + cell pitch, published by `pageView`. The drag
    /// gesture uses these EXACT numbers so the drop target matches the layout.
    /// `gridOrigin` is in the shared "root" space (same space as `dockFrame`),
    /// so the grid hit test and the Dock hit test agree.
    @State private var gridOrigin: CGPoint = .zero
    @State private var gridPitch: CGSize = .zero
    @State private var gridCell: CGSize = .zero
    /// The grid's page-LOCAL origin and the page's origin in root space — the
    /// two pieces `gridOrigin` is derived from.
    @State private var gridLocalOrigin: CGPoint = .zero
    @State private var gridPageOrigin: CGPoint = .zero
    @State private var draggingID: String?
    @State private var dragTranslation: CGSize = .zero
    /// True while a finger is pressing an icon (before the long press fires).
    /// The pager must not page in that window, or the page slides out from
    /// under the finger.
    @State private var isIconPressing = false
    @State private var target: IconSlot?
    @State private var showBuiltinAlert = false
    @State private var renameTarget: RyFolder?
    @State private var renameText = ""
    @State private var toast = ""
    /// Drives the edit-mode jiggle (one shared flag; per-slot duration/parity
    /// keeps the icons from wobbling in lockstep).
    @State private var jiggle = false
    /// Live drag offset for the page-swipe gesture (so the page follows the
    /// finger instead of jumping at the end).
    @State private var pageDragOffset: CGFloat = 0

    @ObservedObject private var sb = SpringBoardController.shared
    /// Gesture-driven shell panels (深度还原 SpringBoard).
    @State private var showControlCenter = false
    @State private var showAppSwitcher = false
    @State private var showNotificationCenter = false

    private var isIPad: Bool { hSize == .regular }
    private var columns: Int { DesktopStore.columns(isIPad: isIPad) }
    private var rows: Int { DesktopStore.rows(isIPad: isIPad) }
    private var iconSize: CGFloat { (isIPad ? 68 : 58) * CGFloat(store.iconScale) }
    private var dockIconSize: CGFloat { (isIPad ? 56 : 48) * CGFloat(store.iconScale) }

    /// CELL width/height. The icon artwork is `iconSize` wide, but the cell also
    /// holds the name label, so the CELL is wider than the artwork.
    ///
    /// THE LAYOUT MUST USE THE CELL SIZE, NOT THE ARTWORK SIZE. The earlier
    /// code mixed the two (artwork width for the pitch, cell width for the
    /// frame), which made every column drift a few points to the right — the
    /// "图标位置会偏移" report. One number, used everywhere.
    private var cellWidth: CGFloat { iconSize + 14 }
    private var cellHeight: CGFloat { iconSize + 22 }
    /// Distance between two cell centres.
    private var colPitch: CGFloat { cellWidth + (isIPad ? 18 : 12) }
    private var rowPitch: CGFloat { cellHeight + (isIPad ? 16 : 12) }

    /// Home pages plus the App Library page.
    private var pageCount: Int { store.pageCount + 1 }

    var body: some View {
        ZStack {
            if respringing {
                RespringView()
                    .transition(.opacity)
            } else if locked {
                LockScreenView { withAnimation(.spring(response: 0.4, dampingFraction: 0.9)) { locked = false } }
                    .transition(.opacity)
            } else {
                homeScreen
                    .transition(.opacity)
            }

            // Gesture-driven shell panels (深度还原 SpringBoard).
            if showControlCenter {
                ControlCenterView(onDismiss: { showControlCenter = false })
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .zIndex(10)
            }
            if showAppSwitcher {
                AppSwitcherView(
                    recents: sb.recents,
                    onOpen: { item in
                        showAppSwitcher = false
                        open(item)
                    },
                    onQuit: { id in
                        SpringBoardController.shared.removeRecent(id)
                    },
                    onDismiss: { showAppSwitcher = false }
                )
                .transition(.opacity)
                .zIndex(10)
            }
            if showNotificationCenter {
                NotificationCenterView(
                    onOpen: { item in
                        showNotificationCenter = false
                        open(item)
                    },
                    onDismiss: { showNotificationCenter = false }
                )
                .transition(.move(edge: .top).combined(with: .opacity))
                .zIndex(10)
            }
        }
        .animation(.easeInOut(duration: 0.25), value: respringing)
        .animation(.easeInOut(duration: 0.25), value: locked)
        .onAppear {
            store.pruneSlots()
            store.ensurePlaced(isIPad: isIPad)
            VirtualRoot.shared.ensure()
        }
        .onReceive(NotificationCenter.default.publisher(for: SpringBoardController.goHomeNotification)) { _ in
            goHome()
        }
        .onReceive(NotificationCenter.default.publisher(for: SpringBoardController.respringNotification)) { _ in
            respring()
        }
        .onReceive(NotificationCenter.default.publisher(for: SpringBoardController.reloadLibraryNotification)) { _ in
            reloadLibrary()
        }
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

    // MARK: Home screen

    private var homeScreen: some View {
        GeometryReader { geo in
            ZStack {
                wallpaper
                    .ignoresSafeArea()

                VStack(spacing: 0) {
                    StatusBarView()
                        .padding(.top, max(0, geo.safeAreaInsets.top - 4))
                        .onLongPressGesture(minimumDuration: 0.4) { showControlCenter = true }
                        .simultaneousGesture(
                            DragGesture(minimumDistance: 24)
                                .onEnded { v in
                                    if v.translation.height > 40 && abs(v.translation.width) < 50 {
                                        showNotificationCenter = true
                                    }
                                }
                        )

                    pager
                        .frame(maxHeight: .infinity)

                    // Reserve the dock + Home key strip so the last grid row is
                    // never hidden underneath them.
                    Spacer(minLength: dockHeight + 40)
                }

                if let app = activeApp {
                    // No ✕ inside: the floating Home key above this page IS the
                    // way out (the user asked for exactly that).
                    FullScreenAppView(item: app,
                                      onOpenItem: { newItem in open(newItem) },
                                      onDismiss: { closeActiveApp() })
                        .transition(.scale(scale: 0.82).combined(with: .opacity))
                        .zIndex(2)
                }

                dock(geo)
                    .zIndex(1)

                homeKey(geo)
                    .zIndex(3)

                if store.editMode { editHint.zIndex(4) }
                if !toast.isEmpty { toastView.zIndex(5) }
            }
            .coordinateSpace(name: "root")
        }
        .ignoresSafeArea()
        .animation(.spring(response: 0.35, dampingFraction: 0.85), value: activeApp != nil)
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: store.editMode)
        // Start/stop the wobble with edit mode.
        .onChange(of: store.editMode) { jiggle = $0 }
    }

    // MARK: Wallpaper (themed, with page parallax like iOS)

    private var wallpaper: some View {
        ZStack {
            if let img = theme.wallpaper(.home) {
                Image(uiImage: img)
                    .resizable()
                    .scaledToFill()
                    // iOS shifts the wallpaper slightly per page; cheap but it
                    // is the detail that makes paging feel like a home screen.
                    .offset(x: -CGFloat(page) * 14)
                    .animation(.easeInOut(duration: 0.25), value: page)
            } else {
                LinearGradient(colors: [Color(red: 0.10, green: 0.16, blue: 0.42),
                                        Color(red: 0.23, green: 0.37, blue: 0.76)],
                               startPoint: .topLeading, endPoint: .bottomTrailing)
                Circle()
                    .fill(Color(red: 0.48, green: 0.32, blue: 0.88).opacity(0.32))
                    .frame(width: 460).blur(radius: 95).offset(x: -150, y: -240)
                Circle()
                    .fill(Color(red: 0.16, green: 0.66, blue: 0.88).opacity(0.26))
                    .frame(width: 400).blur(radius: 95).offset(x: 170, y: 280)
            }
        }
    }

    // MARK: Pager

    /// A hand-rolled pager instead of `TabView(.page)`.
    ///
    /// `TabView(.page)` was the source of the "左右滑动手势触发区偏移" report:
    /// its internal scroll view swallows the gesture in unpredictable places,
    /// and the App Library's own vertical ScrollView competes with it, so the
    /// last page could not be reached by swiping.
    ///
    /// This implementation owns the gesture end to end:
    ///   * the horizontal drag is detected on the whole pager area,
    ///   * the page follows the finger 1:1 (no jump at the end),
    ///   * the App Library's vertical ScrollView keeps working, because the
    ///     pager only reacts to clearly HORIZONTAL drags.
    private var pager: some View {
        GeometryReader { geo in
            let w = geo.size.width
            ZStack(alignment: .topLeading) {
                ForEach(0..<pageCount, id: \.self) { i in
                    pageView(i)
                        .frame(width: w, height: geo.size.height)
                        .offset(x: -CGFloat(page) * w + pageDragOffset)
                }
                AppLibraryView { item in open(item) }
                    .frame(width: w, height: geo.size.height)
                    .offset(x: -CGFloat(pageCount - 1) * w + pageDragOffset)
            }
            .frame(width: w, height: geo.size.height, alignment: .topLeading)
            .contentShape(Rectangle())
            // `simultaneousGesture`, not `gesture`: the App Library's vertical
            // ScrollView must keep working. The gesture below ignores any drag
            // that is not clearly horizontal, so the two never fight.
            .simultaneousGesture(pageSwipeGesture(pageWidth: w))
            .overlay(alignment: .bottom) {
                pageDots
                    .padding(.bottom, dockHeight + 22)
            }
            // The grid's geometry: page-local origin + pitch, plus the page's
            // own origin in root space. Combining them gives the grid's
            // ROOT-space origin, which is the space the drag gesture and the
            // Dock frame both use.
            .onPreferenceChange(PageFramePreferenceKey.self) { metrics in
                gridPitch = metrics.pitch
                gridCell = metrics.cell
                gridLocalOrigin = metrics.origin
                updateGridOrigin()
            }
            .onPreferenceChange(PageOriginPreferenceKey.self) { pageOrigin in
                gridPageOrigin = pageOrigin
                updateGridOrigin()
            }
        }
    }

    /// Recompute the grid's root-space origin from its two components.
    private func updateGridOrigin() {
        gridOrigin = CGPoint(x: gridPageOrigin.x + gridLocalOrigin.x,
                             y: gridPageOrigin.y + gridLocalOrigin.y)
    }

    /// Horizontal paging gesture.
    ///
    /// It only engages for a clearly horizontal drag, so the App Library's
    /// vertical list scrolls normally, and it drives `page` directly so the
    /// trigger area is exactly the pager rectangle — no offset.
    ///
    /// It yields to the ICON drag: while an icon is being dragged (or is being
    /// pressed towards a long-press), the pager must not page — otherwise the
    /// page slides away under the finger.
    private func pageSwipeGesture(pageWidth: CGFloat) -> some Gesture {
        DragGesture(minimumDistance: 12, coordinateSpace: .named("root"))
            .onChanged { v in
                guard !store.editMode, draggingID == nil, !isIconPressing else {
                    pageDragOffset = 0
                    return
                }
                // Vertical intent → let the inner scroll view have it.
                guard abs(v.translation.width) > abs(v.translation.height) * 1.4 else {
                    pageDragOffset = 0
                    return
                }
                // Rubber-band at the first / last page.
                var offset = v.translation.width
                if page == 0 && offset > 0 { offset *= 0.25 }
                if page == pageCount - 1 && offset < 0 { offset *= 0.25 }
                pageDragOffset = offset
            }
            .onEnded { v in
                guard !store.editMode, draggingID == nil, !isIconPressing else {
                    pageDragOffset = 0
                    return
                }
                defer { pageDragOffset = 0 }
                guard abs(v.translation.width) > abs(v.translation.height) * 1.4 else { return }
                let threshold = pageWidth * 0.22
                var next = page
                if v.translation.width < -threshold {
                    next = page + 1
                } else if v.translation.width > threshold {
                    next = page - 1
                }
                let clamped = max(0, min(pageCount - 1, next))
                if clamped != page {
                    withAnimation(.easeInOut(duration: 0.28)) { page = clamped }
                }
            }
    }

    private var pageDots: some View {
        HStack(spacing: 8) {
            // One dot per home page, plus the App Library dot at the end.
            ForEach(0..<pageCount, id: \.self) { i in
                Group {
                    if i == store.pageCount {
                        // The App Library dot is a tiny grid, like iOS.
                        RoundedRectangle(cornerRadius: 1.5)
                            .strokeBorder(Color.white.opacity(i == page ? 0.95 : 0.4), lineWidth: 1)
                            .frame(width: 8, height: 8)
                            .overlay(
                                VStack(spacing: 1.2) {
                                    ForEach(0..<2, id: \.self) { _ in
                                        HStack(spacing: 1.2) {
                                            ForEach(0..<2, id: \.self) { _ in
                                                Rectangle()
                                                    .fill(Color.white.opacity(i == page ? 0.95 : 0.4))
                                                    .frame(width: 2, height: 2)
                                            }
                                        }
                                    }
                                }
                            )
                    } else {
                        Circle()
                            .fill(Color.white.opacity(i == page ? 0.95 : 0.38))
                            .frame(width: 7, height: 7)
                    }
                }
                .onTapGesture {
                    withAnimation(.easeInOut(duration: 0.28)) { page = i }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(.black.opacity(0.001))   // stable hit area
        .allowsHitTesting(true)
    }

    /// One home-screen page: a strict grid whose cells are filled by slot.
    ///
    /// The grid is laid out with ABSOLUTE positions computed from the cell
    /// pitch, not with an HStack/VStack of flexible frames. Two reasons:
    ///   * the cell pitch and the icon artwork size can no longer disagree
    ///     (that mismatch is what made icons drift sideways), and
    ///   * the drag-and-drop hit test can use the very same numbers, so an icon
    ///     lands exactly in the cell the user aimed at.
    private func pageView(_ index: Int) -> some View {
        let items = store.items(onPage: index)
        var placed: [String: DesktopItem] = [:]
        for item in items {
            if let s = store.slot(for: item.id) { placed["\(s.row),\(s.col)"] = item }
        }
        return GeometryReader { geo in
            let gridW = CGFloat(columns) * colPitch
            // Centre the grid horizontally inside the page.
            let originX = max(0, (geo.size.width - gridW) / 2)
            let originY: CGFloat = 18

            ZStack(alignment: .topLeading) {
                // Faint slot outlines make the grid legible while dragging.
                ForEach(0..<rows, id: \.self) { row in
                    ForEach(0..<columns, id: \.self) { col in
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .strokeBorder(Color.white.opacity(store.editMode ? 0.10 : 0.0),
                                          lineWidth: 0.5)
                            .frame(width: cellWidth - 6, height: cellHeight - 6)
                            .position(x: originX + CGFloat(col) * colPitch + colPitch / 2,
                                      y: originY + CGFloat(row) * rowPitch + rowPitch / 2)
                    }
                }

                ForEach(0..<rows, id: \.self) { row in
                    ForEach(0..<columns, id: \.self) { col in
                        if let item = placed["\(row),\(col)"] {
                            iconCell(item, page: index, row: row, col: col)
                                .frame(width: cellWidth, height: cellHeight)
                                .position(x: originX + CGFloat(col) * colPitch + colPitch / 2,
                                          y: originY + CGFloat(row) * rowPitch + rowPitch / 2)
                        }
                    }
                }
            }
            .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
            .background(
                // Publish the grid's geometry in the shared "root" space, so the
                // drag gesture can convert a finger position into a target cell
                // using the SAME coordinates the layout used. (Mixing page-local
                // and root coordinates is what made the drop target appear
                // offset from the finger.)
                GeometryReader { _ in
                    Color.clear.preference(key: PageFramePreferenceKey.self,
                                           value: GridMetrics(origin: CGPoint(x: originX, y: originY),
                                                              pitch: CGSize(width: colPitch, height: rowPitch),
                                                              cell: CGSize(width: cellWidth, height: cellHeight)))
                }
            )
            .background(
                // The page's own frame in root space — combined with the grid's
                // page-local origin it yields the grid's ROOT-space origin.
                GeometryReader { _ in
                    Color.clear.preference(key: PageOriginPreferenceKey.self,
                                           value: geo.frame(in: .named("root")).origin)
                }
            )
        }
        // Long-press EMPTY SPACE → edit mode; child icons win with their own
        // long-press (context menu) so tapping an icon still opens it.
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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

    // MARK: Icon cell

    private func iconCell(_ item: DesktopItem, page: Int, row: Int, col: Int) -> some View {
        let slot = IconSlot(page: page, row: row, col: col)
        let seed = row * columns + col
        let isDragging = draggingID == item.id
        let isTarget = (target.map { $0 == slot } ?? false) && !isDragging
        let badge = store.badge(for: item.id)
        return VStack(spacing: 5) {
            ZStack(alignment: .topTrailing) {
                IconArtwork(item: item,
                            size: iconSize,
                            folderMembers: folderMembers(for: item))
                    .overlay(
                        RoundedRectangle(cornerRadius: iconSize * 0.225, style: .continuous)
                            .strokeBorder(isTarget ? Color.accentColor : Color.clear, lineWidth: 2.5)
                    )
                    .scaleEffect(isDragging ? 1.12 : 1.0)

                if badge > 0 {
                    BadgeView(count: badge)
                        .offset(x: iconSize * 0.18, y: -iconSize * 0.12)
                }

                if store.editMode {
                    Button(action: { delete(item) }) {
                        Image(systemName: "minus.circle.fill")
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, Color(red: 0.92, green: 0.26, blue: 0.30))
                            .font(.system(size: iconSize * 0.27))
                            .contentShape(Circle())
                    }
                    .buttonStyle(.plain)
                    .frame(width: iconSize * 0.34, height: iconSize * 0.34)
                    .offset(x: iconSize * 0.15, y: -iconSize * 0.15)
                }
            }
            Text(item.name)
                .font(.system(size: 11.5, weight: .medium))
                .foregroundStyle(.white)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
                .frame(width: cellWidth - 2)
        }
        .frame(width: cellWidth, height: cellHeight)
        .offset(isDragging ? dragTranslation : .zero)
        .rotationEffect(.degrees(store.editMode ? (jiggle ? jiggleAngle(seed: seed)
                                                         : -jiggleAngle(seed: seed)) : 0),
                        anchor: .center)
        .animation(store.editMode
                   ? .easeInOut(duration: 0.13 + 0.02 * Double(seed % 5))
                       .repeatForever(autoreverses: true)
                   : .default,
                   value: jiggle)
        .animation(.easeInOut(duration: 0.16), value: dragTranslation)
        .zIndex(isDragging ? 20 : 0)
        .contentShape(Rectangle())
        .onTapGesture { if !store.editMode { open(item) } }
        .contextMenu { iconMenu(item) }
        // Long-press-and-drag on an ICON enters edit mode and starts moving
        // that icon — the gesture the user asked for. The drag gesture below
        // only moves icons when edit mode is already on; this one turns edit
        // mode ON by itself when the finger stays down and starts to move.
        .simultaneousGesture(longPressDragGesture(item: item, slot: slot))
        .simultaneousGesture(dragGesture(item: item, slot: slot))
    }

    /// Long-press then drag → enter edit mode and drag the icon.
    ///
    /// Implemented as a `LongPressGesture` sequenced with a `DragGesture`:
    /// the long press must succeed first (0.28 s), and only a subsequent
    /// movement starts the drag. A plain long press without movement still
    /// shows the context menu (the `contextMenu` above wins that case).
    private func longPressDragGesture(item: DesktopItem, slot: IconSlot) -> some Gesture {
        LongPressGesture(minimumDuration: 0.28)
            .sequenced(before: DragGesture(minimumDistance: 6))
            .onChanged { value in
                switch value {
                case .first(true):
                    // The long press has fired — the finger is on an icon, so the
                    // pager must not page.
                    isIconPressing = true
                case .second(true, let drag?):
                    // The long press already happened — if we were not in edit
                    // mode, enter it now and start dragging this icon.
                    //
                    // NOTE the `drag?` — a sequenced gesture's `.second` case
                    // carries an OPTIONAL drag value (`Value2?`), so it must be
                    // unwrapped before `.translation` can be read.
                    if !store.editMode {
                        withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) {
                            store.editMode = true
                        }
                    }
                    guard store.editMode else { return }
                    draggingID = item.id
                    dragTranslation = drag.translation
                    updateTarget(for: item, slot: slot, translation: drag.translation)
                default:
                    break
                }
            }
            .onEnded { value in
                isIconPressing = false
                guard case .second(true, _) = value else { return }
                finishDrag(item: item, slot: slot)
            }
    }

    /// Per-icon jiggle: different phase and direction per slot so the page
    /// wobbles organically instead of in lockstep.
    private func jiggleAngle(seed: Int) -> Double {
        let dir: Double = (seed % 2 == 0) ? 1 : -1
        return dir * 1.2
    }

    private func dragGesture(item: DesktopItem, slot: IconSlot) -> some Gesture {
        DragGesture(minimumDistance: 7)
            .onChanged { v in
                guard store.editMode else { return }
                draggingID = item.id
                dragTranslation = v.translation
                updateTarget(for: item, slot: slot, translation: v.translation)
            }
            .onEnded { v in
                guard store.editMode else { return }
                finishDrag(item: item, slot: slot)
            }
    }

    /// Work out which cell the dragged icon currently hovers over.
    ///
    /// Uses the SAME origin + pitch the layout used, so the highlighted target
    /// is exactly the cell the icon will drop into. The old code recomputed a
    /// different geometry (icon artwork size instead of cell size) and mixed it
    /// with the page's mid-point — that is why icons landed in the wrong place
    /// and the highlight appeared offset from the finger.
    ///
    /// `gridOrigin` is the grid's top-left in the shared "root" space, which is
    /// the same space `dockFrame` uses — so the Dock hit test below is
    /// consistent with the grid hit test.
    private func updateTarget(for item: DesktopItem, slot: IconSlot, translation: CGSize) {
        // The dragged icon's centre in root coordinates.
        let cellCenterX = gridOrigin.x + CGFloat(slot.col) * gridPitch.width + gridPitch.width / 2
        let cellCenterY = gridOrigin.y + CGFloat(slot.row) * gridPitch.height + gridPitch.height / 2
        let point = CGPoint(x: cellCenterX + translation.width,
                            y: cellCenterY + translation.height)

        // Which cell is under it?
        var col = Int(((point.x - gridOrigin.x) / gridPitch.width).rounded(.down))
        var row = Int(((point.y - gridOrigin.y) / gridPitch.height).rounded(.down))
        col = max(0, min(columns - 1, col))
        row = max(0, min(rows - 1, row))

        // The Dock strip sits below the grid — dragging there means "pin to Dock".
        if dockFrame.contains(CGPoint(x: point.x, y: point.y)) {
            target = nil
            store.dockHighlighted = true
        } else {
            store.dockHighlighted = false
            target = IconSlot(page: slot.page, row: row, col: col)
        }
    }

    /// Commit a completed drag: pin to the Dock, drop into a folder, or place
    /// the icon in the highlighted cell.
    private func finishDrag(item: DesktopItem, slot: IconSlot) {
        defer {
            draggingID = nil
            dragTranslation = .zero
            target = nil
            store.dockHighlighted = false
        }
        if store.dockHighlighted {
            store.addToDock(item.id)
            return
        }
        guard let t = target, t != slot else { return }
        if let occupant = store.items(onPage: slot.page).first(where: { store.slot(for: $0.id) == t }) {
            if case .folder(let f) = occupant.kind {
                store.addToFolder(item.id, folderID: f.id)
            } else {
                store.createFolder(with: [occupant.id, item.id])
            }
        } else {
            store.place(item.id, at: t)
        }
    }

    private func iconMenu(_ item: DesktopItem) -> some View {
        Group {
            Button { open(item) } label: {
                Label("打开", systemImage: "arrow.up.right.square")
            }
            if store.isInDock(item.id) {
                Button { store.removeFromDock(item.id) } label: {
                    Label("从 Dock 移除", systemImage: "minus.square")
                }
            } else {
                Button { store.addToDock(item.id) } label: {
                    Label("添加到 Dock", systemImage: "plus.square.on.square")
                }
            }
            if item.isGuest {
                Button(role: .destructive) { delete(item) } label: {
                    Label("删除 App", systemImage: "trash")
                }
            }
            if case .folder(let f) = item.kind {
                Button {
                    renameTarget = f
                    renameText = f.name
                } label: {
                    Label("重命名", systemImage: "pencil")
                }
                Button(role: .destructive) { store.deleteFolder(f.id) } label: {
                    Label("解散文件夹", systemImage: "folder.badge.minus")
                }
            }
        }
    }

    private func folderMembers(for item: DesktopItem) -> [DesktopItem] {
        if case .folder(let f) = item.kind { return store.members(of: f) }
        return []
    }

    // MARK: Dock

    private var dockHeight: CGFloat { dockIconSize + (isIPad ? 44 : 36) }

    private func dock(_ geo: GeometryProxy) -> some View {
        VStack {
            Spacer()
            HStack(spacing: isIPad ? 24 : 16) {
                ForEach(store.dockItems) { item in
                    dockCell(item)
                }
            }
            .padding(.vertical, isIPad ? 12 : 10)
            .padding(.horizontal, isIPad ? 26 : 16)
            .background(dockBackground)
            .overlay(
                RoundedRectangle(cornerRadius: isIPad ? 30 : 24, style: .continuous)
                    .strokeBorder(store.dockHighlighted ? Color.accentColor : Color.white.opacity(0.20),
                                  lineWidth: store.dockHighlighted ? 2 : 0.5)
            )
            .shadow(color: .black.opacity(store.dockHighlighted ? 0.4 : 0.25),
                    radius: store.dockHighlighted ? 16 : 10, y: 4)
            .scaleEffect(store.dockHighlighted ? 1.04 : 1.0)
            .animation(.spring(response: 0.25, dampingFraction: 0.7), value: store.dockHighlighted)
            .padding(.horizontal, isIPad ? 28 : 10)
            .padding(.bottom, geo.safeAreaInsets.bottom + 52)
        }
        .background(
            GeometryReader { g in
                Color.clear.preference(key: DockFramePreferenceKey.self, value: g.frame(in: .named("root")))
            }
        )
        .onPreferenceChange(DockFramePreferenceKey.self) { dockFrame = $0 }
    }

    @ViewBuilder
    private var dockBackground: some View {
        if let img = theme.uiImage("DockBackground") {
            Image(uiImage: img)
                .resizable()
                .scaledToFill()
                .clipShape(RoundedRectangle(cornerRadius: isIPad ? 30 : 24, style: .continuous))
        } else {
            RoundedRectangle(cornerRadius: isIPad ? 30 : 24, style: .continuous)
                .fill(.ultraThinMaterial)
        }
    }

    private func dockCell(_ item: DesktopItem) -> some View {
        let badge = store.badge(for: item.id)
        return VStack(spacing: 4) {
            ZStack(alignment: .topTrailing) {
                IconArtwork(item: item,
                            size: dockIconSize,
                            folderMembers: folderMembers(for: item))
                if badge > 0 {
                    BadgeView(count: badge)
                        .offset(x: dockIconSize * 0.18, y: -dockIconSize * 0.12)
                }
            }
            Text(item.name)
                .font(.system(size: 10.5, weight: .medium))
                .foregroundStyle(.white)
                .lineLimit(1)
                .frame(width: dockIconSize + 10)
        }
        .contentShape(Rectangle())
        .onTapGesture { if !store.editMode { open(item) } }
        .contextMenu {
            Button { open(item) } label: {
                Label("打开", systemImage: "arrow.up.right.square")
            }
            if store.dockItems.count > 1 {
                Button { store.removeFromDock(item.id) } label: {
                    Label("从 Dock 移除", systemImage: "minus.circle")
                }
            }
        }
    }

    // MARK: Home key

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
            .onLongPressGesture(minimumDuration: 0.4) { showAppSwitcher = true }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)
        .padding(.bottom, geo.safeAreaInsets.bottom + 4)
    }

    private var editHint: some View {
        VStack {
            Spacer()
            Text("拖动重排 · 叠放建文件夹 · 拖到 Dock 固定")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.white.opacity(0.75))
                .padding(.horizontal, 14)
                .padding(.vertical, 7)
                .background(.ultraThinMaterial, in: Capsule())
                .padding(.bottom, dockHeight + 44)
            Spacer()
        }
        .allowsHitTesting(false)
    }

    private var toastView: some View {
        VStack {
            Spacer()
            Text(toast)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.white)
                .padding(.horizontal, 16)
                .padding(.vertical, 9)
                .background(.regularMaterial, in: Capsule())
                .padding(.bottom, dockHeight + 60)
            Spacer()
        }
        .allowsHitTesting(false)
        .transition(.opacity)
    }

    // MARK: Actions

    private func open(_ item: DesktopItem) {
        guard !store.editMode else { return }
        SpringBoardController.shared.recordOpen(item.id)
        withAnimation(.spring(response: 0.38, dampingFraction: 0.82)) { activeApp = item }
    }

    private func closeActiveApp() {
        withAnimation(.spring(response: 0.32, dampingFraction: 0.85)) { activeApp = nil }
    }

    private func goHome() {
        closeActiveApp()
        withAnimation { store.editMode = false }
        showControlCenter = false
        showAppSwitcher = false
        showNotificationCenter = false
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
                store.slots.removeValue(forKey: item.id)
            case .folder(let f):
                store.deleteFolder(f.id)
            case .builtin:
                break
            }
        }
    }

    // MARK: 注销（respring / 资源库）

    /// "注销 SpringBoard": tear the shell down and bring it back up the way a
    /// real respring does — spinner, re-read the theme, re-place every icon,
    /// drop back to the lock screen. The process never exits.
    private func respring() {
        respringing = true
        closeActiveApp()
        store.editMode = false
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
            theme.reload()
            store.pruneSlots()
            store.ensurePlaced(isIPad: isIPad)
            page = 0
            respringing = false
            locked = true
        }
    }

    /// "注销资源库": rescan `/Library/Themes` and drop every cached image so
    /// newly installed or edited themes take effect without a full respring.
    private func reloadLibrary() {
        let count = theme.reload()
        store.pruneSlots()
        store.ensurePlaced(isIPad: isIPad)
        toast = count == 0 ? "资源库已刷新（/Library/Themes 为空）" : "资源库已刷新：\(count) 个主题"
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            withAnimation { toast = "" }
        }
    }
}

// MARK: - Preference keys (desktop / dock frames in the shared "root" space)

struct DockFramePreferenceKey: PreferenceKey {
    static var defaultValue: CGRect = .zero
    static func reduce(value: inout CGRect, nextValue: () -> CGRect) { value = nextValue() }
}

/// The home-screen grid's geometry, published by `pageView` so the drag
/// gesture can convert a finger position into a target cell with the very
/// same numbers the layout used.
struct GridMetrics: Equatable {
    var origin: CGPoint
    var pitch: CGSize
    var cell: CGSize
}

struct PageFramePreferenceKey: PreferenceKey {
    static var defaultValue: GridMetrics = GridMetrics(origin: .zero,
                                                        pitch: .zero,
                                                        cell: .zero)
    static func reduce(value: inout GridMetrics, nextValue: () -> GridMetrics) {
        value = nextValue()
    }
}

/// The page's origin in the shared "root" space.
struct PageOriginPreferenceKey: PreferenceKey {
    static var defaultValue: CGPoint = .zero
    static func reduce(value: inout CGPoint, nextValue: () -> CGPoint) {
        value = nextValue()
    }
}
