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
    /// The icon whose long-press menu is open, plus that icon's frame in the
    /// shared "root" space (so the menu can be anchored to it). Long-pressing
    /// an icon WITHOUT dragging shows this; long-pressing and THEN dragging
    /// enters edit mode instead. Both used to fight each other through
    /// `contextMenu` + two drag gestures on the same cell.
    @State private var menuItem: DesktopItem?
    @State private var menuFrame: CGRect = .zero
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
    ///
    /// `store.pageCount` is the number of HOME pages; the App Library is the
    /// page right after them. The old code rendered `ForEach(0..<pageCount)`
    /// over this combined count, which produced one EXTRA home page (an empty
    /// ghost) sitting exactly underneath the App Library — the library looked
    /// blank/unreachable and the extra page dots were wrong.
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
                if menuItem != nil {
                    iconMenuOverlay(geo.size).zIndex(6)
                }
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
                // Home pages ONLY: 0..<store.pageCount. The App Library is the
                // last page and is placed separately below, so there is exactly
                // one view per page index and no ghost page overlapping it.
                ForEach(0..<store.pageCount, id: \.self) { i in
                    pageView(i)
                        .frame(width: w, height: geo.size.height)
                        .offset(x: -CGFloat(page) * w + pageDragOffset)
                }
                AppLibraryView { item in open(item) }
                    .frame(width: w, height: geo.size.height)
                    .offset(x: -CGFloat(store.pageCount) * w + pageDragOffset)
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
            // The grid's geometry: page-local origin + pitch. The page's own
            // ROOT-space origin is NOT published here — see below.
            .onPreferenceChange(PageFramePreferenceKey.self) { metrics in
                gridPitch = metrics.pitch
                gridCell = metrics.cell
                gridLocalOrigin = metrics.origin
                updateGridOrigin()
            }
            // The PAGER's own frame in root space. This view never moves, so
            // the value is stable.
            //
            // It used to publish each PAGE's frame instead — but a page's frame
            // changes on every touch-move of the swipe (that is the whole point
            // of the offset), so each frame of the drag fed a preference change
            // back into @State, which re-rendered the pager, which moved the
            // pages, which published a new frame… an endless feedback loop.
            // That loop is the "滑动页面闪动" report.
            //
            // The current page sits exactly at the pager's origin whenever
            // `pageDragOffset == 0`, and the pager gesture forces that to 0
            // while an icon is being pressed — which is the only time the grid
            // origin is needed (for the drag-and-drop hit test).
            .background(
                GeometryReader { g in
                    Color.clear.preference(key: PagerFramePreferenceKey.self,
                                           value: g.frame(in: .named("root")).origin)
                }
            )
            .onPreferenceChange(PagerFramePreferenceKey.self) { origin in
                gridPageOrigin = origin
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
                guard abs(v.translation.width) > abs(v.translation.height) * 1.4 else {
                    // Snap the page back — animated, or it visibly jumps.
                    withAnimation(.easeInOut(duration: 0.22)) { pageDragOffset = 0 }
                    return
                }
                let threshold = pageWidth * 0.22
                var next = page
                if v.translation.width < -threshold {
                    next = page + 1
                } else if v.translation.width > threshold {
                    next = page - 1
                }
                let clamped = max(0, min(pageCount - 1, next))
                // The total offset of page i is `-page*w + pageDragOffset`. If
                // `page` is animated to its new value while `pageDragOffset`
                // snaps to 0 outside the animation, the rendered position jumps
                // BACKWARDS by the drag distance first and only then glides
                // forward — a visible flash at the end of every swipe. Both
                // must be driven by the same transaction.
                withAnimation(.easeInOut(duration: 0.28)) {
                    page = clamped
                    pageDragOffset = 0
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
                //
                // This reports the grid's PAGE-LOCAL origin — a constant that
                // does not depend on where the page currently sits. The page's
                // own position comes from the pager's (stable) frame, so
                // nothing in here changes while a swipe is in flight.
                GeometryReader { _ in
                    Color.clear.preference(key: PageFramePreferenceKey.self,
                                           value: GridMetrics(origin: CGPoint(x: originX, y: originY),
                                                              pitch: CGSize(width: colPitch, height: rowPitch),
                                                              cell: CGSize(width: cellWidth, height: cellHeight)))
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
        // ONE gesture on the cell. The old stack was four competing systems —
        // `.onTapGesture` + `.contextMenu` + a sequenced long-press/drag + a
        // second, independent drag gesture — which is exactly why taps were
        // unreliable ("应用概率点不动") and why a plain long press sometimes
        // entered edit mode instead of opening the menu.
        //
        // Behaviour now, mirroring iOS:
        //   * tap                            → open
        //   * long press, no drag            → icon menu (drawn by RyBox)
        //   * long press, then drag ≥ 16 pt  → edit mode + move the icon
        .simultaneousGesture(iconGesture(item: item, slot: slot))
    }

    /// The single gesture attached to an icon cell.
    ///
    /// A `LongPressGesture` sequenced with a `DragGesture`:
    ///   * the long press must hold 0.3 s before anything else happens,
    ///   * lifting the finger at that point opens the icon menu,
    ///   * only a subsequent movement of ≥ 16 pt starts a drag (and turns edit
    ///     mode on).
    ///
    /// The 16 pt threshold matters. `DragGesture` inside a sequenced pair
    /// measures its translation from the START of the touch, so by the time the
    /// long press fires the accumulated movement is whatever the finger drifted
    /// while holding. At 6 pt that drift alone was enough to start a drag —
    /// a resting hand moves 2–5 pt — which is why long-pressing an icon went
    /// straight to edit mode. 16 pt is beyond resting drift but still a
    /// comfortable deliberate drag.
    private func iconGesture(item: DesktopItem, slot: IconSlot) -> some Gesture {
        LongPressGesture(minimumDuration: 0.3)
            .sequenced(before: DragGesture(minimumDistance: 16))
            .onChanged { value in
                switch value {
                case .first(true):
                    // The long press has fired — the finger is on an icon, so the
                    // pager must not page.
                    isIconPressing = true
                    longPressFired = true
                case .second(true, let drag?):
                    // The long press already happened and a real drag started.
                    // NOTE the `drag?` — a sequenced gesture's `.second` case
                    // carries an OPTIONAL drag value (`Value2?`), so it must be
                    // unwrapped before `.translation` can be read.
                    longPressFired = false
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
            .onEnded { _ in
                isIconPressing = false
                if longPressFired {
                    // Long press held, no drag followed → the menu.
                    longPressFired = false
                    showMenu(for: item, slot: slot)
                } else {
                    finishDrag(item: item, slot: slot)
                }
            }
    }

    // MARK: Icon menu

    /// Open the long-press menu for an icon, anchored to that icon's cell.
    private func showMenu(for item: DesktopItem, slot: IconSlot) {
        menuFrame = cellFrame(slot)
        menuItem = item
        if store.editMode {
            withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) { store.editMode = false }
        }
    }

    /// The icon's frame in the shared "root" space, derived from the very same
    /// origin + pitch the layout used — so the menu points at the right icon.
    private func cellFrame(_ slot: IconSlot) -> CGRect {
        CGRect(x: gridOrigin.x + CGFloat(slot.col) * gridPitch.width,
               y: gridOrigin.y + CGFloat(slot.row) * gridPitch.height,
               width: gridCell.width, height: gridCell.height)
    }

    private func closeMenu() {
        withAnimation(.easeOut(duration: 0.15)) { menuItem = nil }
    }

    /// The long-press menu, drawn by RyBox rather than SwiftUI's `contextMenu`.
    ///
    /// `contextMenu` ships its own long-press recogniser; stacking that on top
    /// of the long-press-and-drag gesture on the same cell made the two fight,
    /// so the menu sometimes never appeared and a plain long press sometimes
    /// started a drag. The gesture now decides what a long press means and this
    /// view is only the result — no recogniser ambiguity left.
    @ViewBuilder
    private func iconMenuOverlay(_ bounds: CGSize) -> some View {
        if let item = menuItem {
            IconContextMenu(
                item: item,
                anchor: menuFrame,
                bounds: bounds,
                actions: menuActions(for: item),
                onDismiss: { closeMenu() },
                onAction: { action in
                    closeMenu()
                    handleMenuAction(action, for: item)
                }
            )
            .transition(.opacity)
        }
    }

    private func handleMenuAction(_ action: MenuAction, for item: DesktopItem) {
        switch action {
        case .open:
            open(item)
        case .addToDock:
            store.addToDock(item.id)
        case .removeFromDock:
            store.removeFromDock(item.id)
        case .rename:
            if case .folder(let f) = item.kind {
                renameTarget = f
                renameText = f.name
            }
        case .dissolve:
            if case .folder(let f) = item.kind { store.deleteFolder(f.id) }
        case .delete:
            delete(item)
        }
    }

    /// True once the icon long press has fired but before any drag began.
    /// Used in `onEnded` to tell "long press then lift" (→ menu) from "long
    /// press then drag" (→ move), without depending on which enum case the
    /// sequenced gesture happens to deliver on cancellation.
    @State private var longPressFired = false

    /// Per-icon jiggle: different phase and direction per slot so the page
    /// wobbles organically instead of in lockstep.
    private func jiggleAngle(seed: Int) -> Double {
        let dir: Double = (seed % 2 == 0) ? 1 : -1
        return dir * 1.2
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

    private func folderMembers(for item: DesktopItem) -> [DesktopItem] {
        if case .folder(let f) = item.kind { return store.members(of: f) }
        return []
    }

    /// The actions offered in the long-press menu, in display order.
    private func menuActions(for item: DesktopItem) -> [MenuAction] {
        var out: [MenuAction] = [.open]
        out.append(store.isInDock(item.id) ? .removeFromDock : .addToDock)
        if case .folder = item.kind {
            out.append(.rename)
            out.append(.dissolve)
        }
        if item.isGuest { out.append(.delete) }
        return out
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

/// The PAGER's origin in the shared "root" space. Published by the pager, which
/// never moves — so the value is stable and cannot feed back into the layout.
/// (The previous `PageOriginPreferenceKey` published each PAGE's origin, which
/// changes on every touch-move of a swipe and produced a render feedback loop
/// that made paging flicker. It is gone; use `PagerFramePreferenceKey`.)
struct PagerFramePreferenceKey: PreferenceKey {
    static var defaultValue: CGPoint = .zero
    static func reduce(value: inout CGPoint, nextValue: () -> CGPoint) {
        value = nextValue()
    }
}

// MARK: - Long-press menu

/// One row of the icon long-press menu.
enum MenuAction {
    case open
    case addToDock
    case removeFromDock
    case rename
    case dissolve
    case delete

    var title: String {
        switch self {
        case .open:          return "打开"
        case .addToDock:     return "添加到 Dock"
        case .removeFromDock:return "从 Dock 移除"
        case .rename:        return "重命名"
        case .dissolve:      return "解散文件夹"
        case .delete:        return "删除 App"
        }
    }

    var symbol: String {
        switch self {
        case .open:          return "arrow.up.right.square"
        case .addToDock:     return "plus.square.on.square"
        case .removeFromDock:return "minus.square"
        case .rename:        return "pencil"
        case .dissolve:      return "folder.badge.minus"
        case .delete:        return "trash"
        }
    }

    var isDestructive: Bool {
        // A switch rather than `==`: `MenuAction` has no associated values but
        // does not declare Equatable, and a bare `self == .delete` would not
        // compile.
        switch self {
        case .delete, .dissolve: return true
        default:                 return false
        }
    }
}

/// The icon long-press menu: a frosted card anchored to the icon it belongs to.
///
/// Anchored rather than centred (the old `.contextMenu` had no useful position
/// at all on iPad), and clamped inside the screen so it can never be opened
/// off the top edge.
private struct IconContextMenu: View {
    let item: DesktopItem
    /// The icon's frame in the shared "root" space.
    let anchor: CGRect
    /// The host's size, used to clamp the card on screen.
    let bounds: CGSize
    let actions: [MenuAction]
    var onDismiss: () -> Void
    var onAction: (MenuAction) -> Void

    private let rowHeight: CGFloat = 46
    private let cardWidth: CGFloat = 216
    private let cardPadding: CGFloat = 8

    private var cardHeight: CGFloat {
        CGFloat(actions.count) * rowHeight + cardPadding * 2 + 50   // + header
    }

    var body: some View {
        ZStack(alignment: .topLeading) {
            // Tap anywhere outside the card to dismiss.
            Color.black.opacity(0.001)
                .ignoresSafeArea()
                .onTapGesture { onDismiss() }

            VStack(spacing: 0) {
                // Header: the app's own artwork + name, so the menu is
                // unambiguous when two icons look alike.
                HStack(spacing: 10) {
                    IconArtwork(item: item, size: 34, cornerRadius: 8)
                    Text(item.name)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(.white.opacity(0.92))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(.horizontal, 14)
                .padding(.bottom, 8)

                // `id: \.offset` on an enumerated array would need a key path
                // into a tuple element, which Swift does not allow — index the
                // array instead.
                ForEach(actions.indices, id: \.self) { index in
                    let action = actions[index]
                    if index > 0 {
                        Divider()
                            .overlay(Color.white.opacity(0.14))
                            .padding(.horizontal, 10)
                    }
                    Button {
                        onAction(action)
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: action.symbol)
                                .font(.system(size: 14, weight: .semibold))
                                .frame(width: 20)
                            Text(action.title)
                                .font(.system(size: 15, weight: .medium))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .foregroundStyle(action.isDestructive
                                         ? Color(red: 1.0, green: 0.45, blue: 0.47)
                                         : Color.white)
                        .padding(.horizontal, 14)
                        .frame(height: rowHeight)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.vertical, cardPadding)
            .frame(width: cardWidth)
            .background(.regularMaterial,
                        in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.22), lineWidth: 0.6)
            )
            .shadow(color: .black.opacity(0.34), radius: 18, y: 8)
            .position(x: cardX, y: cardY)
        }
    }

    /// Horizontal centre of the icon, clamped so the whole card stays on screen.
    private var cardX: CGFloat {
        let raw = anchor.midX
        let half = cardWidth / 2
        return min(max(raw, half + 10), bounds.width - half - 10)
    }

    /// Prefer ABOVE the icon (that is where a thumb is not), fall back below.
    private var cardY: CGFloat {
        let above = anchor.minY - cardHeight - 12
        if above > 60 { return above + cardHeight / 2 }
        return anchor.maxY + 12 + cardHeight / 2
    }
}
