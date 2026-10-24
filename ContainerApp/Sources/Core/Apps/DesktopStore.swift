import Foundation
import SwiftUI
import Combine

/// Built-in RyBox apps. Sileo is PREINSTALLED (shows on the desktop + dock by
/// default), matching a jailbroken-device home screen.
enum BuiltinApp: String, CaseIterable, Codable {
    case sileo, settings, files, terminal, `import`, logs
}

extension BuiltinApp {
    /// Stable id used for layout persistence: "builtin.sileo" etc.
    var id: String { "builtin." + rawValue }

    var title: String {
        switch self {
        case .sileo: return "Sileo"
        case .settings: return "设置"
        case .files: return "文件"
        case .terminal: return "终端"
        case .import: return "导入"
        case .logs: return "日志"
        }
    }

    var symbol: String {
        switch self {
        case .sileo: return "shippingbox.fill"
        case .settings: return "gearshape.fill"
        case .files: return "folder.fill"
        case .terminal: return "terminal.fill"
        case .import: return "square.and.arrow.down.fill"
        case .logs: return "text.alignleft"
        }
    }

    var tint: Color {
        switch self {
        case .sileo: return Color(red: 0.90, green: 0.20, blue: 0.38)     // Sileo red
        case .settings: return Color(red: 0.40, green: 0.43, blue: 0.49)  // iOS settings gray
        case .files: return Color(red: 0.20, green: 0.55, blue: 0.95)     // Files blue
        case .terminal: return Color(red: 0.14, green: 0.15, blue: 0.18)  // near-black
        case .import: return Color(red: 0.30, green: 0.72, blue: 0.45)    // green
        case .logs: return Color(red: 0.20, green: 0.62, blue: 0.86)     // terminal blue
        }
    }

    /// App Library category (see `LibraryCategory`).
    var category: LibraryCategory {
        switch self {
        case .sileo: return .packages
        case .settings: return .system
        case .files: return .utilities
        case .terminal: return .developer
        case .import: return .utilities
        case .logs: return .developer
        }
    }
}

/// App Library groupings. Real iOS derives these from App Store genres; we can
/// only guess from the bundle id / name, so `other` is the honest fallback.
enum LibraryCategory: String, CaseIterable, Identifiable {
    case recentlyAdded
    case packages
    case developer
    case utilities
    case entertainment
    case social
    case system
    case other

    var id: String { rawValue }

    var title: String {
        switch self {
        case .recentlyAdded: return "最近添加"
        case .packages: return "包管理"
        case .developer: return "开发者"
        case .utilities: return "工具"
        case .entertainment: return "娱乐"
        case .social: return "社交"
        case .system: return "系统"
        case .other: return "其他"
        }
    }

    var symbol: String {
        switch self {
        case .recentlyAdded: return "clock.fill"
        case .packages: return "shippingbox.fill"
        case .developer: return "chevron.left.forwardslash.chevron.right"
        case .utilities: return "wrench.and.screwdriver.fill"
        case .entertainment: return "gamecontroller.fill"
        case .social: return "bubble.left.and.bubble.right.fill"
        case .system: return "gearshape.fill"
        case .other: return "square.grid.3x3.fill"
        }
    }
}

/// One App Library group. A struct rather than a tuple because Swift has no
/// key paths into tuple elements, and the library grid needs to be
/// `ForEach`-able.
struct LibraryBucket: Identifiable {
    let category: LibraryCategory
    let items: [DesktopItem]

    var id: String { category.rawValue }
}

/// A desktop folder (created by dragging one icon on top of another).
struct RyFolder: Identifiable, Hashable, Codable {
    let id: String
    var name: String
    var memberIDs: [String]

    init(id: String = UUID().uuidString, name: String, memberIDs: [String]) {
        self.id = id
        self.name = name
        self.memberIDs = memberIDs
    }
}

/// Where an icon sits: a real SpringBoard grid slot, not a free-floating point.
/// Pages are what let us render the paged home screen and the page dots.
struct IconSlot: Hashable, Codable {
    var page: Int
    var row: Int
    var col: Int
}

/// One item on the RyBox desktop / dock: a builtin app, an imported guest, or
/// a folder. The id is STABLE across launches (String.hashValue is randomly
/// seeded, so guest colors use an FNV-1a hash instead).
struct DesktopItem: Identifiable, Hashable {
    let id: String
    let name: String
    let kind: Kind

    enum Kind: Hashable {
        case builtin(BuiltinApp)
        case guest(ImportedApp)
        case folder(RyFolder)
    }

    var symbol: String {
        switch kind {
        case .builtin(let b): return b.symbol
        case .guest: return "app.fill"
        case .folder: return "folder.fill"
        }
    }

    var tint: Color {
        switch kind {
        case .builtin(let b): return b.tint
        case .guest(let a): return Self.color(for: a.bundleIdentifier)
        case .folder(let f): return Self.color(for: f.id)
        }
    }

    /// Bundle id used for theme icon lookups (`IconBundles/<bid>.png`).
    var bundleIdentifier: String? {
        switch kind {
        case .builtin(let b): return "com.rybox.\(b.rawValue)"
        case .guest(let a): return a.bundleIdentifier
        case .folder: return nil
        }
    }

    var isGuest: Bool {
        if case .guest = kind { return true } else { return false }
    }

    /// Guests and folders can be deleted; built-ins cannot.
    var isDeletable: Bool {
        if case .guest = kind { return true }
        if case .folder = kind { return true }
        return false
    }

    /// Deterministic per-key icon color (FNV-1a — stable across launches).
    static func color(for key: String) -> Color {
        var h: UInt64 = 1469598103934665603
        for b in key.utf8 { h ^= UInt64(b); h &*= 1099511628211 }
        return Color(hue: Double(h % 360) / 360.0, saturation: 0.62, brightness: 0.86)
    }
}

/// Persisted desktop state: grid slots, dock membership/order, folders, icon
/// scale, badges. Slots survive restarts and are what makes the home screen
/// page properly instead of being one long scrolling strip.
final class DesktopStore: ObservableObject {
    static let shared = DesktopStore()
    private let defaults = UserDefaults.standard

    private enum Key {
        static let dock = "rybox.dock.ids"
        static let slots = "rybox.desktop.slots"
        static let iconScale = "rybox.desktop.iconScale"
        static let folders = "rybox.desktop.folders"
        static let badges = "rybox.desktop.badges"
    }

    /// Ordered dock membership (item ids).
    @Published var dockIDs: [String] {
        didSet { defaults.set(dockIDs, forKey: Key.dock) }
    }
    /// Grid slot per item id. Persisted.
    @Published var slots: [String: IconSlot] {
        didSet { saveSlots() }
    }
    /// Desktop folders. Persisted.
    @Published var folders: [RyFolder] {
        didSet { saveFolders() }
    }
    /// Notification badges (item id -> count). Persisted.
    @Published var badges: [String: Int] {
        didSet { saveBadges() }
    }
    /// Global icon scale (0.8 – 1.3), editable in Settings.
    @Published var iconScale: Double {
        didSet { defaults.set(iconScale, forKey: Key.iconScale) }
    }
    /// True while the user rearranges the desktop (jiggle mode).
    @Published var editMode = false
    /// True while an icon is dragged over the dock (drop-target feedback).
    @Published var dockHighlighted = false

    private init() {
        dockIDs = defaults.stringArray(forKey: Key.dock) ?? BuiltinApp.allCases.map(\.id)
        iconScale = defaults.object(forKey: Key.iconScale) as? Double ?? 1.0
        slots = Self.loadSlots()
        folders = Self.loadFolders()
        badges = (defaults.dictionary(forKey: Key.badges) as? [String: Int]) ?? [:]

        // Imported guests change AFTER this store is built: a fresh import
        // (ImportView) and the bootstrap re-scan on relaunch (AppImporter.bootstrap)
        // both repopulate `importedApps` asynchronously. When that happens we must
        // (a) give every guest a desktop slot so it actually shows on the grid,
        // (b) drop stale slots for uninstalled guests, and (c) re-publish so the
        // SpringBoard re-renders. Without this, a restored guest has no slot —
        // `items(onPage:)` filters by slot — and silently vanishes on relaunch,
        // which is exactly the "重新进入软件后已经导入的ipa丢失" bug.
        AppImporter.shared.$importedApps
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self = self else { return }
                self.ensurePlaced(isIPad: UIDevice.current.userInterfaceIdiom == .pad)
                self.pruneSlots()
                self.objectWillChange.send()
            }
            .store(in: &cancellables)
    }

    /// Combine bag for the `importedApps` subscription above.
    private var cancellables = Set<AnyCancellable>()

    // MARK: Item lists

    var builtinItems: [DesktopItem] {
        BuiltinApp.allCases.map { DesktopItem(id: $0.id, name: $0.title, kind: .builtin($0)) }
    }

    var guestItems: [DesktopItem] {
        AppImporter.shared.importedApps.map {
            DesktopItem(id: "guest.\($0.bundleIdentifier)", name: $0.name, kind: .guest($0))
        }
    }

    var folderItems: [DesktopItem] {
        folders.map { DesktopItem(id: "folder.\($0.id)", name: $0.name, kind: .folder($0)) }
    }

    /// Ids that live inside a folder (not shown loose on the desktop).
    var foldedIDs: Set<String> {
        Set(folders.flatMap(\.memberIDs))
    }

    /// Everything shown loose on the desktop: builtins + guests + folders.
    /// The Sileo stub disappears once the REAL preinstalled Sileo is installed.
    var allItems: [DesktopItem] {
        let builtins = realSileoInstalled
            ? builtinItems.filter { $0.id != BuiltinApp.sileo.id }
            : builtinItems
        let looseGuests = guestItems.filter { !foldedIDs.contains($0.id) }
        return builtins + looseGuests + folderItems
    }

    /// True when the real preinstalled Sileo guest is registered.
    var realSileoInstalled: Bool {
        AppImporter.shared.importedApps.contains { $0.bundleIdentifier == PreinstalledStore.sileoBundleID }
    }

    /// Dock contents, in order. Unknown ids and folded items are skipped.
    var dockItems: [DesktopItem] {
        dockIDs.compactMap { item(id: $0) }
    }

    func item(id: String) -> DesktopItem? {
        // The Sileo slot (stub or dock) resolves to the REAL Sileo once installed.
        if id == BuiltinApp.sileo.id, realSileoInstalled,
           let guest = guestItems.first(where: { $0.id == "guest.\(PreinstalledStore.sileoBundleID)" }) {
            return guest
        }
        // Anything living inside a folder is not shown loose on desktop/dock.
        guard !foldedIDs.contains(id) else { return nil }
        return resolve(id: id)
    }

    /// Resolve an id REGARDLESS of folder membership. Folder contents need
    /// this: their member ids are in `foldedIDs`, so `item(id:)` would hide them
    /// and every folder would look empty.
    func resolve(id: String) -> DesktopItem? {
        if id.hasPrefix("folder.") {
            let fid = String(id.dropFirst(7))
            if let f = folders.first(where: { $0.id == fid }) {
                return DesktopItem(id: id, name: f.name, kind: .folder(f))
            }
            return nil
        }
        if id.hasPrefix("builtin."), let b = BuiltinApp(rawValue: String(id.dropFirst(8))) {
            return DesktopItem(id: b.id, name: b.title, kind: .builtin(b))
        }
        if id.hasPrefix("guest.") {
            let bid = String(id.dropFirst(6))
            if let app = AppImporter.shared.importedApps.first(where: { $0.bundleIdentifier == bid }) {
                return DesktopItem(id: id, name: app.name, kind: .guest(app))
            }
        }
        return nil
    }

    /// Members of a folder as desktop items (skips uninstalled guests).
    func members(of folder: RyFolder) -> [DesktopItem] {
        folder.memberIDs.compactMap { resolve(id: $0) }
    }

    // MARK: Badges

    func badge(for id: String) -> Int {
        guard let v = badges[id], v > 0 else { return 0 }
        return v
    }

    func setBadge(_ count: Int, for id: String) {
        if count <= 0 { badges.removeValue(forKey: id) } else { badges[id] = count }
    }

    // MARK: Dock customization

    func isInDock(_ id: String) -> Bool { dockIDs.contains(id) }

    @discardableResult
    func addToDock(_ id: String) -> Bool {
        guard !dockIDs.contains(id), item(id: id) != nil else { return false }
        dockIDs.append(id)
        return true
    }

    func removeFromDock(_ id: String) {
        dockIDs.removeAll { $0 == id }
    }

    func moveDock(from offsets: IndexSet, to destination: Int) {
        dockIDs.move(fromOffsets: offsets, toOffset: destination)
    }

    // MARK: Folders

    func folder(containing itemID: String) -> RyFolder? {
        folders.first { $0.memberIDs.contains(itemID) }
    }

    /// Create a folder from two (or more) item ids. Members leave the dock and
    /// lose their desktop slot.
    @discardableResult
    func createFolder(with ids: [String], name: String? = nil) -> RyFolder {
        let members = ids.filter { item(id: $0) != nil }
        let folder = RyFolder(name: name ?? "文件夹", memberIDs: members)
        folders.append(folder)
        for m in members {
            removeFromDock(m)
            slots.removeValue(forKey: m)
        }
        reflow()
        RyLog.shared.log("建立文件夹「\(folder.name)」· 成员 \(members.count) 个", level: .info, tag: "ui")
        return folder
    }

    /// Add an item to an existing folder.
    func addToFolder(_ itemID: String, folderID: String) {
        guard var f = folders.first(where: { $0.id == folderID }),
              !f.memberIDs.contains(itemID), item(id: itemID) != nil else { return }
        f.memberIDs.append(itemID)
        folders = folders.map { $0.id == folderID ? f : $0 }
        removeFromDock(itemID)
        slots.removeValue(forKey: itemID)
        reflow()
    }

    /// Remove an item from its folder (it flows back to the desktop).
    func removeFromFolder(_ itemID: String) {
        folders = folders.map { f in
            guard f.memberIDs.contains(itemID) else { return f }
            var nf = f
            nf.memberIDs.removeAll { $0 == itemID }
            return nf
        }
        slots.removeValue(forKey: itemID)
        reflow()
    }

    func renameFolder(_ folderID: String, to name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        folders = folders.map { $0.id == folderID ? RyFolder(id: $0.id, name: trimmed, memberIDs: $0.memberIDs) : $0 }
    }

    /// Dissolve a folder: members return to the desktop grid.
    func deleteFolder(_ folderID: String) {
        guard let f = folders.first(where: { $0.id == folderID }) else { return }
        for m in f.memberIDs { slots.removeValue(forKey: m) }
        folders.removeAll { $0.id == folderID }
        reflow()
    }

    /// Re-assign slots to any unplaced item, drop stale slots, and force a
    /// re-render. `items(onPage:)` only renders items that HAVE a slot, so any
    /// mutation that introduces a new desktop item (a folder) or frees one back
    /// to the grid (leaving/dissolving a folder) must re-place — otherwise the
    /// change stays invisible until the next respring. This is the fix for
    /// "建立文件夹 / 从文件夹移除 App 必须注销 SpringBoard 才显示".
    private func reflow() {
        ensurePlaced(isIPad: UIDevice.current.userInterfaceIdiom == .pad)
        pruneSlots()
        objectWillChange.send()
    }

    // MARK: Grid layout

    /// Home-screen grid dimensions. iPadOS uses 6×5, iPhone 4×6 — matching the
    /// real thing keeps icon spacing and paging visually faithful.
    static func columns(isIPad: Bool) -> Int { isIPad ? 6 : 4 }
    static func rows(isIPad: Bool) -> Int { isIPad ? 5 : 6 }

    /// Number of home-screen pages in use (never fewer than 1).
    var pageCount: Int {
        let maxPage = slots.values.map(\.page).max() ?? 0
        return max(maxPage + 1, 1)
    }

    func slot(for id: String) -> IconSlot? { slots[id] }

    /// Items rendered on one page (unplaced items are auto-assigned on demand).
    func items(onPage page: Int) -> [DesktopItem] {
        allItems.filter { (slots[$0.id]?.page ?? 0) == page }
    }

    /// Assign a slot, clearing any item already sitting there.
    func place(_ id: String, at slot: IconSlot) {
        if let occupant = slots.first(where: { $0.value == slot && $0.key != id })?.key {
            // Swap: the displaced icon takes the dragged icon's old spot.
            if let previous = slots[id] {
                slots[occupant] = previous
            } else {
                slots.removeValue(forKey: occupant)
            }
        }
        slots[id] = slot
    }

    /// First free slot on the grid, scanning page by page. Used for anything
    /// that has not been placed yet (newly imported apps, first launch).
    func firstFreeSlot(isIPad: Bool) -> IconSlot {
        let cols = Self.columns(isIPad: isIPad)
        let rows = Self.rows(isIPad: isIPad)
        var page = 0
        while page < pageCount + 1 {
            for row in 0..<rows {
                for col in 0..<cols {
                    let candidate = IconSlot(page: page, row: row, col: col)
                    if !slots.values.contains(candidate) { return candidate }
                }
            }
            page += 1
        }
        return IconSlot(page: page, row: 0, col: 0)
    }

    /// Ensure every loose item has a slot (called before rendering a page).
    func ensurePlaced(isIPad: Bool) {
        var changed = false
        for item in allItems where slots[item.id] == nil {
            slots[item.id] = firstFreeSlot(isIPad: isIPad)
            changed = true
        }
        if changed { saveSlots() }
    }

    /// Drop stale slots for apps/folders that no longer exist.
    func pruneSlots() {
        let live = Set(allItems.map(\.id))
        let stale = slots.keys.filter { !live.contains($0) }
        guard !stale.isEmpty else { return }
        for k in stale { slots.removeValue(forKey: k) }
    }

    func resetLayout() {
        slots = [:]
        folders = []
        dockIDs = BuiltinApp.allCases.map(\.id)
        iconScale = 1.0
        badges = [:]
        reflow()
    }

    // MARK: App Library

    /// App Library buckets, in display order. Anything empty is dropped.
    func libraryBuckets() -> [LibraryBucket] {
        var map: [LibraryCategory: [DesktopItem]] = [:]
        for item in allItems {
            map[Self.category(of: item), default: []].append(item)
        }
        // "最近添加" mirrors the last few installed guests.
        let recent = Array(guestItems.suffix(4))
        if !recent.isEmpty { map[.recentlyAdded] = recent }
        return LibraryCategory.allCases.compactMap { cat in
            guard let items = map[cat], !items.isEmpty else { return nil }
            return LibraryBucket(category: cat, items: items)
        }
    }

    /// Best-effort categorisation. Guests are guessed from their bundle id and
    /// display name; the fallback is honest rather than clever.
    static func category(of item: DesktopItem) -> LibraryCategory {
        switch item.kind {
        case .builtin(let b): return b.category
        case .folder: return .other
        case .guest(let app):
            let hay = (app.bundleIdentifier + " " + app.name).lowercased()
            if hay.contains("sileo") || hay.contains("cydia") || hay.contains("zebra") || hay.contains("installer") {
                return .packages
            }
            if hay.contains("terminal") || hay.contains("shell") || hay.contains("ssh")
                || hay.contains("debug") || hay.contains("dev") {
                return .developer
            }
            if hay.contains("file") || hay.contains("file") || hay.contains("zip")
                || hay.contains("util") || hay.contains("tool") {
                return .utilities
            }
            if hay.contains("game") || hay.contains("play") || hay.contains("video")
                || hay.contains("music") || hay.contains("tube") {
                return .entertainment
            }
            if hay.contains("chat") || hay.contains("social") || hay.contains("message")
                || hay.contains("weibo") || hay.contains("twitter") {
                return .social
            }
            return .other
        }
    }

    // MARK: Persistence

    private func saveSlots() {
        var dict: [String: [Int]] = [:]
        for (k, v) in slots { dict[k] = [v.page, v.row, v.col] }
        defaults.set(dict, forKey: Key.slots)
    }

    private static func loadSlots() -> [String: IconSlot] {
        guard let dict = UserDefaults.standard.dictionary(forKey: Key.slots) as? [String: [Int]] else { return [:] }
        var out: [String: IconSlot] = [:]
        for (k, v) in dict where v.count == 3 {
            out[k] = IconSlot(page: v[0], row: v[1], col: v[2])
        }
        return out
    }

    private func saveBadges() { defaults.set(badges, forKey: Key.badges) }

    private func saveFolders() {
        if let data = try? JSONEncoder().encode(folders) {
            defaults.set(data, forKey: Key.folders)
        }
    }

    private static func loadFolders() -> [RyFolder] {
        guard let data = UserDefaults.standard.data(forKey: Key.folders),
              let decoded = try? JSONDecoder().decode([RyFolder].self, from: data) else { return [] }
        return decoded
    }
}
