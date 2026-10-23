import Foundation
import SwiftUI

/// Built-in RyBox apps. Sileo is PREINSTALLED (shows on the desktop + dock by
/// default), matching a jailbroken-device home screen.
enum BuiltinApp: String, CaseIterable, Codable {
    case sileo, settings, files, terminal, `import`
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
        }
    }

    var symbol: String {
        switch self {
        case .sileo: return "shippingbox.fill"
        case .settings: return "gearshape.fill"
        case .files: return "folder.fill"
        case .terminal: return "terminal.fill"
        case .import: return "square.and.arrow.down.fill"
        }
    }

    var tint: Color {
        switch self {
        case .sileo: return Color(red: 0.90, green: 0.20, blue: 0.38)     // Sileo red
        case .settings: return Color(red: 0.40, green: 0.43, blue: 0.49)  // iOS settings gray
        case .files: return Color(red: 0.20, green: 0.55, blue: 0.95)     // Files blue
        case .terminal: return Color(red: 0.14, green: 0.15, blue: 0.18)  // near-black
        case .import: return Color(red: 0.30, green: 0.72, blue: 0.45)    // green
        }
    }
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

/// Persisted desktop state: icon positions, dock membership/order, folders,
/// icon scale. Layout is stored as top-left points in the desktop area's own
/// coordinate space, so it survives app restarts.
final class DesktopStore: ObservableObject {
    static let shared = DesktopStore()
    private let defaults = UserDefaults.standard

    private enum Key {
        static let dock = "rybox.dock.ids"
        static let positions = "rybox.desktop.positions"
        static let iconScale = "rybox.desktop.iconScale"
        static let folders = "rybox.desktop.folders"
    }

    /// Ordered dock membership (item ids).
    @Published var dockIDs: [String] {
        didSet { defaults.set(dockIDs, forKey: Key.dock) }
    }
    /// Desktop icon positions (top-left, desktop-area coords). Persisted.
    @Published var positions: [String: CGPoint] {
        didSet { savePositions() }
    }
    /// Desktop folders. Persisted.
    @Published var folders: [RyFolder] {
        didSet { saveFolders() }
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
        positions = Self.loadPositions()
        folders = Self.loadFolders()
    }

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
    /// lose their loose desktop position.
    @discardableResult
    func createFolder(with ids: [String], name: String? = nil) -> RyFolder {
        let members = ids.filter { item(id: $0) != nil }
        let folder = RyFolder(name: name ?? "文件夹", memberIDs: members)
        folders.append(folder)
        for m in members {
            removeFromDock(m)
            positions.removeValue(forKey: m)
        }
        return folder
    }

    /// Add an item to an existing folder.
    func addToFolder(_ itemID: String, folderID: String) {
        guard var f = folders.first(where: { $0.id == folderID }),
              !f.memberIDs.contains(itemID), item(id: itemID) != nil else { return }
        f.memberIDs.append(itemID)
        folders = folders.map { $0.id == folderID ? f : $0 }
        removeFromDock(itemID)
        positions.removeValue(forKey: itemID)
    }

    /// Remove an item from its folder (it flows back to the desktop).
    func removeFromFolder(_ itemID: String) {
        folders = folders.map { f in
            guard f.memberIDs.contains(itemID) else { return f }
            var nf = f
            nf.memberIDs.removeAll { $0 == itemID }
            return nf
        }
        positions.removeValue(forKey: itemID)
    }

    func renameFolder(_ folderID: String, to name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        folders = folders.map { $0.id == folderID ? RyFolder(id: $0.id, name: trimmed, memberIDs: $0.memberIDs) : $0 }
    }

    /// Dissolve a folder: members return to the desktop grid.
    func deleteFolder(_ folderID: String) {
        guard let f = folders.first(where: { $0.id == folderID }) else { return }
        for m in f.memberIDs { positions.removeValue(forKey: m) }
        folders.removeAll { $0.id == folderID }
    }

    // MARK: Desktop layout

    func position(for id: String) -> CGPoint? { positions[id] }

    func savePosition(_ point: CGPoint, for id: String) {
        positions[id] = point
    }

    /// Grid slot for an icon with no saved position.
    func defaultPosition(index: Int, area: CGSize, pitch: CGSize, cell: CGSize) -> CGPoint {
        let cols = max(1, Int((area.width + 8) / pitch.width))
        let col = index % cols
        let row = index / cols
        let gridWidth = CGFloat(cols) * pitch.width - (pitch.width - cell.width)
        let originX = max(8, (area.width - gridWidth) / 2)
        return CGPoint(x: originX + CGFloat(col) * pitch.width,
                       y: CGFloat(row) * pitch.height)
    }

    func resetLayout() {
        positions = [:]
        folders = []
        dockIDs = BuiltinApp.allCases.map(\.id)
        iconScale = 1.0
    }

    // MARK: Persistence

    private func savePositions() {
        var dict: [String: [Double]] = [:]
        for (k, v) in positions { dict[k] = [Double(v.x), Double(v.y)] }
        defaults.set(dict, forKey: Key.positions)
    }

    private static func loadPositions() -> [String: CGPoint] {
        guard let dict = UserDefaults.standard.dictionary(forKey: Key.positions) as? [String: [Double]] else { return [:] }
        var out: [String: CGPoint] = [:]
        for (k, v) in dict where v.count == 2 {
            out[k] = CGPoint(x: v[0], y: v[1])
        }
        return out
    }

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
