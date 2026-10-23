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

/// One item on the RyBox desktop / dock: a builtin app or an imported guest.
/// The id is STABLE across launches (String.hashValue is randomly seeded, so
/// guest colors use an FNV-1a hash instead).
struct DesktopItem: Identifiable, Hashable {
    let id: String
    let name: String
    let kind: Kind

    enum Kind: Hashable {
        case builtin(BuiltinApp)
        case guest(ImportedApp)
    }

    var symbol: String {
        switch kind {
        case .builtin(let b): return b.symbol
        case .guest: return "app.fill"
        }
    }

    var tint: Color {
        switch kind {
        case .builtin(let b): return b.tint
        case .guest(let a): return Self.color(for: a.bundleIdentifier)
        }
    }

    var isGuest: Bool {
        if case .guest = kind { return true } else { return false }
    }

    /// Deterministic per-bundle icon color.
    static func color(for key: String) -> Color {
        var h: UInt64 = 1469598103934665603
        for b in key.utf8 { h ^= UInt64(b); h &*= 1099511628211 }
        return Color(hue: Double(h % 360) / 360.0, saturation: 0.62, brightness: 0.86)
    }
}

/// Persisted desktop state: icon positions, dock membership/order, icon scale.
/// Layout is stored as top-left points in the desktop area's own coordinate
/// space (screen-rotation independent), so it survives app restarts.
final class DesktopStore: ObservableObject {
    static let shared = DesktopStore()
    private let defaults = UserDefaults.standard

    private enum Key {
        static let dock = "rybox.dock.ids"
        static let positions = "rybox.desktop.positions"
        static let iconScale = "rybox.desktop.iconScale"
    }

    /// Ordered dock membership (item ids).
    @Published var dockIDs: [String] {
        didSet { defaults.set(dockIDs, forKey: Key.dock) }
    }
    /// Desktop icon positions (top-left, desktop-area coords). Persisted.
    @Published var positions: [String: CGPoint] {
        didSet { savePositions() }
    }
    /// Global icon scale (0.8 – 1.3), editable in Settings.
    @Published var iconScale: Double {
        didSet { defaults.set(iconScale, forKey: Key.iconScale) }
    }
    /// True while the user rearranges the desktop (jiggle mode).
    @Published var editMode = false

    private init() {
        dockIDs = defaults.stringArray(forKey: Key.dock) ?? BuiltinApp.allCases.map(\.id)
        iconScale = defaults.object(forKey: Key.iconScale) as? Double ?? 1.0
        positions = Self.loadPositions()
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

    /// Everything shown on the desktop (builtins first, then imported apps).
    /// The Sileo stub disappears once the REAL preinstalled Sileo is installed.
    var allItems: [DesktopItem] {
        let builtins = realSileoInstalled
            ? builtinItems.filter { $0.id != BuiltinApp.sileo.id }
            : builtinItems
        return builtins + guestItems
    }

    /// True when the real preinstalled Sileo guest is registered.
    var realSileoInstalled: Bool {
        AppImporter.shared.importedApps.contains { $0.bundleIdentifier == PreinstalledStore.sileoBundleID }
    }

    /// Dock contents, in order. Unknown ids and uninstalled guests are skipped.
    var dockItems: [DesktopItem] {
        dockIDs.compactMap { item(id: $0) }
    }

    func item(id: String) -> DesktopItem? {
        // The Sileo slot (stub or dock) resolves to the REAL Sileo once installed.
        if id == BuiltinApp.sileo.id, realSileoInstalled,
           let guest = guestItems.first(where: { $0.id == "guest.\(PreinstalledStore.sileoBundleID)" }) {
            return guest
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
        guard let dict = defaults.dictionary(forKey: Key.positions) as? [String: [Double]] else { return [:] }
        var out: [String: CGPoint] = [:]
        for (k, v) in dict where v.count == 2 {
            out[k] = CGPoint(x: v[0], y: v[1])
        }
        return out
    }
}
