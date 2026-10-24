import Foundation
import UIKit

/// A theme package found under `/Library/Themes`.
///
/// The layout is the one WinterBoard / SnowBoard / Anemone made standard, so a
/// theme built for those works here without conversion:
///
/// ```
/// MyTheme.theme/
///   Info.plist                     optional: Name / Author
///   IconBundles/<bundle-id>.png    icon replacement (bundle id = file stem)
///   Bundles/<bundle-id>/<file>.png per-bundle artwork
///   UIImages/<name>.png            shell artwork (DockBackground, FolderBackground…)
///   HomeWallpaper.png              home screen wallpaper
///   LockWallpaper.png              lock screen wallpaper
///   Wallpaper.png                  fallback for both
/// ```
///
/// Nothing here hooks UIKit: RyBox *is* the shell, so it reads the theme files
/// directly and applies them to the views it renders itself.
struct RyTheme: Identifiable, Hashable {
    let id: String
    let name: String
    let author: String?
    let directory: URL
}

enum RyWallpaperKind: String {
    case home
    case lock

    /// Candidate filenames, most specific first.
    var filenames: [String] {
        switch self {
        case .home: return ["HomeWallpaper.png", "HomeWallpaper.jpg", "Wallpaper.png", "Wallpaper.jpg"]
        case .lock: return ["LockWallpaper.png", "LockWallpaper.jpg", "Wallpaper.png", "Wallpaper.jpg"]
        }
    }
}

final class ThemeEngine: ObservableObject {
    static let shared = ThemeEngine()

    @Published private(set) var themes: [RyTheme] = []

    /// Enabled themes, lowest priority first — later entries win, exactly like
    /// stacking themes in a theming manager.
    @Published var enabledIDs: [String] {
        didSet { saveEnabled(); dropCaches() }
    }

    private let fm = FileManager.default
    private var iconCache = NSCache<NSString, UIImage>()
    private var uiCache = NSCache<NSString, UIImage>()
    private var wallpaperCache = NSCache<NSString, UIImage>()

    var themesURL: URL {
        VirtualRoot.shared.rootURL.appendingPathComponent("Library/Themes", isDirectory: true)
    }

    private init() {
        enabledIDs = (UserDefaults.standard.stringArray(forKey: Self.enabledKey) ?? [])
        reload()
    }

    // MARK: - Scanning

    /// Re-scan `/Library/Themes` and drop every cached image.
    ///
    /// This is the "注销资源库" action: after installing or editing a theme the
    /// old artwork is still sitting in the caches, so a rescan alone would keep
    /// showing stale icons.
    @discardableResult
    func reload() -> Int {
        dropCaches()
        ensureThemesDirectory()
        let items = (try? fm.contentsOfDirectory(at: themesURL, includingPropertiesForKeys: [.isDirectoryKey])) ?? []
        var found: [RyTheme] = []
        for url in items {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue else { continue }
            let dirName = url.lastPathComponent
            let display = (url.lastPathComponent as NSString).deletingPathExtension
            var name = display.isEmpty ? dirName : display
            var author: String?
            let plistURL = url.appendingPathComponent("Info.plist")
            if let data = try? Data(contentsOf: plistURL),
               let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                as? [String: Any] {
                if let n = plist["Name"] as? String ?? plist["CFBundleDisplayName"] as? String, !n.isEmpty {
                    name = n
                }
                author = plist["Author"] as? String
            }
            found.append(RyTheme(id: dirName, name: name, author: author, directory: url))
        }
        found.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        themes = found
        // Drop enablement for themes that no longer exist on disk.
        let live = Set(found.map(\.id))
        let filtered = enabledIDs.filter { live.contains($0) }
        if filtered != enabledIDs { enabledIDs = filtered }
        return found.count
    }

    private func ensureThemesDirectory() {
        try? fm.createDirectory(at: themesURL, withIntermediateDirectories: true)
    }

    private func dropCaches() {
        iconCache.removeAllObjects()
        uiCache.removeAllObjects()
        wallpaperCache.removeAllObjects()
    }

    /// Enabled themes, highest priority first.
    private var activeDirectories: [URL] {
        enabledIDs.reversed().compactMap { id in themes.first(where: { $0.id == id })?.directory }
    }

    // MARK: - Lookup

    /// Themed icon for a bundle id, or nil when no enabled theme provides one.
    func iconURL(forBundleID bundleID: String) -> URL? {
        for dir in activeDirectories {
            let direct = dir.appendingPathComponent("IconBundles/\(bundleID).png")
            if fm.fileExists(atPath: direct.path) { return direct }
            let bundleDir = dir.appendingPathComponent("Bundles/\(bundleID)", isDirectory: true)
            if let best = Self.largestPNG(in: bundleDir) { return best }
        }
        return nil
    }

    func icon(forBundleID bundleID: String) -> UIImage? {
        let key = bundleID as NSString
        if let cached = iconCache.object(forKey: key) { return cached }
        guard let url = iconURL(forBundleID: bundleID),
              let img = UIImage(contentsOfFile: url.path) else { return nil }
        iconCache.setObject(img, forKey: key)
        return img
    }

    /// Shell artwork (DockBackground, FolderBackground, FolderIconBG, StatusBarBG…).
    func uiImageURL(_ name: String) -> URL? {
        for dir in activeDirectories {
            for ext in ["png", "jpg"] {
                let u = dir.appendingPathComponent("UIImages/\(name).\(ext)")
                if fm.fileExists(atPath: u.path) { return u }
            }
        }
        return nil
    }

    func uiImage(_ name: String) -> UIImage? {
        let key = name as NSString
        if let cached = uiCache.object(forKey: key) { return cached }
        guard let url = uiImageURL(name), let img = UIImage(contentsOfFile: url.path) else { return nil }
        uiCache.setObject(img, forKey: key)
        return img
    }

    func wallpaperURL(_ kind: RyWallpaperKind) -> URL? {
        for dir in activeDirectories {
            for file in kind.filenames {
                let u = dir.appendingPathComponent(file)
                if fm.fileExists(atPath: u.path) { return u }
            }
        }
        return nil
    }

    func wallpaper(_ kind: RyWallpaperKind) -> UIImage? {
        let key = kind.rawValue as NSString
        if let cached = wallpaperCache.object(forKey: key) { return cached }
        guard let url = wallpaperURL(kind), let img = UIImage(contentsOfFile: url.path) else { return nil }
        wallpaperCache.setObject(img, forKey: key)
        return img
    }

    // MARK: - Enable / disable

    func isEnabled(_ id: String) -> Bool { enabledIDs.contains(id) }

    func setEnabled(_ id: String, enabled: Bool) {
        if enabled {
            guard !enabledIDs.contains(id) else { return }
            enabledIDs.append(id)          // appended = highest priority
        } else {
            enabledIDs.removeAll { $0 == id }
        }
    }

    func moveTheme(from offsets: IndexSet, to destination: Int) {
        enabledIDs.move(fromOffsets: offsets, toOffset: destination)
    }

    /// Permanently delete a theme package from /Library/Themes. Removes its
    /// directory, drops it from the enabled set, and rescans + clears caches so
    /// its artwork disappears immediately (no respring needed). Irreversible.
    @discardableResult
    func deleteTheme(_ id: String) -> Bool {
        guard let theme = themes.first(where: { $0.id == id }) else { return false }
        try? fm.removeItem(at: theme.directory)
        reload()
        return true
    }

    // MARK: - Import

    /// Unpack a theme archive (.zip/.theme zip) into `/Library/Themes`.
    func importTheme(from url: URL) -> Result<RyTheme, Error> {
        ensureThemesDirectory()
        let stem = (url.lastPathComponent as NSString).deletingPathExtension
        let base = stem.isEmpty ? "Theme" : stem
        let name = base.hasSuffix(".theme") ? base : base + ".theme"
        let dest = themesURL.appendingPathComponent(name, isDirectory: true)
        try? fm.removeItem(at: dest)
        try? fm.createDirectory(at: dest, withIntermediateDirectories: true)

        let rc = ry_unzip_extract(url.path, dest.path)
        guard rc == 0 else {
            try? fm.removeItem(at: dest)
            return .failure(ThemeError.unzipFailed(rc))
        }
        reload()
        guard let theme = themes.first(where: { $0.id == name }) else {
            return .failure(ThemeError.noTheme)
        }
        setEnabled(theme.id, enabled: true)
        return .success(theme)
    }

    enum ThemeError: Error, LocalizedError {
        case unzipFailed(Int32)
        case noTheme
        var errorDescription: String? {
            switch self {
            case .unzipFailed(let c): return "主题解压失败（退出码 \(c)）"
            case .noTheme: return "解压后没有找到主题目录"
            }
        }
    }

    // MARK: - Helpers

    /// Pick the biggest PNG in a directory: bundles carry several icon sizes and
    /// we want the most detailed one (Assets.car is not parseable here).
    private static func largestPNG(in dir: URL) -> URL? {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey]) else {
            return nil
        }
        var best: URL?
        var bestSize: Int = -1
        for f in files where f.pathExtension.lowercased() == "png" {
            let size = (try? f.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
            if size > bestSize { bestSize = size; best = f }
        }
        return best
    }

    // MARK: - Persistence

    private static let enabledKey = "rybox.themes.enabled"

    private func saveEnabled() {
        UserDefaults.standard.set(enabledIDs, forKey: Self.enabledKey)
    }
}
