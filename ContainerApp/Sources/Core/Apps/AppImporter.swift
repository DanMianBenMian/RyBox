import Foundation
import Compression

/// Imports an .ipa: unzip -> parse Info.plist -> classify GUI vs CLI ->
/// sign every Mach-O with the distribution cert -> register in the app library.
public final class AppImporter: ObservableObject {
    public static let shared = AppImporter()
    private init() {}

    @Published public private(set) var lastImported: ImportedApp?
    @Published public private(set) var importedApps: [ImportedApp] = []

    private let fm = FileManager.default

    public enum ImportError: Error, LocalizedError {
        case unzipFailed(Int32)
        case noAppBundle
        case plistMissing
        case signFailed(String)
        public var errorDescription: String? {
            switch self {
            case .unzipFailed(let c): return "解压失败（unzip 退出码 \(c)）"
            case .noAppBundle: return "IPA 内未找到 .app"
            case .plistMissing: return "缺少 Info.plist"
            case .signFailed(let m): return m
            }
        }
    }

    /// Import an .ipa from `url` (caller handles security-scoped access).
    public func importApp(from url: URL) -> Result<ImportedApp, Error> {
        let tmp = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? fm.createDirectory(at: tmp, withIntermediateDirectories: true)

        // 1) unzip via system unzip (present on iOS at /usr/bin/unzip)
        let rc = runUnzip(archive: url.path, into: tmp.path)
        guard rc == 0 else { return .failure(ImportError.unzipFailed(rc)) }

        // 2) locate .app
        let payload = tmp.appendingPathComponent("Payload")
        let appNames = (try? fm.contentsOfDirectory(atPath: payload.path)) ?? []
        guard let appName = appNames.first(where: { $0.hasSuffix(".app") }) else {
            return .failure(ImportError.noAppBundle)
        }
        guard let appURL = (try? fm.contentsOfDirectory(at: payload, includingPropertiesForKeys: nil))?
                .first(where: { $0.lastPathComponent == appName }) else {
            return .failure(ImportError.noAppBundle)
        }

        // 3) parse Info.plist
        let plistURL = appURL.appendingPathComponent("Info.plist")
        guard let data = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                as? [String: Any],
              let exe = plist["CFBundleExecutable"] as? String,
              let bid = plist["CFBundleIdentifier"] as? String else {
            return .failure(ImportError.plistMissing)
        }

        let isGUI = plist["UIApplicationSceneManifest"] != nil
                   || plist["UILaunchStoryboardName"] != nil
                   || plist["CFBundleIcons"] != nil

        let displayName = (plist["CFBundleName"] as? String)
                       ?? (plist["CFBundleDisplayName"] as? String)
                       ?? (bid as NSString).lastPathComponent

        let exePath = appURL.appendingPathComponent(exe).path

        // Make sure the virtual root (incl. Apps/) exists.
        VirtualRoot.shared.ensure()

        // 4) sign (distribution cert) — signs the whole bundle in place,
        //    embeds provisioning profile, derives entitlements.
        switch CodeSigner.shared.sign(bundleAt: appURL.path) {
        case .failure(let e): return .failure(ImportError.signFailed(e.localizedDescription))
        case .success: break
        }

        // Ensure the main executable is marked executable (zip may drop the bit).
        chmod(exePath, 0o755)

        // 5) move into Documents/root/Apps/<bid>.app  (keep the .app extension
        //    so dlopen / UIStoryboard / the signer resolve the bundle correctly)
        let destRoot = VirtualRoot.shared.rootURL
            .appendingPathComponent("Apps/\(bid).app")
        try? fm.removeItem(at: destRoot)
        try? fm.createDirectory(at: destRoot.deletingLastPathComponent(),
                                withIntermediateDirectories: true)
        try? fm.moveItem(at: appURL, to: destRoot)

        let app = ImportedApp(name: displayName,
                              bundleIdentifier: bid,
                              executablePath: destRoot.appendingPathComponent(exe).path,
                              isGUI: isGUI,
                              containerPath: destRoot.path)

        DispatchQueue.main.async {
            self.lastImported = app
            if !self.importedApps.contains(app) { self.importedApps.append(app) }
        }
        return .success(app)
    }

    /// Uninstall a guest app: delete its bundle from the virtual root and
    /// unregister it (the desktop icon disappears with it).
    public func remove(_ app: ImportedApp) {
        try? fm.removeItem(atPath: app.containerPath)
        DispatchQueue.main.async {
            self.importedApps.removeAll { $0.bundleIdentifier == app.bundleIdentifier }
            if self.lastImported?.bundleIdentifier == app.bundleIdentifier {
                self.lastImported = nil
            }
        }
    }

    private func runUnzip(archive: String, into dir: String) -> Int32 {
        // In-process extraction (RyUnzip.c + zlib). posix_spawn of
        // /usr/bin/unzip is denied by the iOS sandbox (EPERM), so the
        // subprocess path was replaced by this in-process extractor.
        return Int32(ry_unzip_extract(archive, dir))
    }
}
