import Foundation
import UIKit
import Compression

/// Imports an .ipa: unzip -> parse Info.plist -> classify GUI vs CLI ->
/// sign every Mach-O with the distribution cert -> register in the app library.
public final class AppImporter: ObservableObject {
    public static let shared = AppImporter()
    private init() {
        bootstrap()
    }

    @Published public private(set) var lastImported: ImportedApp?
    @Published public private(set) var importedApps: [ImportedApp] = []

    /// Re-register guests that were imported in a previous session. Imported
    /// bundles live on disk under `VirtualRoot/Apps/<bid>.app`, so a relaunch
    /// only needs to scan that directory and rebuild the in-memory registry —
    /// the desktop then appears exactly as it did before (the earlier build lost
    /// this: `importedApps` was in-memory only, so the desktop emptied and the
    /// boot gate refused to proceed). Each bundle is re-signed on launch by
    /// `GuestRuntime`, so `signNote` is left nil here.
    ///
    /// IMPORTANT: the registry is filled SYNCHRONOUSLY. The previous version
    /// appended each app inside `DispatchQueue.main.async`, so anything that
    /// read `importedApps.count` right after startup (the boot log, the App
    /// Library) saw ZERO imported apps even though the bundles were on disk —
    /// that is the "0 已导入 App" report.
    func bootstrap() {
        VirtualRoot.shared.ensure()
        let appsDir = VirtualRoot.shared.rootURL.appendingPathComponent("Apps")
        guard let names = try? fm.contentsOfDirectory(atPath: appsDir.path) else { return }
        var found: [ImportedApp] = []
        for name in names where name.hasSuffix(".app") {
            let bundleURL = appsDir.appendingPathComponent(name)
            let plistURL = bundleURL.appendingPathComponent("Info.plist")
            guard let data = try? Data(contentsOf: plistURL),
                  let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                    as? [String: Any],
                  let exe = plist["CFBundleExecutable"] as? String,
                  let bid = plist["CFBundleIdentifier"] as? String else { continue }

            let isGUI = plist["UIApplicationSceneManifest"] != nil
                       || plist["UILaunchStoryboardName"] != nil
                       || plist["CFBundleIcons"] != nil
            let displayName = (plist["CFBundleName"] as? String)
                           ?? (plist["CFBundleDisplayName"] as? String)
                           ?? (bid as NSString).lastPathComponent
            let exePath = bundleURL.appendingPathComponent(exe).path
            let iconPath = Self.extractIconPath(in: bundleURL, plist: plist)

            found.append(ImportedApp(name: displayName,
                                     bundleIdentifier: bid,
                                     executablePath: exePath,
                                     isGUI: isGUI,
                                     containerPath: bundleURL.path,
                                     iconPath: iconPath,
                                     signNote: nil))
        }

        // Keep already-registered apps (they carry the live sign note) and add
        // whatever the disk scan found.
        let existing = Set(importedApps.map { $0.bundleIdentifier })
        let merged = importedApps + found.filter { !existing.contains($0.bundleIdentifier) }
        guard !merged.isEmpty else { return }
        if Thread.isMainThread {
            importedApps = merged
        } else {
            DispatchQueue.main.async { self.importedApps = merged }
        }
        RyLog.shared.log("已导入 App 重新登记：\(merged.count) 个（磁盘扫描 \(found.count) 个）", level: .info, tag: "import")
    }

    private let fm = FileManager.default

    public enum ImportError: Error, LocalizedError {
        case unzipFailed(Int32)
        case noAppBundle
        case plistMissing
        case signFailed(String)
        case moveFailed(String)
        public var errorDescription: String? {
            switch self {
            case .unzipFailed(let c): return "解压失败（unzip 退出码 \(c)）"
            case .noAppBundle: return "IPA 内未找到 .app"
            case .plistMissing: return "缺少 Info.plist"
            case .signFailed(let m): return m
            case .moveFailed(let m): return "无法安装到 Apps 目录：\(m)"
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
        //
        //    If the on-device signer is unavailable we still register the app:
        //    it shows up on the desktop and can be inspected, and the launcher
        //    states plainly that AMFI may refuse to run it. (iOS has no public
        //    API to re-sign a Mach-O, so RyBox needs the bundled "codesign"
        //    helper for this step — see codesign-helper-README.txt.)
        //
        //    The app's ORIGINAL entitlements are read BEFORE re-signing (the
        //    re-sign overwrites the signature, and with it the capability set).
        //    They are kept in the entitlement policy so the guest can still be
        //    told what it is entitled to at runtime.
        let originalEntitlements = Self.readOriginalEntitlements(exePath: exePath)
        if !originalEntitlements.isEmpty {
            EntitlementPolicy.shared.recordOriginal(bundleID: bid, entitlements: originalEntitlements)
            RyLog.shared.log("\(bid) 原始 entitlements：\(originalEntitlements.keys.sorted().joined(separator: ", "))",
                             level: .info, tag: "sign")
        }

        var signNote: String?
        if case .failure(let e) = CodeSigner.shared.sign(bundleAt: appURL.path) {
            signNote = e.localizedDescription
            RyLog.shared.log("签名失败：\(e.localizedDescription)", level: .error, tag: "sign")
        } else {
            RyLog.shared.log("签名成功：\(bid)", level: .info, tag: "sign")
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
        do {
            try fm.moveItem(at: appURL, to: destRoot)
        } catch {
            // The move MUST succeed — otherwise the app is registered in memory
            // but its bundle is not on disk, so it vanishes on the next launch
            // (the "imported but shows 0 apps" symptom).
            RyLog.shared.log("导入失败：无法移动到 Apps 目录（\(error.localizedDescription)）", level: .error, tag: "import")
            return .failure(ImportError.moveFailed(error.localizedDescription))
        }

        // 5b) locate the app's icon so the SpringBoard can draw the real
        //     artwork (and so themes can replace it by bundle id).
        let iconPath = Self.extractIconPath(in: destRoot, plist: plist)

        let app = ImportedApp(name: displayName,
                              bundleIdentifier: bid,
                              executablePath: destRoot.appendingPathComponent(exe).path,
                              isGUI: isGUI,
                              containerPath: destRoot.path,
                              iconPath: iconPath,
                              signNote: signNote)

        // Register SYNCHRONOUSLY on the main thread: the caller awaits the
        // result and the desktop must reflect it right away.
        if Thread.isMainThread {
            registerSynchronously(app)
        } else {
            DispatchQueue.main.sync { self.registerSynchronously(app) }
        }
        RyLog.shared.log("导入完成：\(displayName)（\(bid)）· \(isGUI ? "GUI" : "CLI")", level: .info, tag: "import")
        return .success(app)
    }

    /// Add an app to the registry and make sure it lands on the desktop.
    private func registerSynchronously(_ app: ImportedApp) {
        if !importedApps.contains(where: { $0.bundleIdentifier == app.bundleIdentifier }) {
            importedApps.append(app)
        }
        lastImported = app
        // Give it a grid slot right away so the icon is visible without a
        // respring.
        DesktopStore.shared.ensurePlaced(isIPad: UIDevice.current.userInterfaceIdiom == .pad)
        DesktopStore.shared.objectWillChange.send()
    }

    /// Read the entitlements the app was originally signed with.
    ///
    /// They live in the Mach-O's code signature (the `CSMAGIC_EMBEDDED_ENTITLEMENTS`
    /// blob) — the same thing `codesign -d --entitlements` prints. This has to
    /// happen BEFORE the bundle is re-signed, because the re-sign replaces the
    /// signature (and with it the original capability set).
    static func readOriginalEntitlements(exePath: String) -> [String: Any] {
        var buf: UnsafeMutablePointer<CChar>?
        var len = 0
        let rc = ry_macho_entitlements(exePath, &buf, &len)
        guard rc == 0, let buf = buf else { return [:] }
        defer { free(buf) }
        guard let data = String(cString: buf).data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                as? [String: Any] else { return [:] }
        return plist
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

    /// Find the bundle's icon PNG.
    ///
    /// `Assets.car` (the modern asset catalog) is not parseable here, so this
    /// tries the classic keys first and then falls back to the largest PNG in
    /// the bundle — which for a repacked IPA is virtually always the app icon.
    static func extractIconPath(in bundle: URL, plist: [String: Any]) -> String? {
        let fm = FileManager.default
        var named: [String] = []
        if let file = plist["CFBundleIconFile"] as? String { named.append(file) }
        if let files = plist["CFBundleIconFiles"] as? [String] { named.append(contentsOf: files) }
        if let primary = (plist["CFBundleIcons"] as? [String: Any])?["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] { named.append(contentsOf: files) }

        for n in named {
            let base = (n as NSString).deletingPathExtension
            for ext in ["png", "jpg"] {
                for suffix in ["@3x", "@2x", ""] {
                    let candidate = bundle.appendingPathComponent("\(base)\(suffix).\(ext)")
                    if fm.fileExists(atPath: candidate.path) { return candidate.path }
                }
            }
        }

        // Fallback: the biggest PNG whose name mentions the icon, else the
        // biggest PNG overall.
        let pngs = (try? fm.subpathsOfDirectory(atPath: bundle.path))?
            .filter { ($0 as NSString).pathExtension.lowercased() == "png" } ?? []
        var best: String?
        var bestSize: Int = -1
        var genericBest: String?
        var genericSize: Int = -1
        for rel in pngs {
            let full = bundle.appendingPathComponent(rel)
            guard let size = (try? full.resourceValues(forKeys: [.fileSizeKey]))?.fileSize else { continue }
            let lower = rel.lowercased()
            if lower.contains("icon") || lower.contains("appicon") {
                if size > bestSize { bestSize = size; best = full.path }
            }
            if size > genericSize { genericSize = size; genericBest = full.path }
        }
        return best ?? genericBest
    }

    private func runUnzip(archive: String, into dir: String) -> Int32 {
        // In-process extraction (RyUnzip.c + zlib). posix_spawn of
        // /usr/bin/unzip is denied by the iOS sandbox (EPERM), so the
        // subprocess path was replaced by this in-process extractor.
        return Int32(ry_unzip_extract(archive, dir))
    }
}
