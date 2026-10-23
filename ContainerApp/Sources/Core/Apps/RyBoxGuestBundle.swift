import Foundation
import Darwin
import ObjectiveC

/// Resolves an imported guest app's bundle and prepares it to run as the
/// process's main application (LiveContainer model).
enum RyBoxGuestBundle {

    /// Locate the guest's .app bundle directory inside RyBox's sandbox.
    static func bundleURL(for bundleID: String) -> URL? {
        let root = VirtualRoot.shared.rootURL
            .appendingPathComponent("Apps/\(bundleID).app")
        guard FileManager.default.fileExists(atPath: root.path) else { return nil }
        return root
    }

    /// Activate a guest bundle: redirect +[NSBundle mainBundle] to it so the
    /// guest's Info.plist / resources are resolved as the "main" bundle while
    /// RyBox is running AS the guest.
    ///
    /// The actual dlopen + entry jump is performed by `RyLaunchGuestExecutable`
    /// (RyDyldHooks.m) AFTER the dyld hooks are installed — keep this to the
    /// mainBundle redirect only.
    /// - Returns: the guest's NSPrincipalClass if present (informational).
    static func activate(_ bundleURL: URL) -> String? {
        // Redirect mainBundle BEFORE the guest's UIApplicationMain runs.
        GuestBundleOverride.set(bundleURL)

        guard let data = try? Data(contentsOf: bundleURL.appendingPathComponent("Info.plist")),
              let plist = try? PropertyListSerialization.propertyList(
                  from: data, options: [], format: nil) as? [String: Any] else {
            return nil
        }
        return plist["NSPrincipalClass"] as? String
    }
}

/// Swizzle +[NSBundle mainBundle] so the guest's Info.plist / resources are used
/// while RyBox is running AS the guest. This is the core LiveContainer trick:
/// the guest believes it is the main app.
private enum GuestBundleOverride {
    static var overriddenURL: URL?

    static func set(_ url: URL) {
        overriddenURL = url
        swizzle()
    }

    private static func swizzle() {
        guard let original = class_getClassMethod(NSBundle.self, #selector(getter: NSBundle.main)),
              let replacement = class_getClassMethod(Self.self, #selector(guestMain)) else { return }
        method_exchangeImplementations(original, replacement)
    }

    @objc static func guestMain() -> NSBundle {
        if let u = overriddenURL, let b = NSBundle(url: u) {
            return b
        }
        return NSBundle.main
    }
}
