import Foundation

/// Presents the app sandbox as a rooted filesystem view ("/").
/// Documents/root  ->  /
/// Within it: /bin /usr /var /Apps /Library  etc. (jailed userspace).
public final class VirtualRoot {
    public static let shared = VirtualRoot()
    private init() {}

    public let rootURL: URL = {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("root", isDirectory: true)
    }()

    public func ensure() {
        let fm = FileManager.default
        // Library/Themes is where theming engines look for packages, so it has
        // to exist before the first scan — otherwise a user dropping a theme in
        // through Files would have nowhere to put it.
        for sub in ["bin", "usr", "var", "Apps", "Library", "tmp",
                    "Library/Themes", "Library/Caches",
                    "Library/MobileSubstrate/DynamicLibraries",
                    "var/mobile/Library/Preferences"] {
            try? fm.createDirectory(at: rootURL.appendingPathComponent(sub),
                                    withIntermediateDirectories: true)
        }
    }

    /// Map a virtual absolute path ("/bin/sh") to the real sandbox URL.
    public func url(for virtualPath: String) -> URL {
        let trimmed = virtualPath.hasPrefix("/") ? String(virtualPath.dropFirst()) : virtualPath
        return rootURL.appendingPathComponent(trimmed)
    }

    public func realPath(of virtualPath: String) -> String {
        url(for: virtualPath).path
    }
}
