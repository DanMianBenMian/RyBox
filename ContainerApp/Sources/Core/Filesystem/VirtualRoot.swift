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
        for sub in ["bin", "usr", "var", "Apps", "Library", "tmp"] {
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
