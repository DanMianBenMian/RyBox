import Foundation

/// Dual-mode runtime environment.
///  - jailed:   pure in-sandbox microkernel (any device, distribution cert).
///  - jailbroken: detect and enable stronger capabilities (real rootfs, global tweaks).
public final class RuntimeEnvironment: ObservableObject {
    public static let shared = RuntimeEnvironment()
    private init() {}

    public enum Mode { case jailed, jailbroken }

    @Published public private(set) var mode: Mode = .jailed
    @Published public private(set) var detecting = true

    @MainActor
    public func detect() async {
        detecting = true
        defer { detecting = false }
        #if JAILED
        mode = .jailed
        #else
        mode = Self.isJailbroken() ? .jailbroken : .jailed
        #endif
    }

    /// Best-effort jailbreak detection (file-based; bypassable, informational).
    public static func isJailbroken() -> Bool {
        let probes = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/bin/ssh",
            "/private/var/lib/apt"
        ]
        let fm = FileManager.default
        for p in probes {
            if fm.fileExists(atPath: p) { return true }
        }
        // sandbox writability to / is a strong signal
        let test = "/.container_jb_probe"
        if fm.createFile(atPath: test, contents: nil) {
            try? fm.removeItem(atPath: test)
            return true
        }
        return false
    }
}
