import Foundation

/// Builds the environment block a guest process sees: a self-contained
/// userspace rooted at `VirtualRoot`, with the container's bin dirs on PATH.
enum GuestEnvironment {
    /// - Parameter app: the guest app, if known (sets guest-specific vars).
    static func build(for app: ImportedApp? = nil) -> [String: String] {
        let root = VirtualRoot.shared.rootURL.path
        let path = [
            "\(root)/usr/bin",
            "\(root)/bin",
            "/usr/bin", "/bin", "/usr/sbin", "/sbin"
        ].joined(separator: ":")

        var env: [String: String] = [
            "PATH": path,
            "HOME": root,
            "TMPDIR": "\(root)/tmp",
            "RYBOX_ROOT": root,
            "LOGNAME": "mobile",
            "SHELL": "/bin/sh"
        ]
        if let app = app {
            env["RYBOX_GUEST_BID"] = app.bundleIdentifier
            env["RYBOX_GUEST_HOME"] = app.containerPath
        }
        return env
    }
}
