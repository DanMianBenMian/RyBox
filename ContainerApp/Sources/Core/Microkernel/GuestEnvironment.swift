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
            // Entitlement simulation for CLI guests: the child process runs with
            // the CONTAINER's entitlements (it is a fork of RyBox), so an app
            // that asks "do I have capability X?" would get the wrong answer.
            // We hand it the app's ORIGINAL entitlement set instead — the same
            // table the in-process guests query through the entitlement oracle.
            let original = EntitlementPolicy.shared.original[app.bundleIdentifier] ?? [:]
            if !original.isEmpty {
                let simulated = EntitlementPolicy.simulatedEntitlements(
                    original: original,
                    profile: EntitlementPolicy.shared.profile)
                if let data = try? PropertyListSerialization.data(fromPropertyList: simulated,
                                                                 format: .xml, options: 0),
                   let s = String(data: data, encoding: .utf8) {
                    env["RYBOX_ENTITLEMENTS"] = s
                }
                env["RYBOX_ENTITLEMENTS_KEYS"] = simulated.keys.sorted().joined(separator: ",")
                RyLog.shared.log("微内核放行 \(app.bundleIdentifier) 的 entitlements：\(simulated.keys.sorted().joined(separator: ", "))",
                                 level: .info, tag: "kernel")
            }
        }
        return env
    }
}
