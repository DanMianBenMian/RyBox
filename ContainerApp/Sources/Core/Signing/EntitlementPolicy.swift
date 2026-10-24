import Foundation
import Combine

/// RyBox's entitlement policy.
///
/// ## The problem
///
/// A guest IPA is signed by a DIFFERENT team than the one that built it.
/// When RyBox re-signs the bundle with the user's own distribution
/// certificate, the entitlements the app originally shipped with (HealthKit,
/// App Groups, keychain access groups, background modes, push, associated
/// domains, …) are thrown away — the signature only carries what the user's
/// provisioning profile grants.
///
/// Two things then go wrong:
///   * the app asks the OS for a capability it no longer has and silently
///     degrades (or refuses to launch),
///   * the container itself has no idea which capabilities the app expects,
///     so "环境不兼容" can only be guessed at.
///
/// ## The fix (three halves)
///
/// 1. **Signed entitlements = the profile's set, MINUS privileged keys.**
///    AMFI compares the entitlements in the signature against the
///    provisioning profile and REJECTS a signature that claims more than the
///    profile allows. So the signed blob must stay exactly what the profile
///    grants — with one deliberate subtraction: *privileged* entitlements
///    (`platform-application`, `com.apple.private.*`, `task_for_pid-allow`, …)
///    are STRIPPED before signing. A guest runs INSIDE RyBox's own process
///    (in-process dlopen model), so at runtime its entitlement queries are
///    answered by the HOST process anyway — the special permissions in the
///    guest's signature would buy nothing and only risk rejection. Stripping
///    them is both safe and required by the "特殊权限分配" design.
///
/// 2. **Every stripped key is MARKED** (`takenOver`): per bundle id we keep
///    the list of privileged entitlements the app originally declared. They
///    are visible in the log at import time and in Settings → 特殊权限分配.
///
/// 3. **RyBox takes over the allocation.** The guest still gets to believe it
///    has the capabilities it was built with: the entitlement oracle
///    (`SecTaskCopyValueForEntitlement` hook) answers from the simulated
///    table, which is the original set minus the identity keys (those MUST
///    match the signing team) plus the profile's own non-identity keys. Each
///    privileged key can be switched OFF per app in the manager UI — a
///    withheld key returns "not entitled", which is how the user *allocates*
///    special permissions instead of the signature pretending to grant them.
public final class EntitlementPolicy: ObservableObject {
    public static let shared = EntitlementPolicy()

    /// Entitlements the app originally shipped with, per bundle id.
    @Published public private(set) var original: [String: [String: Any]] = [:]

    /// Entitlements the user's provisioning profile grants (the signed set).
    @Published public private(set) var profile: [String: Any] = [:]

    /// Privileged entitlements RyBox took over, per bundle id (the "标记").
    /// Empty when the app declared none.
    @Published public private(set) var takenOver: [String: [String]] = [:]

    /// Per-app allocation switches: bundle id → privileged key → granted?
    /// A key missing from the table counts as granted (default ON).
    @Published public private(set) var grants: [String: [String: Bool]] = [:]

    /// Bundle id of the guest that is currently running (if any).
    @Published public private(set) var activeBundleID: String?

    /// Entitlements the CURRENT guest is allowed to observe.
    public var activeSimulated: [String: Any] {
        guard let bid = activeBundleID else { return [:] }
        var out = Self.simulatedEntitlements(original: original[bid] ?? [:],
                                             profile: profile)
        // Privileged keys the user explicitly withheld are NOT granted.
        for (key, allowed) in grants[bid] ?? [:] where !allowed {
            out.removeValue(forKey: key)
        }
        return out
    }

    private init() {
        // The C/ObjC side asks this table when the guest queries its own
        // entitlements. The lookup is a C function pointer, so it must be a
        // top-level function without captures (see `ryEntitlementLookup`).
        RyInstallEntitlementLookup(ryEntitlementLookup)
        load()
    }

    /// Keys that MUST come from the signing profile: they encode the signing
    /// identity, and AMFI validates them against the profile.
    public static let identityKeys: Set<String> = [
        "application-identifier",
        "keychain-access-groups",
        "com.apple.developer.team-identifier",
        "get-task-allow",
        "beta-reports-active",
        "com.apple.developer.applesignid",
        "com.apple.developer.mac-app-store",
        "com.apple.security.application-groups",
        "com.apple.developer.team-id"
    ]

    /// Entitlements that grant kernel-/system-level power. They are stripped
    /// from the guest's SIGNATURE (RyBox allocates them at runtime instead) —
    /// a sandboxed in-process guest cannot use them, and carrying them only
    /// risks AMFI rejecting the signature.
    public static let privilegedKeys: Set<String> = [
        "platform-application",                 // full platform binary powers
        "task_for_pid-allow",                   // task_for_pid() on other pids
        "com.apple.system-task-ports",          // raw mach task ports
        "seatbelt-profiles",                    // custom sandbox profiles
        "dynamic-codesigning",                  // run unsigned code
        "com.apple.private.cs.debugger"         // debug other processes
    ]

    /// Key prefixes with the same meaning as `privilegedKeys`.
    public static let privilegedPrefixes: [String] = [
        "com.apple.private."
    ]

    /// Is this entitlement "special" — i.e. something RyBox must take over?
    public static func isPrivileged(_ key: String) -> Bool {
        if privilegedKeys.contains(key) { return true }
        for prefix in privilegedPrefixes where key.hasPrefix(prefix) { return true }
        return false
    }

    /// Split an entitlement set into the three buckets the policy works with.
    public static func classify(_ entitlements: [String: Any])
        -> (identity: [String], privileged: [String], normal: [String]) {
        var identity: [String] = []
        var privileged: [String] = []
        var normal: [String] = []
        for key in entitlements.keys {
            if identityKeys.contains(key) { identity.append(key) }
            else if isPrivileged(key)     { privileged.append(key) }
            else                          { normal.append(key) }
        }
        return (identity.sorted(), privileged.sorted(), normal.sorted())
    }

    // MARK: - Recording

    /// Remember the entitlements an imported app originally had, and mark the
    /// privileged ones RyBox takes over (allocation defaults to ON).
    public func recordOriginal(bundleID: String, entitlements: [String: Any]) {
        guard !entitlements.isEmpty else { return }
        var copy = original
        copy[bundleID] = entitlements
        original = copy

        let privileged = entitlements.keys.filter { Self.isPrivileged($0) }.sorted()
        var to = takenOver
        to[bundleID] = privileged
        takenOver = to

        var g = grants
        var per = g[bundleID] ?? [:]
        for key in privileged where per[key] == nil { per[key] = true }
        g[bundleID] = per
        grants = g
        save()
    }

    /// Update the profile-side entitlement set (from the user's .mobileprovision).
    public func updateProfile(_ entitlements: [String: Any]) {
        profile = entitlements
        save()
    }

    /// Mark which guest is running (its simulated entitlements become active).
    public func setActive(bundleID: String?) {
        activeBundleID = bundleID
    }

    /// Allocate (or withhold) one privileged entitlement for one app. The
    /// change takes effect the next time the guest queries it — and for the
    /// running guest, immediately (the oracle reads this table live).
    public func setGrant(bundleID: String, key: String, allowed: Bool) {
        var g = grants
        var per = g[bundleID] ?? [:]
        per[key] = allowed
        g[bundleID] = per
        grants = g
        save()
    }

    /// Turn every privileged entitlement for an app back on.
    public func grantAll(bundleID: String) {
        var g = grants
        var per = g[bundleID] ?? [:]
        for key in takenOver[bundleID] ?? [] { per[key] = true }
        g[bundleID] = per
        grants = g
        save()
    }

    /// Privileged keys RyBox has taken over for an app (empty if none).
    public func takenOverKeys(bundleID: String) -> [String] {
        takenOver[bundleID] ?? []
    }

    /// Whether a taken-over key is currently allocated to the app.
    public func isGranted(bundleID: String, key: String) -> Bool {
        grants[bundleID]?[key] ?? true
    }

    // MARK: - Merging

    /// The entitlements that go INTO the signature: what the profile grants,
    /// MINUS privileged keys. AMFI would reject a signature that claims more
    /// than the profile allows; and privileged keys buy an in-process guest
    /// nothing anyway, so they are stripped and allocated by RyBox instead.
    public static func sanitizeForSigning(profile: [String: Any])
        -> (signed: [String: Any], stripped: [String]) {
        var signed: [String: Any] = [:]
        var stripped: [String] = []
        for (key, value) in profile {
            if isPrivileged(key) { stripped.append(key) } else { signed[key] = value }
        }
        return (signed, stripped.sorted())
    }

    /// The entitlements the guest is allowed to OBSERVE: everything the app
    /// originally declared, minus the identity keys (which belong to the
    /// signing team, not the app).
    public static func simulatedEntitlements(original: [String: Any],
                                             profile: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [:]
        for (key, value) in original where !identityKeys.contains(key) {
            out[key] = value
        }
        // The profile's own capability keys stay visible too (e.g. the app
        // asking for a background mode the user's profile happens to grant).
        for (key, value) in profile where !identityKeys.contains(key) {
            if out[key] == nil { out[key] = value }
        }
        return out
    }

    /// Human-readable diff between what the app wanted and what it gets.
    public static func diff(original: [String: Any], profile: [String: Any])
        -> (kept: [String], dropped: [String], privileged: [String]) {
        var kept: [String] = []
        var dropped: [String] = []
        var privileged: [String] = []
        for key in original.keys.sorted() {
            if identityKeys.contains(key) { dropped.append(key); continue }
            if isPrivileged(key) { privileged.append(key); continue }
            kept.append(key)
        }
        return (kept, dropped, privileged)
    }

    // MARK: - Helpers

    /// Render an entitlement value as a plist string so it can cross the C
    /// boundary and be re-parsed on the other side.
    public static func plistString(_ value: Any) -> String {
        if let s = value as? String { return s }
        if let b = value as? Bool { return b ? "true" : "false" }
        if let n = value as? NSNumber { return n.stringValue }
        if let d = value as? [String: Any] {
            if let data = try? PropertyListSerialization.data(fromPropertyList: d,
                                                             format: .xml, options: 0),
               let s = String(data: data, encoding: .utf8) {
                return s
            }
        }
        if let a = value as? [Any] {
            if let data = try? PropertyListSerialization.data(fromPropertyList: a,
                                                             format: .xml, options: 0),
               let s = String(data: data, encoding: .utf8) {
                return s
            }
        }
        return String(describing: value)
    }

    // MARK: - Persistence

    /// The whole policy table lives in the app sandbox so a relaunch does not
    /// "forget" what was taken over or how it was allocated. Imported apps are
    /// registered from DesktopStore on launch but never re-imported, so without
    /// this the manager UI would come up empty every restart.
    private var policyURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("RyBoxKeys/entitlement-policy.plist")
    }

    private func save() {
        let dict: [String: Any] = [
            "original": original,
            "takenOver": takenOver,
            "grants": grants
        ]
        guard let data = try? PropertyListSerialization.data(fromPropertyList: dict,
                                                             format: .xml, options: 0) else { return }
        let url = policyURL
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        try? data.write(to: url, options: .atomic)
    }

    private func load() {
        guard let data = try? Data(contentsOf: policyURL),
              let dict = try? PropertyListSerialization.propertyList(from: data,
                      options: [], format: nil) as? [String: Any] else { return }
        if let o = dict["original"] as? [String: [String: Any]] { original = o }
        if let t = dict["takenOver"] as? [String: [String]] { takenOver = t }
        if let g = dict["grants"] as? [String: [String: Bool]] { grants = g }
    }

    /// Forget everything (used when the user wipes the container's data).
    public func reset() {
        original = [:]
        takenOver = [:]
        grants = [:]
        profile = [:]
        activeBundleID = nil
        try? FileManager.default.removeItem(at: policyURL)
    }
}

/// C trampoline for the entitlement oracle (see `EntitlementPolicy.init`).
///
/// Top-level, capture-free so it converts to a C function pointer. The
/// typedef is `const char *(*)(const char *)`.
///
/// OWNERSHIP: the returned pointer is only valid until the next call — the C
/// side copies it into its own malloc'd buffer immediately. Handing out a
/// Swift-allocated pointer would be a mismatch with the C side's `free()`.
private var ryEntitlementBuffer: UnsafeMutablePointer<CChar>? = nil

private func ryEntitlementLookup(_ key: UnsafePointer<CChar>?) -> UnsafePointer<CChar>? {
    guard let key = key else { return nil }
    let name = String(cString: key)
    guard let value = EntitlementPolicy.shared.activeSimulated[name] else { return nil }
    let text = EntitlementPolicy.plistString(value)
    ryEntitlementBuffer?.deallocate()
    let bytes = Array(text.utf8) + [0]
    let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: bytes.count)
    for (i, b) in bytes.enumerated() { buffer[i] = CChar(bitPattern: b) }
    ryEntitlementBuffer = buffer
    return UnsafePointer(buffer)
}
