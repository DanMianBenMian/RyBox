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
/// ## The fix (two halves)
///
/// 1. **Signed entitlements = the profile's set.** AMFI compares the
///    entitlements in the signature against the provisioning profile and
///    REJECTS a signature that claims more than the profile allows. So the
///    signed blob must stay exactly what the profile grants. Blindly merging
///    the original app's entitlements into it would make the signature
///    invalid and the guest would die at dlopen time — strictly worse.
///
/// 2. **Simulated entitlements = the original app's set.** Everything the app
///    originally declared (minus the identity keys that MUST match the
///    profile) is kept in a runtime table. `EntitlementPolicy` exposes it,
///    the guest loader swizzles `SecTaskCopyValueForEntitlement` so the guest
///    asks the container instead of the kernel, and the microkernel exports
///    the same table to CLI guests through `RYBOX_ENTITLEMENTS`.
///
/// So: the signature stays legal, and the app still gets to believe it has
/// the capabilities it was built with — that is the "模拟放行" the container
/// owes its guests.
public final class EntitlementPolicy: ObservableObject {
    public static let shared = EntitlementPolicy()

    /// Entitlements the app originally shipped with, per bundle id.
    @Published public private(set) var original: [String: [String: Any]] = [:]

    /// Entitlements the user's provisioning profile grants (the signed set).
    @Published public private(set) var profile: [String: Any] = [:]

    /// Bundle id of the guest that is currently running (if any).
    @Published public private(set) var activeBundleID: String?

    /// Entitlements the CURRENT guest is allowed to observe.
    public var activeSimulated: [String: Any] {
        guard let bid = activeBundleID else { return [:] }
        return original[bid] ?? [:]
    }

    private init() {
        // The C/ObjC side asks this table when the guest queries its own
        // entitlements. The lookup is a C function pointer, so it must be a
        // top-level function without captures (see `ryEntitlementLookup`).
        RyInstallEntitlementLookup(ryEntitlementLookup)
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

    // MARK: - Recording

    /// Remember the entitlements an imported app originally had.
    public func recordOriginal(bundleID: String, entitlements: [String: Any]) {
        guard !entitlements.isEmpty else { return }
        var copy = original
        copy[bundleID] = entitlements
        original = copy
    }

    /// Update the profile-side entitlement set (from the user's .mobileprovision).
    public func updateProfile(_ entitlements: [String: Any]) {
        profile = entitlements
    }

    /// Mark which guest is running (its simulated entitlements become active).
    public func setActive(bundleID: String?) {
        activeBundleID = bundleID
    }

    // MARK: - Merging

    /// The entitlements that go INTO the signature: exactly what the profile
    /// grants. We deliberately do NOT merge the original app's capabilities
    /// here — AMFI would reject the signature.
    public static func signedEntitlements(profile: [String: Any]) -> [String: Any] {
        profile
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
    public static func diff(original: [String: Any], profile: [String: Any]) -> (kept: [String], dropped: [String]) {
        var kept: [String] = []
        var dropped: [String] = []
        for key in original.keys.sorted() {
            if identityKeys.contains(key) { dropped.append(key); continue }
            kept.append(key)
        }
        return (kept, dropped)
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
