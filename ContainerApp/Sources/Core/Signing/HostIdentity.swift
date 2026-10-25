import Foundation

/// The signing identity of the HOST app (RyBox itself), as it exists on the
/// device right now.
///
/// ## Why this matters
///
/// LiveContainer's FAQ is explicit about it:
///
///     "If you don't see `get-task-allow`, or it's false, you are using a
///      distribution certificate profile to sign LiveContainer, which is not
///      supported and LiveContainer won't work at all."
///
/// The reason is library validation. A dylib that is `dlopen`ed into a host
/// process has to pass AMFI's library-validation check: the loaded image's
/// team must match the host's team — unless the host process is exempt. A
/// host signed with a **development** profile carries `get-task-allow` and is
/// therefore exempt, so it may load a dylib signed by a *different* team
/// (that is exactly what a JIT / debugger / injection tool does).
///
/// A host signed with a **distribution** profile has no such exemption. Then
/// the guest dylib must be signed by the SAME team as the host — and even
/// then, a distribution profile does not grant
/// `com.apple.security.cs.disable-library-validation`, so the host has no
/// second way out.
///
/// ## The consequence for RyBox
///
/// The guest is re-signed on-device with the certificate the user imports
/// into RyBox. The HOST, on the other hand, was signed by whatever tool the
/// user side-loaded the IPA with (AltStore / Esign / a hand-rolled signer) —
/// and that tool's certificate is very often NOT the one the user imported.
/// When the two teams differ, the guest dylib is refused with
/// `code signature invalid (errno=85)`, and the kernel reports the UUID of
/// the *guest's* CodeDirectory — which is why the failure looks like "our
/// signature is broken" even though the signature is perfectly well formed.
///
/// So the container must be able to SEE this. It reads its own entitlements
/// out of its own Mach-O and its own embedded provisioning profile, and
/// compares them with the identity the guest will be signed with. Everything
/// it finds is written to the log, so one device round-trip answers the
/// question instead of a week of guessing.
public enum HostIdentity {

    // MARK: - What we found

    /// Team identifier of the HOST's own signature.
    ///
    /// Read from the host's embedded provisioning profile (`TeamIdentifier`),
    /// which is what the platform itself binds the app to.
    public private(set) static var hostTeamID: String? = nil

    /// The host's `get-task-allow` entitlement — the library-validation
    /// exemption. `true` means the host may load dylibs signed by other teams.
    public private(set) static var hostGetTaskAllow: Bool = false

    /// The host's `com.apple.security.cs.disable-library-validation`
    /// entitlement. Rarely present in a real profile, but some side-loading
    /// tools add it, and it is the other half of the exemption.
    public private(set) static var hostDisableLibraryValidation: Bool = false

    /// Whether the host's entitlements could be read at all. `false` means we
    /// could not inspect ourselves (no signature / not readable) — not that
    /// the entitlements are empty.
    public private(set) static var hostEntitlementsReadable: Bool = false

    /// Name of the host's embedded provisioning profile, for display.
    public private(set) static var hostProfileName: String? = nil

    /// Whether the host looks like it was signed with a DEVELOPMENT profile.
    ///
    /// A development profile always carries `get-task-allow = true`; a
    /// distribution profile never does. This is the single most useful bit of
    /// information for the "Sileo dies with errno=85" case.
    public static var hostLooksDevelopment: Bool { hostGetTaskAllow }

    // MARK: - Inspection

    /// Inspect the host app's own signature and provisioning profile.
    ///
    /// Cheap (one mmap of the executable + one plist parse) and safe to call
    /// from any thread. Called once at launch.
    @discardableResult
    public static func inspect() -> Bool {
        // 1) Entitlements out of our own Mach-O.
        var buf: UnsafeMutablePointer<CChar>?
        var len = 0
        if let exe = Bundle.main.executablePath {
            let rc = ry_macho_entitlements(exe, &buf, &len)
            if rc == 0, let buf = buf {
                defer { free(buf) }
                if let text = String(cString: buf).data(using: .utf8),
                   let plist = try? PropertyListSerialization.propertyList(from: text,
                                                                          options: [], format: nil)
                    as? [String: Any] {
                    hostEntitlementsReadable = true
                    hostGetTaskAllow = (plist["get-task-allow"] as? Bool) ?? false
                    hostDisableLibraryValidation =
                        (plist["com.apple.security.cs.disable-library-validation"] as? Bool) ?? false
                }
            }
        }

        // 2) Team id + profile name out of our embedded provisioning profile.
        if let provURL = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
           let data = try? Data(contentsOf: provURL),
           let plist = CertificateStore.decodeProvisioningPlist(data) {
            if let teams = plist["TeamIdentifier"] as? [String], let t = teams.first {
                hostTeamID = t
            }
            hostProfileName = plist["Name"] as? String
            // The profile's own entitlements are the authoritative source for
            // get-task-allow — the Mach-O blob can be stale if a tool re-signed
            // the app without refreshing it.
            if let ents = plist["Entitlements"] as? [String: Any],
               let gta = ents["get-task-allow"] as? Bool {
                hostGetTaskAllow = hostGetTaskAllow || gta
            }
            if let ents = plist["Entitlements"] as? [String: Any],
               let dlv = ents["com.apple.security.cs.disable-library-validation"] as? Bool {
                hostDisableLibraryValidation = hostDisableLibraryValidation || dlv
            }
        }

        logSummary()
        return hostEntitlementsReadable
    }

    // MARK: - Diagnostics

    /// One-line verdict: can this host load a foreign-team dylib at all?
    public enum LibraryValidationVerdict {
        /// The host may load a dylib signed by any team.
        case exempt
        /// The host may only load dylibs signed by its own team.
        case sameTeamOnly
        /// We could not tell (no readable signature / profile).
        case unknown

        var text: String {
            switch self {
            case .exempt:      return "宿主已豁免库验证（get-task-allow 或 disable-library-validation）"
            case .sameTeamOnly: return "宿主未豁免库验证：guest 必须与宿主同 team"
            case .unknown:     return "无法读取宿主签名信息"
            }
        }
    }

    public static var libraryValidation: LibraryValidationVerdict {
        if hostGetTaskAllow || hostDisableLibraryValidation { return .exempt }
        if hostEntitlementsReadable || hostTeamID != nil { return .sameTeamOnly }
        return .unknown
    }

    /// The team the guest will be signed with (from the imported identity).
    public static func guestTeamID() -> String? {
        CertificateStore.shared.teamIdentifier
    }

    /// Are host and guest on the same team? `nil` when either side is unknown.
    public static func sameTeam() -> Bool? {
        guard let h = hostTeamID, let g = guestTeamID() else { return nil }
        return h == g
    }

    /// The full diagnosis of the current host/guest signing setup.
    ///
    /// This is what the Settings screen shows and what the launch path logs
    /// before it tries to load a guest — so a failure says *why* instead of
    /// just "errno=85".
    public static func diagnose() -> String {
        var lines: [String] = []
        lines.append("宿主 team=\(hostTeamID ?? "未知")"
                     + " · 描述文件=\(hostProfileName ?? "无")")
        lines.append("宿主 get-task-allow=\(hostGetTaskAllow)"
                     + " · disable-library-validation=\(hostDisableLibraryValidation)")
        lines.append("guest 签名 team=\(guestTeamID() ?? "未配置")")
        switch sameTeam() {
        case .some(true):
            lines.append("→ host 与 guest 同 team，库验证可通过")
        case .some(false):
            lines.append("→ ⚠ host 与 guest 不同 team：宿主没有 get-task-allow，"
                         + "库验证会拒绝这个 guest dylib（errno=85）")
        case .none:
            lines.append("→ team 对比不了（有一侧没读到）")
        }
        lines.append(libraryValidation.text)
        return lines.joined(separator: "\n")
    }

    /// Pre-flight gate for the in-process (LiveContainer-style) guest path.
    ///
    /// Returns `nil` when the launch may proceed, or a human-readable reason
    /// when it definitely cannot work.
    ///
    /// The rule, in one sentence: a dylib loaded into a host must either be
    /// signed by the host's own team, or the host must be exempt from library
    /// validation. The exemption is exactly what a DEVELOPMENT profile gives
    /// you (`get-task-allow` ⇒ the host is debuggable ⇒ AMFI skips the
    /// library-validation check for it).
    public static func preflightWarning() -> String? {
        // Exempt host (development profile) → nothing can go wrong here.
        if hostGetTaskAllow || hostDisableLibraryValidation { return nil }

        // Same team → library validation passes anyway.
        if sameTeam() == true { return nil }

        // No exemption and we cannot prove same-team → refuse with a message
        // that names the fix.
        //
        // Only refuse when we can actually PROVE the mismatch. If the host's
        // own profile is unreadable we do not block the launch (some
        // side-loading tools do not embed a profile at all) — we only warn,
        // because a false refusal would be worse than the errno we are trying
        // to explain.
        if hostTeamID == nil {
            return nil
        }
        return "宿主用分发证书签名（get-task-allow=false），不豁免库验证；"
             + "而 guest 将以 team=\(guestTeamID() ?? "未配置") 签名，与宿主 team=\(hostTeamID!) 不同。"
             + "AMFI 会拒绝这个 guest 动态库（errno=85）。\n"
             + "解决办法：用「开发证书 + 开发描述文件（含本机 UDID）」重新侧载 RyBox.ipa，"
             + "并把同一张 p12 导入 RyBox —— 开发证书自带 get-task-allow，宿主即豁免库验证。"
    }

    /// Log the diagnosis. One call, one log entry, all the facts.
    public static func logSummary() {
        RyLog.shared.log("宿主签名自检：\n\(diagnose())",
                         level: hostGetTaskAllow || hostDisableLibraryValidation ? .info : .warn,
                         tag: "sign")
    }
}
