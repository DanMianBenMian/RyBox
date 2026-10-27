import Foundation

/// The signing identity of the HOST app (RyBox itself), as it exists on the
/// device right now.
///
/// ## What library validation actually checks
///
/// Apple's Code Signing Guide states the rule verbatim:
///
///     "A program may link against any library with the same team identifier
///      in its code signature as the main executable, or with any Apple system
///      library. Requests to link against other libraries are denied."
///
/// So there are exactly **two** ways for a guest dylib to be loaded:
///
///   * **Channel A — same team.** The guest's CodeDirectory carries the same
///     team identifier as the host's. The team identifier belongs to the
///     *Apple developer account*, not to the certificate type: a development
///     certificate and a distribution certificate issued by the SAME account
///     carry the SAME team id. **A distribution certificate therefore works
///     perfectly well** — as long as the host and the guest are signed by the
///     same account. This is the route that does not require a development
///     certificate at all.
///   * **Channel B — host exemption.** The host itself carries
///     `get-task-allow` (i.e. it was signed with a development profile and is
///     debuggable) or `com.apple.security.cs.disable-library-validation`.
///     AMFI then skips the library-validation check for that process and any
///     team may be loaded into it.
///
/// LiveContainer's FAQ only documents Channel B ("if `get-task-allow` is
/// false you are using a distribution certificate profile, which is not
/// supported") because its own distribution path (AltStore / SideStore
/// re-signing) always uses a *different* account than the imported p12 — which
/// breaks Channel A as well. LiveContainer itself insists on this:
///
///     "Re-import a certificate that matches the current LiveContainer
///      signing account."
///
/// RyBox supports both channels and reports which one is currently in force.
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
    /// Read from the host's own CodeDirectory (`teamOffset` in the embedded
    /// code signature) — that is written by whoever signed the app, and it
    /// exists for every real (non-ad-hoc) signature, with or without an
    /// embedded provisioning profile. The profile's `TeamIdentifier` is used
    /// as a fallback.
    public private(set) static var hostTeamID: String? = nil

    /// Where `hostTeamID` came from — shown in the diagnosis so the user can
    /// tell "read from the signature" apart from "read from the profile".
    public private(set) static var hostTeamSource: String? = nil

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

        // 2) Team id out of our own CodeDirectory — the authoritative source.
        //
        //    The team id is written into the CodeDirectory by whoever signed
        //    the binary, so it is present for every real signature even when
        //    the side-loading tool did not embed a provisioning profile (very
        //    common: ad-hoc / CI-built IPAs re-signed by the tool carry no
        //    `embedded.mobileprovision` at all). Reading the profile alone
        //    would leave `hostTeamID` nil exactly in the case we need to
        //    diagnose.
        if let exe = Bundle.main.executablePath {
            var teamBuf: UnsafeMutablePointer<CChar>?
            if ry_macho_team_id(exe, &teamBuf) == 0, let teamBuf = teamBuf {
                defer { free(teamBuf) }
                let t = String(cString: teamBuf)
                if !t.isEmpty {
                    hostTeamID = t
                    hostTeamSource = "Mach-O CodeDirectory"
                }
            }
        }

        // 3) Team id + profile name out of our embedded provisioning profile.
        if let provURL = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
           let data = try? Data(contentsOf: provURL),
           let plist = CertificateStore.decodeProvisioningPlist(data) {
            if hostTeamID == nil,
               let teams = plist["TeamIdentifier"] as? [String], let t = teams.first {
                hostTeamID = t
                hostTeamSource = "描述文件"
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
        /// The host is not exempt, but the guest is on the SAME team — the
        /// dylib is accepted anyway. This is the distribution-certificate
        /// route: it needs no development certificate at all.
        case sameTeam
        /// The host may only load dylibs signed by its own team.
        case sameTeamOnly
        /// We could not tell (no readable signature / profile).
        case unknown

        var text: String {
            switch self {
            case .exempt:
                return "宿主已豁免库验证（get-task-allow 或 disable-library-validation）"
            case .sameTeam:
                return "宿主与 guest 同 team → 库验证直接通过（不需要开发证书）"
            case .sameTeamOnly:
                return "宿主未豁免库验证：guest 必须与宿主同 team"
            case .unknown:
                return "无法读取宿主签名信息"
            }
        }
    }

    public static var libraryValidation: LibraryValidationVerdict {
        if hostGetTaskAllow || hostDisableLibraryValidation { return .exempt }
        if sameTeam() == true { return .sameTeam }
        if hostEntitlementsReadable || hostTeamID != nil { return .sameTeamOnly }
        return .unknown
    }

    /// The team the guest will be signed with (from the imported identity).
    public static func guestTeamID() -> String? {
        CertificateStore.shared.teamIdentifier
    }

    /// Where the guest's team came from — "证书" / "描述文件" / …
    public static var guestTeamSource: String? {
        CertificateStore.shared.teamSource
    }

    /// Are host and guest on the same team? `nil` when either side is unknown.
    public static func sameTeam() -> Bool? {
        guard let h = hostTeamID, let g = guestTeamID() else { return nil }
        return h == g
    }

    /// The two ways a guest dylib can be loaded into this host.
    ///
    /// Apple only checks the team identifier of the loaded library against the
    /// host's — it does not care whether either signature came from a
    /// development or a distribution certificate, as long as both come from
    /// the same Apple developer account (same team id).
    public enum LoadRoute {
        /// Channel B: the host is exempt (development profile / debuggable).
        case hostExempt
        /// Channel A: same team — works with a distribution certificate too.
        case sameTeam
        /// Neither channel is available.
        case blocked
        /// Not enough information to tell.
        case unknown

        public var works: Bool {
            switch self {
            case .hostExempt, .sameTeam: return true
            case .blocked, .unknown: return false
            }
        }

        public var title: String {
            switch self {
            case .hostExempt: return "通道 B：宿主豁免（开发证书）"
            case .sameTeam:   return "通道 A：同 team（分发证书即可）"
            case .blocked:    return "通道不通"
            case .unknown:    return "信息不足"
            }
        }
    }

    /// Which channel (if any) is currently available for loading a guest.
    public static func loadRoute() -> LoadRoute {
        if hostGetTaskAllow || hostDisableLibraryValidation { return .hostExempt }
        switch sameTeam() {
        case .some(true):  return .sameTeam
        case .some(false): return .blocked
        case .none:        return .unknown
        }
    }

    /// The full diagnosis of the current host/guest signing setup.
    ///
    /// This is what the Settings screen shows and what the launch path logs
    /// before it tries to load a guest — so a failure says *why* instead of
    /// just "errno=85".
    public static func diagnose() -> String {
        var lines: [String] = []
        lines.append("宿主 team=\(hostTeamID ?? "未知")"
                     + (hostTeamSource.map { "（来源：\($0)）" } ?? "")
                     + " · 描述文件=\(hostProfileName ?? "无")")
        lines.append("宿主 get-task-allow=\(hostGetTaskAllow)"
                     + " · disable-library-validation=\(hostDisableLibraryValidation)")
        lines.append("guest 签名 team=\(guestTeamID() ?? "未配置")"
                     + (guestTeamSource.map { "（来源：\($0)）" } ?? ""))
        switch sameTeam() {
        case .some(true):
            lines.append("→ ✅ host 与 guest 同 team，库验证直接通过")
        case .some(false):
            lines.append("→ ⚠ host 与 guest 不同 team：宿主没有 get-task-allow，"
                         + "库验证会拒绝这个 guest dylib（errno=85）")
        case .none:
            lines.append("→ team 对比不了（有一侧没读到）")
        }
        lines.append(libraryValidation.text)
        lines.append("可用通路：\(loadRoute().title)")
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
        // Channel B — exempt host (development profile): nothing can go wrong.
        if hostGetTaskAllow || hostDisableLibraryValidation { return nil }

        // Channel A — same team: library validation passes anyway, and this
        // works with a DISTRIBUTION certificate because the team id belongs
        // to the Apple account, not to the certificate type.
        if sameTeam() == true { return nil }

        // No exemption and we cannot PROVE the mismatch → do not block.
        //
        // Only refuse when we actually know the two teams differ. If either
        // side could not be read (no profile embedded, ad-hoc signature, the
        // imported p12 not parsed yet) we stay out of the way: a false refusal
        // is worse than the errno we are trying to explain. The diagnosis
        // panel and the log line carry the uncertainty instead.
        guard let host = hostTeamID, let guest = guestTeamID() else { return nil }

        return "宿主用分发证书签名（get-task-allow=false），不豁免库验证；"
             + "而 guest 将以 team=\(guest) 签名，与宿主 team=\(host) 不同。"
             + "AMFI 会拒绝这个 guest 动态库（errno=85）。\n\n"
             + "两条通路任选其一：\n"
             + "【A · 同 team —— 分发证书就能用】用**同一个 Apple 开发者账号**的证书去侧载"
             + " RyBox.ipa，并把**同一张 p12** 导入 RyBox 给 guest 重签。宿主与 guest 同 team 时"
             + "库验证直接通过（Apple 官方规则只比对 team id，开发证书与分发证书的 team id 相同）。\n"
             + "【B · 开发证书】用「开发证书 + 开发描述文件（含本机 UDID）」重新侧载 RyBox.ipa。"
             + "开发证书自带 get-task-allow，宿主即豁免库验证，可加载任意 team 的 guest。"
    }

    /// Log the diagnosis. One call, one log entry, all the facts.
    public static func logSummary() {
        RyLog.shared.log("宿主签名自检：\n\(diagnose())",
                         level: hostGetTaskAllow || hostDisableLibraryValidation ? .info : .warn,
                         tag: "sign")
    }
}
