import Foundation

/// On-device signing engine.
///
/// Guest binaries MUST be signed with the user's cert before spawn/dlopen, or
/// AMFI rejects them. We do NOT bypass AMFI — we satisfy it with a legitimate
/// signature (distribution or development). The actual Mach-O signing is
/// delegated to a bundled auxiliary executable ("codesign", e.g. a zsign build
/// or an ldid wrapper). See codesign-helper-README.txt for the exact contract.
public final class CodeSigner {
    public static let shared = CodeSigner()

    /// Bundled helper filename. Must sit at the app root so
    /// `Bundle.main.url(forAuxiliaryExecutable:)` (or the bundle-root fallback)
    /// resolves it.
    private let helperName = "codesign"

    public enum SignError: Error, LocalizedError {
        case notConfigured
        case helperMissing
        case stageFailed
        case signFailed(Int32, String)
        public var errorDescription: String? {
            switch self {
            case .notConfigured:
                return "未配置证书（请先在「设置」导入 p12 + mobileprovision）"
            case .helperMissing:
                return "缺少 codesign 辅助二进制（需 zsign 类工具，见 codesign-helper-README.txt）"
            case .stageFailed:
                return "无法暂存签名材料（p12 / provisioning / entitlements）"
            case .signFailed(let c, let m):
                return "签名失败（退出码 \(c)）：\(m)"
            }
        }
    }

    /// Re-sign an entire .app bundle IN PLACE with the user's distribution cert.
    ///
    /// Steps:
    ///   1. stage p12 + provisioning + entitlements plist into a temp dir
    ///   2. embed the provisioning profile as `embedded.mobileprovision`
    ///      (AMFI requires the running code's profile to match the signature)
    ///   3. derive guest entitlements from the provisioning profile
    ///   4. delegate the Mach-O signing to the bundled helper (in-place contract)
    ///
    /// - Parameter path: absolute path to the guest `.app` bundle.
    public func sign(bundleAt path: String) -> Result<Void, SignError> {
        guard CertificateStore.shared.isConfigured else { return .failure(.notConfigured) }
        guard let helper = resolveHelper() else { return .failure(.helperMissing) }

        let fm = FileManager.default
        let tmp = fm.temporaryDirectory
            .appendingPathComponent("rybox-sign-\(UUID().uuidString)")
        guard (try? fm.createDirectory(at: tmp, withIntermediateDirectories: true)) != nil else {
            return .failure(.stageFailed)
        }

        // 1) stage p12
        let p12URL = tmp.appendingPathComponent("id.p12")
        guard let p12 = CertificateStore.shared.p12RawData(),
              let pw = CertificateStore.shared.p12Passphrase(),
              (try? p12.write(to: p12URL)) != nil else { return .failure(.stageFailed) }

        // 1) stage provisioning
        let provURL = tmp.appendingPathComponent("profile.mobileprovision")
        guard let prov = CertificateStore.shared.provisioningRawData(),
              (try? prov.write(to: provURL)) != nil else { return .failure(.stageFailed) }

        // 3) stage entitlements (from provisioning's embedded Entitlements dict)
        let entsURL = tmp.appendingPathComponent("guest.entitlements.plist")
        if let ents = CertificateStore.shared.guestEntitlements(),
           let entsData = try? PropertyListSerialization.data(fromPropertyList: ents,
                                                             format: .xml, options: 0) {
            try? entsData.write(to: entsURL)
        }

        // 2) embed provisioning profile inside the guest bundle
        let embeddedURL = URL(fileURLWithPath: path)
            .appendingPathComponent("embedded.mobileprovision")
        try? prov.write(to: embeddedURL)

        // 4) invoke helper — in-place contract (see codesign-helper-README.txt):
        //    <helper> --p12 <p12> --password <pw> --prov <prov>
        //             [--entitlements <ents>] --bundle <bundle>
        var args: [String] = [
            "--p12", p12URL.path,
            "--password", pw,
            "--prov", provURL.path
        ]
        if fm.fileExists(atPath: entsURL.path) {
            args += ["--entitlements", entsURL.path]
        }
        args += ["--bundle", path]

        let rc = spawnHelper(helper.path, args: args)
        if rc != 0 {
            return .failure(.signFailed(rc, helper.lastPathComponent))
        }
        return .success(())
    }

    /// Resolve the bundled helper: prefer `forAuxiliaryExecutable`, then fall
    /// back to the app-bundle root (iOS keeps auxiliary binaries there).
    private func resolveHelper() -> URL? {
        if let u = Bundle.main.url(forAuxiliaryExecutable: helperName) { return u }
        let alt = Bundle.main.bundleURL.appendingPathComponent(helperName)
        return FileManager.default.fileExists(atPath: alt.path) ? alt : nil
    }

    private func spawnHelper(_ path: String, args: [String]) -> Int32 {
        var pid: pid_t = 0
        var fa: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fa)
        var a: [UnsafeMutablePointer<CChar>?] = ([path] + args).map { $0.withCString(strdup) }
        a.append(nil)
        var e: [UnsafeMutablePointer<CChar>?] = ["PATH=/usr/bin:/bin"].map { $0.withCString(strdup) }
        e.append(nil)
        let rc = posix_spawn(&pid, path, &fa, nil, &a, &e)
        a.forEach { free($0) }; e.forEach { free($0) }
        posix_spawn_file_actions_destroy(&fa)
        guard rc == 0 else { return rc }
        var st: Int32 = 0
        waitpid(pid, &st, 0)
        let exited = (st & 0x7f) == 0
        return exited ? Int32((st >> 8) & 0xff) : -1
    }
}
