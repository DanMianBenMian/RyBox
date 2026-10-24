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
    ///   4. delegate the Mach-O signing to the bundled signer (in-process C
    ///      routine `rysign_sign_bundle`, compiled into this target)
    ///
    /// - Parameter path: absolute path to the guest `.app` bundle.
    public func sign(bundleAt path: String) -> Result<Void, SignError> {
        guard CertificateStore.shared.isConfigured else { return .failure(.notConfigured) }

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

        // 2) stage provisioning
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

        // 4) embed provisioning profile inside the guest bundle
        let embeddedURL = URL(fileURLWithPath: path)
            .appendingPathComponent("embedded.mobileprovision")
        try? prov.write(to: embeddedURL)

        // 5) delegate Mach-O signing to the bundled on-device signer (in-process).
        //    rysign_sign_bundle() re-signs every Mach-O in the bundle with the
        //    staged identity + profile so the guest passes AMFI when dlopen'd.
        let rc = rysign_sign_bundle(path, p12URL.path, pw, provURL.path, entsURL.path)
        if rc != 0 {
            return .failure(.signFailed(rc, "rysign"))
        }
        return .success(())
    }
}
