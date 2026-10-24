import Foundation
import Security

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
    ///   1. stage provisioning + entitlements plist into a temp dir
    ///   2. embed the provisioning profile as `embedded.mobileprovision`
    ///      (AMFI requires the running code's profile to match the signature)
    ///   3. derive guest entitlements from the provisioning profile
    ///   4. delegate the Mach-O signing to the bundled signer (in-process C
    ///      routine `rysign_sign_bundle*`, compiled into this target)
    ///
    /// ## Which signer entry is used
    ///
    /// `CertificateStore.importP12` first tries `SecPKCS12Import`. When that
    /// fails (which is the norm for p12 files written by OpenSSL 3: PBES2 +
    /// AES-256-CBC + PBKDF2-SHA256) it falls back to RyBox's own PKCS#12
    /// decoder, which decrypts the file and hands back a DER certificate + a
    /// DER private key. The signer then takes the DER entry point and never
    /// calls `SecPKCS12Import` at all — that call is what made every guest
    /// launch die with "签名失败（退出码 3）".
    ///
    /// ## Entitlements
    ///
    /// The SIGNED entitlement set is exactly what the user's provisioning
    /// profile grants — nothing more. AMFI compares the signature's entitlements
    /// against the profile and REJECTS a signature that claims capabilities
    /// the profile does not cover, so merging the original app's entitlements
    /// into the signature would break the guest at dlopen time.
    ///
    /// What the app ORIGINALLY had is preserved separately (see
    /// `EntitlementPolicy`): the container keeps it, hands it to the running
    /// guest through the entitlement oracle, and exports it to CLI guests via
    /// `RYBOX_ENTITLEMENTS`. That is how an imported app keeps working with
    /// the capabilities it was built for even though the container signs it
    /// with a different identity.
    ///
    /// - Parameter path: absolute path to the guest `.app` bundle.
    public func sign(bundleAt path: String) -> Result<Void, SignError> {
        guard CertificateStore.shared.isConfigured else { return .failure(.notConfigured) }

        // LiveContainer parity: the CodeDirectory identifier of every guest
        // binary is the HOST app's bundle id, because that is the identity the
        // provisioning profile authorises. (ZSign is called with
        // `bundleId: NSBundle.mainBundle.bundleIdentifier` in LCUtils.m.)
        let hostBundleID = Bundle.main.bundleIdentifier ?? ""
        rysign_set_code_identity(hostBundleID)

        let fm = FileManager.default
        let tmp = fm.temporaryDirectory
            .appendingPathComponent("rybox-sign-\(UUID().uuidString)")
        guard (try? fm.createDirectory(at: tmp, withIntermediateDirectories: true)) != nil else {
            return .failure(.stageFailed)
        }

        // 1) stage provisioning
        let provURL = tmp.appendingPathComponent("profile.mobileprovision")
        guard let prov = CertificateStore.shared.provisioningRawData(),
              (try? prov.write(to: provURL)) != nil else { return .failure(.stageFailed) }

        // 2) stage entitlements (from provisioning's embedded Entitlements dict)
        let entsURL = tmp.appendingPathComponent("guest.entitlements.plist")
        let profileEnts = CertificateStore.shared.guestEntitlements() ?? [:]
        EntitlementPolicy.shared.updateProfile(profileEnts)
        if let entsData = try? PropertyListSerialization.data(fromPropertyList: profileEnts,
                                                             format: .xml, options: 0) {
            try? entsData.write(to: entsURL)
        }

        // 3) embed provisioning profile inside the guest bundle
        let embeddedURL = URL(fileURLWithPath: path)
            .appendingPathComponent("embedded.mobileprovision")
        try? prov.write(to: embeddedURL)

        // 4) Build the identity material (leaf cert + private key DER) and the
        //    trust chain, team, and entitlements — all decoded in Swift. The
        //    in-C profile parser cannot read a CMS-wrapped binary plist, so the
        //    Swift side now does the decoding and feeds the signer everything.
        var certDER: Data? = nil
        var keyDER: Data? = nil
        var keyIsEC = false
        if CertificateStore.shared.usesFallbackIdentity,
           let c = CertificateStore.shared.fallbackCertDER(),
           let k = CertificateStore.shared.fallbackKeyDER() {
            RyLog.shared.log("sign  使用内置 PKCS#12 解码器（OpenSSL 3 p12）",
                             level: .info, tag: "sign")
            certDER = c; keyDER = k; keyIsEC = CertificateStore.shared.fallbackKeyIsEC()
        } else if let identity = CertificateStore.shared.identityRef() {
            var cert: SecCertificate? = nil
            SecIdentityCopyCertificate(identity, &cert)
            if let cert = cert { certDER = SecCertificateCopyData(cert) as Data }
            var key: SecKey? = nil
            SecIdentityCopyPrivateKey(identity, &key)
            if let key = key {
                keyDER = SecKeyCopyExternalRepresentation(key, nil) as Data?
                if let attrs = SecKeyCopyAttributes(key) as? [String: Any],
                   let t = attrs[kSecAttrKeyType as String] as? String {
                    keyIsEC = (t == (kSecAttrKeyTypeECSECPrimeRandom as String))
                }
            }
        }
        guard let certDER = certDER, let keyDER = keyDER else {
            return .failure(.stageFailed)
        }

        // 4a) stage leaf cert + key DER (entsURL / profileEnts already staged above)
        let certURL = tmp.appendingPathComponent("cert.der")
        let keyURL = tmp.appendingPathComponent("key.der")
        guard (try? certDER.write(to: certURL)) != nil,
              (try? keyDER.write(to: keyURL)) != nil else { return .failure(.stageFailed) }

        // 4b) team + full cert chain (intermediate + root) from the profile
        let team = CertificateStore.shared.teamIdentifier ?? ""
        let certsDir = tmp.appendingPathComponent("chain")
        try? fm.createDirectory(at: certsDir, withIntermediateDirectories: true)
        if let chain = CertificateStore.shared.provisioningCertificates() {
            for (i, c) in chain.enumerated() {
                try? c.write(to: certsDir.appendingPathComponent("\(i).der"))
            }
        }

        // 4c) delegate Mach-O signing to the robust in-process signer. All profile
        //     material is pre-decoded by Swift; the signer only embeds the profile.
        let rc: Int32 = rysign_sign_bundle_robust(path, certURL.path, keyURL.path,
                                                 keyIsEC ? 1 : 0, provURL.path, entsURL.path,
                                                 team, certsDir.path)
        if rc != 0 {
            return .failure(.signFailed(rc, signFailureReason(rc)))
        }
        return .success(())
    }

    /// Turn a rysign exit code into something a human can act on. The old code
    /// reported the literal string "rysign", which told the user nothing.
    private func signFailureReason(_ rc: Int32) -> String {
        switch rc {
        case 2:  return "读不到 p12 文件"
        case 3:  return "系统无法导入这个 p12（多为 OpenSSL 3 加密），内置解码器也没能解开"
        case 4:  return "读不到描述文件（mobileprovision）"
        case 5:  return "在 App 包里找不到主可执行文件"
        case 6:  return "给主可执行文件签名失败"
        case 7:  return "证书/私钥 DER 无法使用"
        case 8:  return "私钥无法创建（可能不是 RSA，或 DER 损坏）"
        case 9:  return "无法用这把私钥签名（SecKeyCreateSignature 拒绝）——证书可能是 EC，或密钥不受信任"
        default: return "签名器内部错误（rc=\(rc)）"
        }
    }
}
