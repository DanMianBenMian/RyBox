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

        // 4) delegate Mach-O signing to the bundled on-device signer (in-process).
        //    Prefer the decoded-DER entry whenever the p12 needed RyBox's own
        //    decoder; that path does not depend on SecPKCS12Import at all.
        var rc: Int32 = -1
        if CertificateStore.shared.usesFallbackIdentity,
           let cert = CertificateStore.shared.fallbackCertDER(),
           let key = CertificateStore.shared.fallbackKeyDER() {
            let certURL = tmp.appendingPathComponent("cert.der")
            let keyURL = tmp.appendingPathComponent("key.der")
            guard (try? cert.write(to: certURL)) != nil,
                  (try? key.write(to: keyURL)) != nil else { return .failure(.stageFailed) }
            RyLog.shared.log("sign  使用内置 PKCS#12 解码器（OpenSSL 3 p12）",
                             level: .info, tag: "sign")
            rc = rysign_sign_bundle_with_der(path, certURL.path, keyURL.path,
                                             CertificateStore.shared.fallbackKeyIsEC() ? 1 : 0,
                                             provURL.path, entsURL.path)
        } else {
            // Legacy-encrypted p12: SecPKCS12Import can open it, so stage the
            // raw bytes + password and let C import them.
            let p12URL = tmp.appendingPathComponent("id.p12")
            guard let p12 = CertificateStore.shared.p12RawData(),
                  let pw = CertificateStore.shared.p12Passphrase(),
                  (try? p12.write(to: p12URL)) != nil else { return .failure(.stageFailed) }
            rc = rysign_sign_bundle(path, p12URL.path, pw, provURL.path, entsURL.path)
            // Belt and braces: if C's importer refused a file Swift's importer
            // accepted (or vice versa), retry through the decoder material.
            if rc == 3, let cert = CertificateStore.shared.fallbackCertDER(),
               let key = CertificateStore.shared.fallbackKeyDER() {
                let certURL = tmp.appendingPathComponent("cert.der")
                let keyURL = tmp.appendingPathComponent("key.der")
                if (try? cert.write(to: certURL)) != nil, (try? key.write(to: keyURL)) != nil {
                    RyLog.shared.log("sign  SecPKCS12Import 失败，回退到内置解码器",
                                     level: .warn, tag: "sign")
                    rc = rysign_sign_bundle_with_der(path, certURL.path, keyURL.path,
                                                     CertificateStore.shared.fallbackKeyIsEC() ? 1 : 0,
                                                     provURL.path, entsURL.path)
                }
            }
        }
        if rc != 0 {
            return .failure(.signFailed(rc, signFailureReason(rc)))
        }
        verifySignature(bundleAt: path, hostBundleID: hostBundleID)
        return .success(())
    }

    /// LiveContainer calls `checkCodeSignature()` after signing and refuses to
    /// hand the app to dlopen when it fails. RyBox logs the same check: the
    /// result is the only way to tell "the signer ran" from "the signer
    /// produced something AMFI will accept", and a silent failure here is
    /// indistinguishable from a black screen later.
    private func verifySignature(bundleAt path: String, hostBundleID: String) {
        let exe = URL(fileURLWithPath: path).appendingPathComponent(mainExecutableName(in: path))
        var code: SecStaticCode?
        // `SecCSFlags` is imported either as a UInt32 typealias or as an
        // OptionSet depending on the SDK, so both values below are built from
        // constants the SDK itself declares. `SecStaticCodeCreateWithPath` only
        // honours kSecCSInternalInformation (which we do NOT want), so the
        // check flag is harmless there and equivalent to "default".
        let createFlags = kSecCSCheckAllArchitectures
        guard SecStaticCodeCreateWithPath(exe as CFURL, createFlags, &code) == errSecSuccess,
              let code = code else {
            RyLog.shared.log("sign  签名后校验：无法读取已签名的主可执行文件", level: .warn, tag: "sign")
            return
        }
        let status = SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures, nil)
        if status == errSecSuccess {
            RyLog.shared.log("sign  签名后校验通过（标识符 \(hostBundleID)）", level: .info, tag: "sign")
        } else {
            RyLog.shared.log("sign  签名后校验未通过（OSStatus \(status)）——dlopen 时可能被 AMFI 拒绝",
                             level: .warn, tag: "sign")
        }
    }

    /// The guest's `CFBundleExecutable`, read straight out of its Info.plist.
    private func mainExecutableName(in bundlePath: String) -> String {
        let plist = URL(fileURLWithPath: bundlePath).appendingPathComponent("Info.plist")
        guard let data = try? Data(contentsOf: plist),
              let dict = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                    as? [String: Any],
              let name = dict["CFBundleExecutable"] as? String, !name.isEmpty else {
            return ""
        }
        return name
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
