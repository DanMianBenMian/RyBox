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

        // What are we signing WITH? (subject · key type/bits · scheme). This
        // one line is what turns "rc=8 私钥无法创建" from a mystery into a
        // checkable fact — e.g. "RSA 2048 · PBES2 · AES-256-CBC".
        if let info = CertificateStore.shared.certificateInfo {
            RyLog.shared.log("sign  身份：\(info)", level: .info, tag: "sign")
        }

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
        //
        //    SPECIAL PERMISSIONS ARE STRIPPED HERE (2026-10-25, user-requested
        //    "特殊权限分配"): `platform-application`, `com.apple.private.*`,
        //    `task_for_pid-allow`, … never go into the guest's signature. A
        //    guest runs in-process (dlopen'd into RyBox), so its runtime
        //    entitlement queries are answered by the HOST process — the
        //    special keys would buy it nothing and only risk AMFI rejection.
        //    What was stripped is MARKED in EntitlementPolicy (takenOver) and
        //    re-granted at runtime through the entitlement oracle, where the
        //    user can switch each one on/off per app (Settings → 特殊权限分配).
        //
        //    2026-10-25 (errno=85 fix): the staged plist is NO LONGER embedded
        //    into the guest binaries. RyBox patches every guest Mach-O to
        //    MH_DYLIB before signing (GuestRuntime step 1 patches, step 2
        //    signs), and LiveContainer/zsign leave the entitlements slot EMPTY
        //    for dylibs (`IsExecute() ? m_strEntitleData : ""`). An XML-only
        //    slot 5 with no DER slot 7 sends AMFI down the transmute path,
        //    which refuses dylibs → `code signature invalid (errno=85)`. The
        //    signer now nulls the slot for non-MH_EXECUTE files; the staged
        //    file stays because the policy above still needs `sanitized`, and
        //    because an MH_EXECUTE path would use it.
        let entsURL = tmp.appendingPathComponent("guest.entitlements.plist")
        let profileEnts = CertificateStore.shared.guestEntitlements() ?? [:]
        EntitlementPolicy.shared.updateProfile(profileEnts)
        let sanitized = EntitlementPolicy.sanitizeForSigning(profile: profileEnts)
        if !sanitized.stripped.isEmpty {
            RyLog.shared.log("签名 entitlements 已剥离 \(sanitized.stripped.count) 项特殊权限（由 RyBox 接管分配）：\(sanitized.stripped.joined(separator: ", "))",
                             level: .info, tag: "sign")
        }
        if let entsData = try? PropertyListSerialization.data(fromPropertyList: sanitized.signed,
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
        /// When a real SecIdentity exists we hand its SecKey STRAIGHT to the
        /// signer. Rebuilding it inside the signer from raw DER
        /// (`SecKeyCopyExternalRepresentation` → `SecKeyCreateWithData`) is the
        /// step that actually broke on device: the reconstructed SecKey comes
        /// back unable to perform the signature algorithm the certificate needs,
        /// so `SecKeyCreateSignature` refuses — identically for a development
        /// AND a distribution certificate (which is exactly what the user's
        /// log showed: both rejected, sub-code -5).
        var liveKey: SecKey? = nil
        if let identity = CertificateStore.shared.identityRef() {
            var key: SecKey? = nil
            let st = SecIdentityCopyPrivateKey(identity, &key)
            if st == errSecSuccess, let key = key {
                liveKey = key
                var cert: SecCertificate? = nil
                SecIdentityCopyCertificate(identity, &cert)
                if let cert = cert {
                    certDER = SecCertificateCopyData(cert) as Data
                    if let attrs = SecKeyCopyAttributes(key) as? [String: Any],
                       let t = attrs[kSecAttrKeyType as String] as? String {
                        keyIsEC = (t == (kSecAttrKeyTypeECSECPrimeRandom as String))
                    }
                }
                RyLog.shared.log("sign  使用系统 SecIdentity 私钥（不经 DER 重建）",
                                 level: .info, tag: "sign")
            } else {
                RyLog.shared.log("sign  ⚠ SecIdentityCopyPrivateKey 失败 osstatus=\(st)，回退到 DER 重建路径",
                                 level: .warn, tag: "sign")
            }
        }
        if liveKey == nil {
            if CertificateStore.shared.usesFallbackIdentity,
               let c = CertificateStore.shared.fallbackCertDER(),
               let k = CertificateStore.shared.fallbackKeyDER() {
                RyLog.shared.log("sign  使用内置 PKCS#12 解码器（OpenSSL 3 p12）",
                                 level: .info, tag: "sign")
                certDER = c; keyDER = k; keyIsEC = CertificateStore.shared.fallbackKeyIsEC()
                // The DER → SecKey round-trip INSIDE the signer is the weakest
                // link in the whole chain: on the device (iPadOS 27 beta,
                // rc=8) every reading of the decoded key bytes was refused by
                // SecKeyCreateWithData. The keychain route produces a REAL
                // SecKey through a different Security code path, which lets us
                // skip that reconstruction entirely and use the proven
                // `rysign_sign_bundle_with_key` entry.
                if let kc = CertificateStore.shared.fallbackSecKey() {
                    liveKey = kc
                }
            } else if let identity = CertificateStore.shared.identityRef() {
                // Second chance: no live SecKey could be extracted, so fall back
                // to the historical external-representation round-trip. Less
                // reliable, but better than refusing to sign at all.
                RyLog.shared.log("sign  ⚠ 回退到 DER 私钥重建路径（可靠性较低）",
                                 level: .warn, tag: "sign")
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
        }
        guard let certDER = certDER else {
            RyLog.shared.log("sign  拿不到叶子证书（\(liveKey == nil ? "DER 路径" : "SecIdentity 路径")）",
                             level: .error, tag: "sign")
            return .failure(.stageFailed)
        }
        if liveKey == nil && keyDER == nil {
            RyLog.shared.log("sign  拿不到私钥", level: .error, tag: "sign")
            return .failure(.stageFailed)
        }

        // 4a) stage leaf cert (+ key DER when we actually need to rebuild it)
        let certURL = tmp.appendingPathComponent("cert.der")
        guard (try? certDER.write(to: certURL)) != nil else { return .failure(.stageFailed) }
        let keyURL = tmp.appendingPathComponent("key.der")
        if let k = keyDER {
            // Hand the signer the FULL PKCS#8 when we have it. Its
            // `create_signing_key` tries the whole blob AND the PKCS#1/SEC1
            // inner (`pkcs8_inner`), so both Security readings get a turn —
            // but only if the wrapper is actually there. We used to stage the
            // inner alone, which is how a PKCS#8-friendly Security build would
            // still end up with rc=8 "私钥无法创建".
            let staged = CertificateStore.shared.fallbackKeyPKCS8DER() ?? k
            guard (try? staged.write(to: keyURL)) != nil else { return .failure(.stageFailed) }
        }

        // 4b) team + full cert chain (intermediate + root) — ordered so the
        //     WWDR intermediate lands at CMS slot 1 (the DR requires
        //     `certificate 1[1.2.840.113635.100.6.2.1 exists]`). The leaf is
        //     written separately (cert.der) and prepended as slot 0 by the
        //     signer, so this set holds only the intermediates/root.
        let team = CertificateStore.shared.teamIdentifier ?? ""
        if team.isEmpty {
            // The team id ends up in the guest's CodeDirectory (teamOffset),
            // and it is the ONLY thing library validation compares against
            // the host's. An empty team ⇒ no team id in the CodeDirectory ⇒
            // the "same team" route can never match, so the guest is refused
            // with errno=85 no matter how perfect the signature is.
            //
            // The team normally comes from the imported certificate's Subject
            // OU (see CertificateStore.captureTeamFromCertificate); it is
            // empty only when the p12 could not be parsed far enough to read
            // its leaf certificate. Say so loudly — this is invisible in the
            // errno otherwise.
            RyLog.shared.log("sign  ⚠ 签名身份里没有 team id —— guest 的 CodeDirectory 将不包含 team，"
                             + "AMFI 的库验证一定不通过（errno=85）。请确认 p12 导入成功且叶子证书可读。",
                             level: .error, tag: "sign")
        }
        let certsDir = tmp.appendingPathComponent("chain")
        try? fm.createDirectory(at: certsDir, withIntermediateDirectories: true)
        let chain = CertificateStore.shared.signingIntermediateCertificates()
        for (i, c) in chain.enumerated() {
            try? c.write(to: certsDir.appendingPathComponent("\(i).der"))
        }
        if !chain.isEmpty {
            // Slot 1 (chain[0]) is the WWDR intermediate we selected to match the
            // leaf's issuer. Log its subject so a re-test can confirm we embedded
            // G6 (not the old hardcoded G3) — the errno=1 fix.
            let slot1Summary: String = {
                guard let cert = SecCertificateCreateWithData(nil, chain[0] as CFData) else { return "?" }
                return (SecCertificateCopySubjectSummary(cert) as? String) ?? "?"
            }()
            RyLog.shared.log("sign  证书链：\(chain.count) 张中间/根证书；slot 1 = \(slot1Summary)",
                             level: .info, tag: "sign")
        } else {
            RyLog.shared.log("sign  ⚠ 证书链为空：CMS 将只有叶子证书，DR 的 slot 1(WWDR) 校验会失败 → errno=85。请确认 p12 含完整链或由系统信任库提供。",
                             level: .warn, tag: "sign")
        }

        // 4c) delegate Mach-O signing to the robust in-process signer. All profile
        //     material is pre-decoded by Swift; the signer only embeds the profile.
        //
        //     Two entries, in order of preference:
        //       * `rysign_sign_bundle_with_key` — hands over the LIVE SecKey we
        //         got from the SecIdentity. No key reconstruction inside the
        //         signer, which is the path the device proved works... and the
        //         one it never got to use before.
        //       * `rysign_sign_bundle_robust` — rebuilds the private key from
        //         raw DER (only when no SecKey could be extracted).
        let rc: Int32
        if let key = liveKey {
            rc = rysign_sign_bundle_with_key(path, key, certURL.path, provURL.path,
                                             entsURL.path, team, certsDir.path)
        } else {
            rc = rysign_sign_bundle_robust(path, certURL.path, keyURL.path,
                                           keyIsEC ? 1 : 0, provURL.path, entsURL.path,
                                           team, certsDir.path)
        }
        if rc != 0 {
            // rc=6 ("sign the main executable failed") covers a dozen internal
            // causes; the signer keeps the precise one in rysign_last_subcode().
            let detail = signFailureReason(rc)
            // The raw OSStatus and the signer's own one-liner are what turn a
            // three-build-cycle mystery into one log line.
            let os = rysign_last_osstatus()
            let diag = diagString()
            if os != 0 || !diag.isEmpty {
                RyLog.shared.log("rysign osstatus=\(os) diag=\(diag)",
                                 level: .error, tag: "sign")
            }
            if rc == 6 {
                let sub = rysign_last_subcode()
                RyLog.shared.log("rysign 子码 \(sub)：\(subcodeReason(sub))",
                                 level: .error, tag: "sign")
                return .failure(.signFailed(rc, detail + "（\(subcodeReason(sub))）"))
            }
            if rc == 11 {
                // rc=11 IS the self-verify verdict — surface it to the user
                // instead of a bare "internal error". The diag carries the
                // CMS algorithm note first and the verdict after a "｜".
                let parts = diag.split(separator: "｜", omittingEmptySubsequences: false)
                if let verdict = parts.last, !verdict.isEmpty {
                    return .failure(.signFailed(rc, detail + "：" + verdict))
                }
            }
            return .failure(.signFailed(rc, detail))
        }
        // On success the signer records WHICH of the four algorithm variants
        // actually worked — the fastest way to stop guessing next time.
        let win = diagString()
        if !win.isEmpty {
            RyLog.shared.log("sign  签名成功：\(win)", level: .info, tag: "sign")
        }
        return .success(())
    }

    /// The signer's one-line diagnosis of the last failure (UTF-8 static buffer).
    private func diagString() -> String {
        guard let p = rysign_last_diag() else { return "" }
        let s = String(cString: p)
        return s.isEmpty ? "" : s
    }

    /// Turn a rysign internal sub-code into something a human can act on.
    private func subcodeReason(_ sub: Int32) -> String {
        switch sub {
        case -1:  return "主可执行文件读不出来或不完整"
        case -2:  return "二进制没有 LC_CODE_SIGNATURE，且头部没有空间补一个"
        case -3:  return "Requirements 构件失败"
        case -4:  return "CodeDirectory 构件失败"
        case -5:  return "CMS 签名失败：系统拒绝用这把私钥签名（多为 EC/RSA 类型不匹配或密钥不可用，见日志里的 osstatus）"
        case -6:  return "SuperBlob 组装失败"
        case -7:  return "写签名时内存不足"
        case -8:  return "主可执行文件路径不是普通文件"
        case -9:  return "主可执行文件不是 arm64 64 位 Mach-O"
        case -10: return "签名写回磁盘失败"
        default:  return "内部错误（子码 \(sub)）"
        }
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
        case 11: return "签名自检未通过：签完的 guest 签名内部不一致（team / 页哈希 / CMS），已拦截 dlopen"
        case 13: return "签名自检未通过：CMS 槽缺少 FADE0B01 BlobWrapper 头（格式错，内核会以 errno=85 拒签）"
        case 14: return "签名自检未通过：CMS 载荷不是合法的 DER SignedData"
        case 15: return "签名自检未通过：备用(SHA-256)CodeDirectory 的页哈希与磁盘字节不符（amfid 的 cdhashes 校验会拒签）"
        default: return "签名器内部错误（rc=\(rc)）"
        }
    }
}
