import Foundation
import Security

/// `Result`'s Failure must conform to `Error`, but every failure in this module
/// is just a sentence for the user. This wrapper keeps `Result<Void,
/// RyMessageError>` type-correct while still allowing `.failure("…")` — a bare
/// `String` would not compile here.
public struct RyMessageError: LocalizedError, ExpressibleByStringLiteral {
    public let message: String
    public init(_ message: String) { self.message = message }
    public init(stringLiteral value: String) { self.message = value }
    public var errorDescription: String? { message }
    public var localizedDescription: String { message }
}

/// Holds the user-imported signing identity + provisioning profile.
/// Supports BOTH development and DISTRIBUTION certificates (Ad Hoc / Enterprise).
/// Distribution certs lack get-task-allow (no JIT) — acceptable for a runtime env.
///
/// Persistence: the raw p12 bytes, the provisioning profile and the p12 password
/// are written to a private `Application Support/RyBoxKeys` directory so the
/// configuration survives a relaunch. On launch (`init`) they are re-read and
/// re-imported, which re-populates the in-memory `identity` / `p12VerifiedByFallback`
/// / `certificateInfo` / `teamIdentifier` / `isConfigured` — previously those were
/// in-memory only, so re-entering the app "lost" the certificate and the boot gate
/// refused to proceed.
public final class CertificateStore: ObservableObject {
    public static let shared = CertificateStore()

    private let fileManager = FileManager.default

    /// Private, sandboxed directory for the signing material.
    private var keysDir: URL {
        fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("RyBoxKeys", isDirectory: true)
    }

    private var identity: SecIdentity?
    /// True when SecPKCS12Import couldn't read the file but RyP12 did. In that
    /// mode there is no SecIdentity object, but nothing needs one: CodeSigner
    /// only stages the p12 bytes + password for the bundled helper, and the
    /// parser already proved the passphrase and the private key are real.
    private var p12VerifiedByFallback = false
    /// Decoded identity material for the fallback path. Kept because the C
    /// signer needs a leaf certificate + private key, and in fallback mode the
    /// ONLY way to get them is our own decoder — `SecPKCS12Import` (which the
    /// signer used to call) cannot read the file at all.
    ///
    /// NOTE the names: the public accessors below are `fallbackCertDER()` /
    /// `fallbackKeyDER()`, and Swift forbids a stored property and a method
    /// sharing a name — hence the different spelling here.
    private var decodedCert: Data?
    private var decodedKey: Data?
    /// The FULL PKCS#8 `PrivateKeyInfo` (wrapper included) — the form the
    /// keychain importer and the signer's whole-blob attempt both want. See
    /// `RyP12.Outcome.keyPKCS8`.
    private var decodedKeyPKCS8: Data?
    private var fallbackKeyType: String = "rsa"
    private var provisioningData: Data?
    /// Raw p12 bytes (kept so CodeSigner can stage them for the bundled helper).
    private var p12Data: Data?
    private var p12Password: String?

    @Published public private(set) var isConfigured: Bool = false
    /// Team id extracted from the provisioning profile (e.g. "ABCDE12345").
    @Published public private(set) var teamIdentifier: String?
    /// Human readable "what we actually imported" line, shown in the UI.
    @Published public private(set) var certificateInfo: String?

    private init() {
        load()
    }

    /// Import a .p12 / .pfx (distribution or development) using its password.
    ///
    /// Real-world certificate files fail here for three very different reasons,
    /// so the failure is diagnosed instead of just returning false:
    ///   * the user has a .cer (public cert only — no private key),
    ///   * the file is PEM text instead of DER,
    ///   * the p12 uses the modern OpenSSL 3 encryption (AES-256-CBC + PBKDF2)
    ///     that iOS's SecPKCS12Import cannot read at all.
    /// The empty passphrase is tried as a fallback because a lot of
    /// distribution p12 files simply have none.
    public func importP12(_ data: Data, password: String) -> Result<Void, RyMessageError> {
        guard !data.isEmpty else { return .failure("文件是空的（0 字节）") }

        var candidates = [password]
        if !password.isEmpty { candidates.append("") }
        if password.isEmpty { candidates.append("") }
        candidates = Array(NSOrderedSet(array: candidates).array.compactMap { $0 as? String })

        var lastStatus: OSStatus = errSecSuccess
        for pw in candidates {
            let opts = [kSecImportExportPassphrase as String: pw] as CFDictionary
            var items: CFArray?
            let status = SecPKCS12Import(data as CFData, opts, &items)
            if status != errSecSuccess {
                lastStatus = status
                continue
            }
            guard let items = items,
                  let first = (items as NSArray).firstObject as? NSDictionary,
                  let raw = first[kSecImportItemIdentity as String] else {
                lastStatus = errSecParam
                continue
            }
            // A conditional downcast to a CoreFoundation type always
            // "succeeds", so Swift rejects `as? SecIdentity`. Verify the type
            // ID instead, then bridge — that actually catches a malformed p12.
            guard CFGetTypeID(raw as CFTypeRef) == SecIdentityGetTypeID() else {
                lastStatus = errSecParam
                continue
            }
            self.identity = (raw as! SecIdentity)
            self.p12VerifiedByFallback = false
            self.decodedCert = nil
            self.decodedKey = nil
            self.decodedKeyPKCS8 = nil
            self.p12Data = data
            self.p12Password = pw
            self.certificateInfo = Self.describe(identity: self.identity)
            refresh()
            save()
            return .success(())
        }

        // ---- fallback -----------------------------------------------------
        // SecPKCS12Import gave up. The overwhelmingly common cause is an
        // OpenSSL 3.x p12 (PBES2/AES-256-CBC/PBKDF2-SHA256) — Apple's importer
        // predates that. Parse it ourselves instead of sending the user away.
        var lastFallback = ""
        for pw in candidates {
            switch RyP12.decode(data, password: pw) {
            case .success(let o):
                self.identity = nil
                self.p12VerifiedByFallback = true
                self.decodedCert = o.certDER
                self.decodedKey = o.keyDER
                self.decodedKeyPKCS8 = o.keyPKCS8
                self.fallbackKeyType = o.keyType
                // A DIFFERENT p12 means a DIFFERENT key: drop the keychain item
                // left by the previous import, or the SecItemAdd later (same
                // application tag) would fail with a duplicate-item error and
                // the new key could never be imported. Replaying the SAME bytes
                // (every launch does, via load()) keeps the item — it is still
                // the same key.
                if self.p12Data != data {
                    Self.deleteFallbackKeychainItem()
                }
                self.p12Data = data
                self.p12Password = o.password
                self.certificateInfo = "\(o.subject) · \(o.keyDescription) · \(o.scheme)"
                refresh()
                save()
                return .success(())
            case .failure(let m):
                if lastFallback.isEmpty { lastFallback = m.message }
            }
        }
        // Prefer the built-in decoder's reason: it knows far more about the
        // actual bytes than a bare OSStatus does.
        let fallbackHint = lastFallback.isEmpty
            ? "" : "\n（RyBox 内置解码器：\(lastFallback)）"
        return .failure(RyMessageError(Self.diagnoseP12(data, status: lastStatus,
                                         password: password) + fallbackHint))
    }

    private static func describe(identity: SecIdentity?) -> String {
        guard let identity = identity else { return "证书已导入" }
        var cert: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &cert) == errSecSuccess,
              let cert = cert else { return "证书已导入" }
        let subject = (SecCertificateCopySubjectSummary(cert) as? String) ?? "证书"
        return "\(subject) · 系统钥匙串已接受"
    }

    /// Import a .mobileprovision (embedded entitlements are read from it).
    public func importProvisioning(_ data: Data) -> Result<Void, RyMessageError> {
        guard !data.isEmpty else { return .failure("文件是空的（0 字节）") }
        self.provisioningData = data
        guard let plist = provisioningPlist() else {
            self.provisioningData = nil
            refresh()
            save()
            return .failure("不是有效的描述文件：里面没有找到 plist。请确认选的是 .mobileprovision（不是 .cer/.p12）。")
        }
        if let teams = plist["TeamIdentifier"] as? [String], let t = teams.first {
            teamIdentifier = t
        }
        refresh()
        save()
        return .success(())
    }

    // MARK: - Diagnostics

    /// Tell the user WHY their certificate file was rejected (and how to fix it).
    private static func diagnoseP12(_ data: Data, status: OSStatus, password: String) -> String {
        if let text = String(data: data.prefix(256), encoding: .utf8),
           text.contains("BEGIN CERTIFICATE") || text.contains("BEGIN RSA PRIVATE KEY") {
            return "这是 PEM 文本格式，iOS 需要 PKCS#12（.p12）。用 openssl 转换：\nopenssl pkcs12 -export -legacy -inkey key.pem -in cert.pem -out cert.p12"
        }
        if let text = String(data: data.prefix(4096), encoding: .isoLatin1),
           text.contains("<?xml") || text.contains("mobileprovision") {
            return "这个文件是描述文件（mobileprovision），请放到「描述文件」那一栏，证书栏要选 p12。"
        }
        if data.prefix(2) == Data("PK".utf8) {
            return "这是 zip/IPA 文件，不是证书。"
        }
        if data.first == 0x30 {
            // DER. A lone certificate still parses as one; a p12 will not.
            if SecCertificateCreateWithData(nil, data as CFData) != nil {
                return "这是 .cer 公钥证书，里面没有私钥，无法用来签名。请在钥匙串里把「证书 + 私钥」一起导出为 .p12（或 .pfx）。"
            }
            let hint = password.isEmpty
                ? "（密码留空）若这个 p12 设了密码，请填上。"
                : "密码可能不对。"
            return "PKCS#12 解析失败：\(hint) RyBox 已用内置解码器重试过（支持 OpenSSL 3 的 PBES2/AES-256-CBC 等新式加密），仍然失败。若你有原始的 key.pem + cert.pem，可用旧式加密重新导出：\nopenssl pkcs12 -export -legacy -inkey key.pem -in cert.pem -out cert.p12\n（错误码 \(status)）"
        }
        return "无法识别的文件格式（前几字节：\(data.prefix(4).map { String(format: "%02x", $0) }.joined(separator: " "))）。需要 p12/pfx。"
    }

    private func refresh() {
        isConfigured = ((identity != nil || p12VerifiedByFallback) && provisioningData != nil)
    }

    // MARK: - Accessors used by CodeSigner

    public func identityRef() -> SecIdentity? { identity }
    public func p12RawData() -> Data? { p12Data }
    public func p12Passphrase() -> String? { p12Password }
    public func provisioningRawData() -> Data? { provisioningData }

    /// True when the p12 could only be opened by RyBox's own decoder (OpenSSL 3
    /// PBES2/AES-256-CBC files). In that mode the signer MUST take the DER path.
    public var usesFallbackIdentity: Bool { p12VerifiedByFallback }
    public func fallbackCertDER() -> Data? { decodedCert }
    public func fallbackKeyDER() -> Data? { decodedKey }
    public func fallbackKeyPKCS8DER() -> Data? { decodedKeyPKCS8 }
    public func fallbackKeyIsEC() -> Bool { fallbackKeyType == "ec" }

    // MARK: - Fallback identity → a REAL SecKey (keychain route)

    /// Stable keychain tag for the fallback private key. Kept across launches so
    /// the key is imported once and simply looked up afterwards.
    ///
    /// Stored as CFData (UTF-8 bytes), not CFString: the keychain normalises
    /// string attributes in ways that differ between the add and the query side,
    /// which silently breaks the match-up. Bytes are bytes.
    private static let fallbackKeyTag = "rybox.signing.fallback.key.v1".data(using: .utf8)!

    private var fallbackKeyTypeCF: CFString {
        fallbackKeyType == "ec" ? kSecAttrKeyTypeECSECPrimeRandom : kSecAttrKeyTypeRSA
    }

    /// A usable `SecKeyRef` for the fallback-decoded key — WITHOUT ever calling
    /// `SecKeyCreateWithData`.
    ///
    /// Why this exists: on the device (iPadOS 27 beta, rc=8) every reading of
    /// the decoded key bytes — PKCS#1 inner, full PKCS#8, RSA type, EC type —
    /// was refused by `SecKeyCreateWithData`, and the CFError that would have
    /// explained why was discarded at two separate call sites. The keychain
    /// import route (`SecItemAdd` with `kSecClassKey`) is a different Security
    /// code path that historically accepts private-key blobs the direct
    /// constructor rejects, and the resulting key is a REAL, keychain-backed
    /// key that can sign CMS directly — the same shape `rysign_sign_bundle_with_key`
    /// wants.
    ///
    /// Order: (1) an item already in the keychain under our tag, (2) import the
    /// full PKCS#8, (3) import the inner PKCS#1/SEC1 key. Returns nil when all
    /// three fail (the caller then falls back to raw DER for the C signer).
    public func fallbackSecKey() -> SecKey? {
        guard p12VerifiedByFallback else { return nil }

        // (1) Already imported?
        if let existing = Self.copyFallbackKeychainRef(type: fallbackKeyTypeCF) {
            return existing
        }
        // (2)+(3) Import. PKCS#8 first: it is the form Apple's own import
        // samples use, and the p12 key bag stored exactly that.
        let blobs: [Data] = [decodedKeyPKCS8, decodedKey].compactMap { $0 }
        for blob in blobs {
            let add: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeyType as String: fallbackKeyTypeCF,
                kSecAttrApplicationTag as String: Self.fallbackKeyTag,
                // The key must be readable when RyBox signs a guest, which
                // happens after the device has been unlocked at least once.
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
                kSecValueData as String: blob
            ]
            let st = SecItemAdd(add as CFDictionary, nil)
            RyLog.shared.log("sign  钥匙串导入私钥（\(blob.count) 字节）→ osstatus=\(st)",
                             level: st == errSecSuccess ? .info : .warn, tag: "sign")
            if st == errSecSuccess {
                if let k = Self.copyFallbackKeychainRef(type: fallbackKeyTypeCF) {
                    RyLog.shared.log("sign  私钥已进入系统钥匙串，改用活 SecKey 签名路径", level: .info, tag: "sign")
                    return k
                }
            }
        }
        return nil
    }

    private static func copyFallbackKeychainRef(type: CFString) -> SecKey? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: fallbackKeyTag,
            kSecAttrKeyType as String: type,
            kSecReturnRef as String: true
        ]
        var ref: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &ref) == errSecSuccess,
              let ref = ref else { return nil }
        // Same CoreFoundation downcast rule as SecIdentity: verify the type ID
        // before bridging, or a wrong-typed item becomes a crash later.
        guard CFGetTypeID(ref) == SecKeyGetTypeID() else { return nil }
        return (ref as! SecKey)
    }

    private static func deleteFallbackKeychainItem() {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: fallbackKeyTag
        ]
        SecItemDelete(q as CFDictionary)
    }

    /// Decode the provisioning profile into its outer dict.
    ///
    /// A real `.mobileprovision` is a CMS `SignedData` whose *content* is a
    /// binary property list — there is no `<?xml`/`</plist>` text in the bytes,
    /// so the old ASCII-slice approach returned `nil` for every genuine profile
    /// (which also blocked the boot gate). We unwrap the CMS ourselves (the
    /// `CMSDecoder` API is macOS-only and absent from the iOS SDK), then let
    /// `PropertyListSerialization` parse either XML or binary form.
    public func provisioningPlist() -> [String: Any]? {
        guard let data = provisioningData else { return nil }
        let plistData: Data
        if data.first == 0x30 {
            // Looks like DER (a CMS envelope). Try to unwrap it.
            plistData = Self.unwrapCMS(data) ?? data
        } else {
            // Plain XML/binary plist (0x3C '<?' or 0x62 'bplist00').
            plistData = data
        }
        return (try? PropertyListSerialization.propertyList(from: plistData,
                options: [], format: nil)) as? [String: Any]
    }

    /// Unwrap a CMS `SignedData` and return its encapsulated content (the inner
    /// plist). Returns `nil` if `data` is not a readable CMS message.
    ///
    /// ## Why not `CMSDecoder`
    ///
    /// `CMSDecoder` is a **macOS-only** API — Apple's own header annotates it
    /// "macOS 10.5+" and the symbol does not exist in the iOS SDK, so calling it
    /// simply fails to compile for the iOS target. A genuine `.mobileprovision`
    /// is a CMS `SignedData` whose content is a *binary* property list, so the
    /// decoder is the only way to reach the profile's `Entitlements` and
    /// `DeveloperCertificates`.
    ///
    /// So we unwrap it ourselves. The walk is:
    ///
    ///     ContentInfo ::= SEQUENCE {
    ///       contentType  OBJECT IDENTIFIER,          -- 1.2.840.113549.1.7.2 (signedData)
    ///       content     [0] EXPLICIT SignedData }
    ///     SignedData ::= SEQUENCE {
    ///       version, digestAlgorithms, encapContentInfo, ... }
    ///     EncapsulatedContentInfo ::= SEQUENCE {
    ///       eContentType OBJECT IDENTIFIER,          -- 1.2.840.113549.1.7.1 (data)
    ///       eContent    [0] EXPLICIT OCTET STRING }  -- <- the plist bytes
    ///
    /// Only the *content* is needed — the signature is not verified here. The
    /// profile's authenticity is established by the platform itself (the
    /// certificate chain is checked when the profile is embedded and used).
    private static func unwrapCMS(_ data: Data) -> Data? {
        let r = RyASN1.Reader(data)
        guard let top = r.at(0), top.tag == RyASN1.SEQUENCE else { return nil }
        let topKids = r.children(top)
        guard topKids.count >= 2, topKids[0].tag == RyASN1.OID else { return nil }

        // contentType must be signedData (1.2.840.113549.1.7.2).
        guard RyASN1.oidString(topKids[0], r) == oidSignedData else { return nil }

        // content [0] EXPLICIT -> SignedData.
        // NOTE: topKids[1] IS the [0] wrapper; its first child is the SignedData
        // SEQUENCE. The previous code asserted the *child's* tag == 0xA0, but the
        // child is a 0x30 SEQUENCE — so unwrapCMS always returned nil and every
        // real profile was rejected as "无法识别". Check the wrapper, then descend.
        guard topKids[1].tag == 0xA0,
              let signedData = r.children(topKids[1]).first,
              signedData.tag == RyASN1.SEQUENCE else { return nil }

        // SignedData children: version, digestAlgorithms, encapContentInfo,
        // [certificates], [crls], signerInfos. Locate encapContentInfo by its
        // `data` OID instead of hardcoding index 2, so an optional field or a
        // slightly different encoding can't break the walk.
        var encap: RyASN1.Element?
        for kid in r.children(signedData) {
            guard kid.tag == RyASN1.SEQUENCE else { continue }
            let ek = r.children(kid)
            guard ek.count >= 1, ek[0].tag == RyASN1.OID,
                  RyASN1.oidString(ek[0], r) == oidData else { continue }
            encap = kid
            break
        }
        guard let encapInfo = encap else { return nil }
        let encapKids = r.children(encapInfo)
        guard encapKids.count >= 2 else { return nil }
        // eContentType must already be `data` (matched above); eContent [0] EXPLICIT.
        guard encapKids[1].tag == 0xA0,
              let ec = r.children(encapKids[1]).first else { return nil }

        // eContent is an OCTET STRING — primitive (0x04) normally, constructed
        // (0x24) for large payloads. Concatenate segments in the latter case.
        if ec.tag == RyASN1.OCTET_STRING {
            return Data(r.slice(ec))
        } else if ec.tag == 0x24 {
            var out = Data()
            for seg in r.children(ec) where seg.tag == RyASN1.OCTET_STRING {
                out.append(Data(r.slice(seg)))
            }
            return out.isEmpty ? nil : out
        }
        return nil
    }

    private static let oidSignedData = "1.2.840.113549.1.7.2"
    private static let oidData = "1.2.840.113549.1.7.1"

    /// Entitlements to apply to a guest: taken from the provisioning profile's
    /// embedded `Entitlements` dict. This already contains application-identifier
    /// (TEAMID.com.rybox.ios), get-task-allow=false, keychain-access-groups, etc.
    /// AMFI validates the guest's signature against exactly this set.
    public func guestEntitlements() -> [String: Any]? {
        guard let plist = provisioningPlist() else { return nil }
        return plist["Entitlements"] as? [String: Any]
    }

    /// The `DeveloperCertificates` array from the profile — DER-encoded X.509
    /// certificates forming the trust chain (leaf, intermediate, root). Swift
    /// decodes them so the signer can embed the FULL chain; AMFI needs it to
    /// validate the guest signature (a leaf-only CMS fails trust evaluation).
    public func provisioningCertificates() -> [Data]? {
        guard let plist = provisioningPlist() else { return nil }
        return plist["DeveloperCertificates"] as? [Data]
    }

    // MARK: - Persistence

    /// Persist the raw signing material so it survives a relaunch. The p12 holds
    /// the private key, so the directory is inside the app sandbox
    /// (Application Support) — only this app can read it.
    private func save() {
        do {
            try fileManager.createDirectory(at: keysDir, withIntermediateDirectories: true)
            if let d = p12Data { try? d.write(to: keysDir.appendingPathComponent("id.p12")) }
            if let d = provisioningData { try? d.write(to: keysDir.appendingPathComponent("profile.mobileprovision")) }
            let meta = ["password": p12Password ?? ""]
            if let data = try? PropertyListSerialization.data(fromPropertyList: meta,
                                                             format: .xml, options: 0) {
                try? data.write(to: keysDir.appendingPathComponent("meta.plist"))
            }
        } catch {
            // Persistence is best-effort; an in-memory session still works.
        }
    }

    /// Reload a previously saved configuration on launch. Re-importing from the
    /// stored bytes rebuilds every in-memory field, so the boot gate and the
    /// signer see exactly the same state as when the user first imported.
    private func load() {
        let p12URL = keysDir.appendingPathComponent("id.p12")
        let provURL = keysDir.appendingPathComponent("profile.mobileprovision")
        guard fileManager.fileExists(atPath: p12URL.path),
              fileManager.fileExists(atPath: provURL.path) else { return }
        guard let p12 = try? Data(contentsOf: p12URL),
              let prov = try? Data(contentsOf: provURL) else { return }
        let pw: String = {
            guard let data = try? Data(contentsOf: keysDir.appendingPathComponent("meta.plist")),
                  let dict = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                    as? [String: Any],
                  let p = dict["password"] as? String else { return "" }
            return p
        }()
        _ = importP12(p12, password: pw)
        _ = importProvisioning(prov)
    }

    /// Wipe the saved signing material (used if the user wants to reconfigure).
    public func reset() {
        identity = nil
        p12VerifiedByFallback = false
        decodedCert = nil
        decodedKey = nil
        decodedKeyPKCS8 = nil
        // The keychain copy of the fallback key must go too: it is tagged, and
        // a re-import replaces the tag's key — but a reset that left it behind
        // would let the NEXT import find the PREVIOUS identity's key.
        Self.deleteFallbackKeychainItem()
        fallbackKeyType = "rsa"
        p12Data = nil
        p12Password = nil
        provisioningData = nil
        teamIdentifier = nil
        certificateInfo = nil
        refresh()
        try? fileManager.removeItem(at: keysDir)
    }
}
