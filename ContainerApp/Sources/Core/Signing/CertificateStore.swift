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
    /// Full certificate chain carried by the p12 (leaf + intermediates), as
    /// DER. Sourced from `kSecImportItemCertChain` (SecPKCS12Import path) or
    /// from every certBag in RyP12 (fallback path). The signer needs this to
    /// embed the WWDR intermediate at CMS slot 1 — the DR requires
    /// `certificate 1[1.2.840.113635.100.6.2.1 exists]`, and a leaf-only CMS
    /// fails trust evaluation on a non-jailbroken device (errno=85).
    private var identityCertChain: [Data]?
    /// The leaf certificate as a live `SecCertificateRef`, kept so the signer
    /// can build the rest of the chain (intermediate / root) from the system
    /// trust store via `SecTrust` when the p12 omits the intermediate.
    private var signingLeafCert: SecCertificate?
    private var provisioningData: Data?
    /// Raw p12 bytes (kept so CodeSigner can stage them for the bundled helper).
    private var p12Data: Data?
    private var p12Password: String?

    @Published public private(set) var isConfigured: Bool = false
    /// Team id of the SIGNING identity (e.g. "ABCDE12345").
    ///
    /// Sourced from the p12's leaf certificate (Subject OU), with the
    /// provisioning profile's `TeamIdentifier` as a cross-check / fallback.
    ///
    /// It has to come from the certificate: the profile says which team may
    /// sign an *app*, the certificate says which team the *private key* belongs
    /// to. Library validation compares the latter, and a CI-built or
    /// side-loaded app frequently has no embedded profile at all — so a
    /// profile-only lookup returns nil exactly when the team is needed.
    @Published public private(set) var teamIdentifier: String?
    /// Where `teamIdentifier` came from — "证书" / "描述文件" / "证书（与描述文件不一致）" /
    /// "证书与描述文件一致".
    @Published public private(set) var teamSource: String?
    /// The team the PROVISIONING PROFILE claims. Kept separately so the
    /// certificate's own team can be cross-checked against it regardless of
    /// the order the two files were imported in.
    private var profileTeamIdentifier: String?
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
            // Capture the FULL chain the importer resolved (leaf + any
            // intermediates it could find), so the signer can embed the WWDR
            // intermediate at CMS slot 1. `kSecImportItemCertChain` is present
            // when the p12 carries more than the leaf.
            if let chain = first[kSecImportItemCertChain as String] as? [Any] {
                var derChain: [Data] = []
                for item in chain {
                    let cf = item as CFTypeRef
                    if CFGetTypeID(cf) == SecCertificateGetTypeID() {
                        if let d = SecCertificateCopyData(cf as! SecCertificate) as Data? {
                            derChain.append(d)
                        }
                    }
                }
                self.identityCertChain = derChain.isEmpty ? nil : derChain
            } else {
                self.identityCertChain = nil
            }
            // Keep the leaf certificate so the signer can extend the chain from
            // the system trust store at sign time.
            var leaf: SecCertificate? = nil
            if SecIdentityCopyCertificate(self.identity!, &leaf) == errSecSuccess {
                self.signingLeafCert = leaf
            }
            self.certificateInfo = Self.describe(identity: self.identity)
            self.captureTeamFromCertificate()
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
                // RyP12 decodes every certBag, so the full chain (leaf +
                // intermediates) is available even from an OpenSSL-3 p12 that
                // SecPKCS12Import cannot read. Feed it to the signer so the
                // WWDR intermediate reaches CMS slot 1.
                self.identityCertChain = o.certChain.isEmpty ? nil : o.certChain
                if let leaf = SecCertificateCreateWithData(nil, o.certDER as CFData) {
                    self.signingLeafCert = leaf
                }
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
                self.captureTeamFromCertificate()
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
            // Cross-check against the certificate's own team. A mismatch means
            // the p12 and the profile belong to DIFFERENT Apple accounts — the
            // guest would then be signed by a key whose team is not the one the
            // profile claims, which AMFI rejects. Report it instead of
            // silently picking one.
            //
            // The certificate wins, because it is the private key's team and
            // that is what library validation compares.
            profileTeamIdentifier = t
            if let certTeam = teamIdentifier, certTeam != t {
                RyLog.shared.log("⚠ p12 证书的 team=\(certTeam) 与描述文件的 team=\(t) 不一致 —— "
                                 + "两者必须来自同一个 Apple 开发者账号，否则重签后 AMFI 会拒绝。",
                                 level: .error, tag: "sign")
                teamIdentifier = certTeam
                teamSource = "证书（与描述文件不一致）"
            } else if let certTeam = teamIdentifier {
                teamIdentifier = certTeam
                teamSource = "证书与描述文件一致"
            } else {
                // No certificate imported yet — the profile is all we have.
                teamIdentifier = t
                teamSource = "描述文件"
            }
        } else {
            captureTeamFromCertificate()
        }
        refresh()
        save()
        return .success(())
    }

    /// Read the Team ID out of the signing certificate and record it.
    ///
    /// The certificate is the authority here: it is the private key's team,
    /// and library validation compares exactly that. A provisioning profile
    /// only says which team may sign an *app*, and a CI-built or side-loaded
    /// app often carries no profile at all.
    private func captureTeamFromCertificate() {
        var der: Data? = nil
        if let leaf = signingLeafCert {
            der = SecCertificateCopyData(leaf) as Data
        } else if let d = decodedCert {
            der = d
        }
        guard let der = der,
              let t = RyASN1.teamID(inCertificateDER: der) else { return }
        if let existing = teamIdentifier, existing != t {
            RyLog.shared.log("⚠ 证书里的 team=\(t) 与已记录的 team=\(existing) 不一致，以证书为准。",
                             level: .warn, tag: "sign")
        }
        teamIdentifier = t
        // The certificate is the authority. If a profile is already known and
        // disagrees, say so — the mismatch is fatal for library validation and
        // must not be silently swallowed.
        if let pt = profileTeamIdentifier, pt != t {
            RyLog.shared.log("⚠ p12 证书的 team=\(t) 与描述文件的 team=\(pt) 不一致 —— "
                             + "两者必须来自同一个 Apple 开发者账号，否则重签后 AMFI 会拒绝。",
                             level: .error, tag: "sign")
            teamSource = "证书（与描述文件不一致）"
        } else if profileTeamIdentifier != nil {
            teamSource = "证书与描述文件一致"
        } else {
            teamSource = "证书"
        }
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
        if let existing = Self.copyFallbackKeychainRef() {
            Self.logKeySanity(existing)
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
            // Capture the live SecKey straight from the add call. A SEPARATE
            // SecItemCopyMatching right after a successful add returns nil on
            // some iOS builds — that is exactly the rc=8 "import ok, lookup
            // nil" failure that forced the DER path. kSecReturnRef hands back
            // the SecKey in the same call, skipping that second lookup.
            kSecReturnRef as String: true,
            kSecValueData as String: blob
        ]
        var added: CFTypeRef?
        var st = SecItemAdd(add as CFDictionary, &added)
        if st == errSecDuplicateItem {
            // Our tag is already taken (previous launch, or the sibling
            // blob). Drop the stale item and re-add so the keychain always
            // holds the CURRENT p12's key — a stale key from an older
            // certificate would silently sign with the wrong identity.
            RyLog.shared.log("sign  钥匙串已有同 tag 私钥，清除旧项后重新导入（\(blob.count) 字节）",
                             level: .info, tag: "sign")
            Self.deleteFallbackKeychainItem()
            added = nil
            st = SecItemAdd(add as CFDictionary, &added)
        }
        RyLog.shared.log("sign  钥匙串导入私钥（\(blob.count) 字节）→ osstatus=\(st)",
                         level: st == errSecSuccess ? .info : .warn, tag: "sign")
        if st == errSecSuccess {
            // PREFER the ref returned by SecItemAdd — it is the reliable path.
            if let ref = added, CFGetTypeID(ref) == SecKeyGetTypeID() {
                let k = ref as! SecKey
                RyLog.shared.log("sign  私钥已进入系统钥匙串，改用活 SecKey 签名路径（add 直接取回）",
                                 level: .info, tag: "sign")
                Self.logKeySanity(k)
                return k
            }
            // Fallback to the separate lookup in case kSecReturnRef was
            // unavailable on this build (kept for robustness).
            if let k = Self.copyFallbackKeychainRef() {
                RyLog.shared.log("sign  私钥已进入系统钥匙串，改用活 SecKey 签名路径", level: .info, tag: "sign")
                Self.logKeySanity(k)
                return k
            }
            // Import succeeded but the lookup returned nothing. This is
            // exactly how rc=8 looked on the device: osstatus=0 on add,
            // nil on copy, signer silently back on the DER path that
            // SecKeyCreateWithData refuses. Say it out loud now.
            RyLog.shared.log("sign  ⚠ 钥匙串导入成功但取回失败——签名器将退回 DER 路径",
                             level: .warn, tag: "sign")
        }
        }
        return nil
    }

    /// Look up the fallback key by tag ONLY.
    ///
    /// The query deliberately omits `kSecAttrKeyType`: Apple's documented
    /// "find a key" query is class + application tag (+ kSecReturnRef), and
    /// carrying the key-type attribute makes `SecItemCopyMatching` fail even
    /// when the item exists — which is exactly how the rc=8 signing failure
    /// happened (import osstatus=0, lookup silently nil, DER fallback refused).
    private static func copyFallbackKeychainRef() -> SecKey? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: fallbackKeyTag,
            kSecReturnRef as String: true
        ]
        var ref: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &ref)
        if st == errSecItemNotFound { return nil } // not imported yet — caller adds next
        guard st == errSecSuccess else {
            RyLog.shared.log("sign  钥匙串取回私钥失败：osstatus=\(st)", level: .warn, tag: "sign")
            return nil
        }
        guard let ref = ref else {
            RyLog.shared.log("sign  钥匙串取回私钥：查询成功但返回 nil", level: .warn, tag: "sign")
            return nil
        }
        // Same CoreFoundation downcast rule as SecIdentity: verify the type ID
        // before bridging, or a wrong-typed item becomes a crash later.
        guard CFGetTypeID(ref) == SecKeyGetTypeID() else {
            RyLog.shared.log("sign  钥匙串取回私钥：返回对象不是 SecKey（type ID 不符）",
                             level: .warn, tag: "sign")
            return nil
        }
        return (ref as! SecKey)
    }

    /// Canary self-check for a keychain-backed key: sign 4 bytes and log the
    /// outcome. A key that imports fine but cannot sign (locked keychain,
    /// wrong key class, …) is otherwise invisible until the CMS step fails
    /// deep inside the signer — on the device that surfaced as a bare "rc=8".
    /// Diagnostic only: a failed canary does NOT discard the key.
    ///
    /// Implemented in C (`rysign_canary`) on purpose: the Swift overlay
    /// imports `SecKeyCreateSignature`'s error parameter as
    /// `UnsafeMutablePointer<Unmanaged<CFError>?>`, and that shape is exactly
    /// what inverted success/failure in the C signer before.
    private static func logKeySanity(_ key: SecKey) {
        guard let p = rysign_canary(key) else {
            RyLog.shared.log("sign  canary 自检：C 层未返回报告", level: .warn, tag: "sign")
            return
        }
        let report = String(cString: p)
        let parts = report.split(separator: " ")
        if parts.first == "ok" && parts.count >= 4 {
            RyLog.shared.log("sign  canary 自检通过：\(parts[1]) 签名 \(parts[2]) 字节，块长 \(parts[3]) 位",
                             level: .info, tag: "sign")
        } else if report == "skip" {
            RyLog.shared.log("sign  canary 自检跳过：取回的 SecKey 不支持已知签名算法",
                             level: .warn, tag: "sign")
        } else if report == "null" {
            RyLog.shared.log("sign  canary 自检：密钥引用为空", level: .warn, tag: "sign")
        } else {
            RyLog.shared.log("sign  canary 自检失败（仍继续）：\(report)", level: .warn, tag: "sign")
        }
    }

    private static func deleteFallbackKeychainItem() {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: fallbackKeyTag
        ]
        SecItemDelete(q as CFDictionary)
    }

    /// Decode an arbitrary `.mobileprovision` blob into its plist.
    ///
    /// Exposed as a STATIC helper so the container can inspect its OWN
    /// embedded provisioning profile (see `HostIdentity`) with exactly the same
    /// CMS-unwrapping code that parses the user's imported one. Two parsers
    /// would inevitably disagree about what a profile says.
    public static func decodeProvisioningPlist(_ data: Data) -> [String: Any]? {
        guard !data.isEmpty else { return nil }
        let plistData: Data
        if data.first == 0x30 {
            plistData = Self.unwrapCMS(data) ?? data
        } else {
            plistData = data
        }
        return (try? PropertyListSerialization.propertyList(from: plistData,
                options: [], format: nil)) as? [String: Any]
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

    /// The certificate set to embed in the guest's CMS, EXCLUDING the leaf
    /// (the signer always prepends the leaf as slot 0). The result is ordered
    /// so the **WWDR intermediate lands at slot 1** — the DR requires
    /// `certificate 1[1.2.840.113635.100.6.2.1 exists]`, so slot 1 MUST be the
    /// WWDR intermediate; anything else there fails trust evaluation
    /// (`code signature invalid`, errno=85) even with perfect hashes.
    ///
    /// Sources, unioned and de-duplicated:
    ///   1. the WWDR intermediate resolved from the system trust store via
    ///      `SecTrust` (most reliable — the device ships the Apple root + WWDR
    ///      as anchors, and `SecTrust` supplies the intermediate even when the
    ///      p12 carries only the leaf),
    ///   2. the full chain carried by the p12 (`identityCertChain`),
    ///   3. the profile's `DeveloperCertificates`,
    ///   4. a direct `SecItem` scan of the certificate store for the WWDR
    ///      (covers iOS builds where `SecTrust` is unusually constrained).
    ///
    /// The leaf's DER is excluded so it cannot displace the intermediate at
    /// slot 1.
    public func signingIntermediateCertificates() -> [Data] {
        let leafDER = (signingLeafCert.flatMap { SecCertificateCopyData($0) as Data? })
        // Leaf issuer (canonical DER) — used to accept ONLY the WWDR that
        // actually signed this leaf, so a WRONG intermediate (e.g. a
        // system-cached G3) is never embedded alongside the correct one.
        let leafIssuer = (signingLeafCert.flatMap {
            SecCertificateCopyNormalizedIssuerSequence($0) as Data?
        })
        var seen = Set<Data>()
        var wwdr: [Data] = []
        var others: [Data] = []

        // A WWDR is only useful if its SUBJECT == the leaf's ISSUER (it truly
        // issued the leaf). When we don't know the leaf, accept any WWDR.
        func wwdrCanChain(_ c: Data) -> Bool {
            guard let leafIssuer = leafIssuer else { return true }
            guard let cert = SecCertificateCreateWithData(nil, c as CFData),
                  let subj = SecCertificateCopyNormalizedSubjectSequence(cert) as Data?
            else { return false }
            return subj == leafIssuer
        }

        func take(_ c: Data, wwdrFirst: Bool) {
            guard c.count > 0 else { return }
            if let leaf = leafDER, leaf == c { return }   // never re-add the leaf
            if seen.contains(c) { return }
            seen.insert(c)
            if isWWDR(c) {
                // Only keep a WWDR that can actually chain to this leaf.
                guard wwdrCanChain(c) else { return }
                if wwdrFirst { wwdr.append(c) } else { others.append(c) }
            } else {
                others.append(c)
            }
        }

        // 0) EMBEDDED Apple WWDR intermediate — ALWAYS present, pre-pended so it
        //    becomes CMS slot 1 (the DR requires
        //    `certificate 1[1.2.840.113635.100.6.2.1 exists]`). Many devices
        //    ship WITHOUT a WWDR in SecTrust / the keychain (the user's iPad:
        //    empty chain → `code signature invalid`, errno=85), so we carry the
        //    certs in-code — exactly what LiveContainer does
        //    (`ZSignAsset::s_szAppleDevCACert` / `...G3`).
        if let embedded = Self.preferredEmbeddedWWDR(for: signingLeafCert) {
            take(embedded.der, wwdrFirst: true)
        }

        // 1) system-trust chain of the leaf (gives the WWDR intermediate)
        for c in systemTrustChain().dropFirst(1) { take(c, wwdrFirst: true) }
        // 2) p12 chain
        if let chain = identityCertChain { for c in chain { take(c, wwdrFirst: true) } }
        // 3) profile
        if let prof = provisioningCertificates() { for c in prof { take(c, wwdrFirst: true) } }
        // 4) direct WWDR scan of the certificate store
        for c in systemWWDRCertificates() { take(c, wwdrFirst: true) }

        // WWDR first, then any remaining intermediates/roots. This guarantees
        // the FIRST extra cert (→ CMS slot 1) is the matched WWDR intermediate.
        return wwdr + others
    }

    /// True when `cert` is an Apple Worldwide Developer Relations
    /// Certification Authority certificate (the intermediate the DR checks for).
    private func isWWDR(_ cert: Data) -> Bool {
        guard let c = SecCertificateCreateWithData(nil, cert as CFData) else { return false }
        let summary = (SecCertificateCopySubjectSummary(c) as? String) ?? ""
        return summary.contains("Apple Worldwide Developer Relations")
    }

    /// Build the chain the system trust store assembles for the leaf: drop the
    /// leaf itself (the caller prepends it) and return the intermediate(s) +
    /// root. Uses `SecTrust` so the device supplies the WWDR even when the p12
    /// omits it. The final validity verdict is ignored — only the assembled
    /// chain matters.
    private func systemTrustChain() -> [Data] {
        guard let leaf = signingLeafCert else { return [] }
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(leaf as CFTypeRef,
                                                   SecPolicyCreateBasicX509(), &trust)
        guard status == errSecSuccess, let trust = trust else { return [] }
        var err: CFError? = nil
        _ = SecTrustEvaluateWithError(trust, &err)   // build chain; verdict ignored
        var out: [Data] = []
        let n = SecTrustGetCertificateCount(trust)
        for i in 0..<n {
            if let c = SecTrustGetCertificateAtIndex(trust, i),
               let d = SecCertificateCopyData(c) as Data? {
                out.append(d)
            }
        }
        return out
    }

    /// Scan the certificate store for every Apple WWDR intermediate present on
    /// the device. A belt-and-suspenders source in case `SecTrust` is
    /// constrained on some iOS builds. Returns DER blobs.
    private func systemWWDRCertificates() -> [Data] {
        let q: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var res: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &res) == errSecSuccess,
              let arr = res as? [SecCertificate] else { return [] }
        var out: [Data] = []
        for c in arr {
            let summary = (SecCertificateCopySubjectSummary(c) as? String) ?? ""
            if summary.contains("Apple Worldwide Developer Relations"),
               let d = SecCertificateCopyData(c) as Data? {
                out.append(d)
            }
        }
        return out
    }

    // MARK: - Embedded Apple WWDR intermediates

    /// Apple Worldwide Developer Relations Certification Authority (G3) — the
    /// intermediate most signing certificates chained through until ~2023.
    /// Hardcoded on purpose: the device's trust store / keychain may not supply
    /// a WWDR (the user's iPad returned an EMPTY chain → `code signature
    /// invalid`, errno=85 without this). We therefore carry the Apple
    /// intermediates in-code — exactly what LiveContainer does
    /// (`ZSignAsset::s_szAppleDevCACert` / `...G3`).
    ///
    /// IMPORTANT (errno=1 root cause): Apple did NOT stick with G3. Certificates
    /// issued from 2023 onward chain through G5 / G6 (G6 is signed by the
    /// separate "Apple Root CA - G3" anchor; G5/G7/G8 by the original
    /// "Apple Root CA"). Hardcoding ONLY G3 made the guest CMS embed a WRONG
    /// intermediate when the leaf is signed by G6 → the trust chain
    /// `leaf → G3 → root` cannot be built → errno=1. We now embed
    /// G3/G5/G6/G7/G8 and pick the one whose SUBJECT matches the leaf's ISSUER
    /// (see `preferredEmbeddedWWDR`).
    ///
    /// The DR (Designated Requirement) requires CMS slot 1 to carry a cert with
    /// the Apple OID `1.2.840.113635.100.6.2.1` — every WWDR below satisfies it.
    private static let appleWWDRG3Base64 = "MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZC4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbWBpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LSVpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsGAQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3JsMB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJHQr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qAHXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETKXXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTCNwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVzaUDSdlTs="

    /// G5 (RSA, signed by the original Apple Root CA).
    private static let appleWWDRG5Base64 = "MIIEVTCCAz2gAwIBAgIUO36ACu7TAqHm7NuX2cqsKJzxaZQwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTIwMTIxNjE5Mzg1NloXDTMwMTIxMDAwMDAwMFowdTFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxCzAJBgNVBAsMAkc1MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ9d2h/7+rzQSyI8x9Ym+hf39J8ePmQRZprvXr6rNL2qLCFu1h6UIYUsdMEOEGGqPGNKfkrjyHXWz8KcCEh7arkpsclm/ciKFtGyBDyCuoBs4v8Kcuus/jtvSL6eixFNlX2ye5AvAhxO/Em+12+1T754xtress3J2WYRO1rpCUVziVDUTuJoBX7adZxLAa7a489tdE3eU9DVGjiCOtCd410pe7GB6iknC/tgfIYS+/BiTwbnTNEf2W2e7XPaeCENnXDZRleQX2eEwXN3CqhiYraucIa7dSOJrXn25qTU/YMmMgo7JJJbIKGc0S+AGJvdPAvntf3sgFcPF54/K4cnu/cCAwEAAaOB7zCB7DASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFCvQaUeUdgn+9GuNLkCm90dNfwheMEQGCCsGAQUFBwEBBDgwNjA0BggrBgEFBQcwAYYoaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJvb3RjYTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmFwcGxlLmNvbS9yb290LmNybDAdBgNVHQ4EFgQUGYuXjUpbYXhX9KVcNRKKOQjjsHUwDgYDVR0PAQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQBaxDWi2eYKnlKiAIIid81yL5D5Iq8UJcyqCkJgksK9dR3rTMoV5X5rQBBe+1tFdA3wen2Ikc7eY4tCidIY30GzWJ4GCIdI3UCvI9Xt6yxg5eukfxzpnIPWlF9MYjmKTq4TjX1DuNxerL4YQPLmDyxdE5Pxe2WowmhI3v+0lpsM+zI2np4NlV84CouW0hJst4sLjtc+7G8Bqs5NRWDbhHFmYuUZZTDNiv9FU/tu+4h3Q8NIY/n3UbNyXnniVs+8u4S5OFp4rhFIUrsNNYuU3sx0mmj1SWCUrPKosxWGkNDMMEOG0+VwAlG0gcCol9Tq6rCMCUDvOJOyzSID62dDZchF"

    /// G6 (ECDSA, signed by the separate "Apple Root CA - G3" anchor). This is
    /// the intermediate the user's "iPhone Distribution: … (A6MS28G6T8)" cert
    /// actually chains through — embedding G3 alone caused errno=1.
    private static let appleWWDRG6Base64 = "MIIDFjCCApygAwIBAgIUIsGhRwp0c2nvU4YSycafPTjzbNcwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjEwMzE3MjAzNzEwWhcNMzYwMzE5MDAwMDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzYxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbsQKC94PrlWmZXnXgtxzdVJL8T0SGYngDRGpngn3N6PT8JMEb7FDi4bBmPhCnZ3/sq6PF/cGcKXWsL5vOteRhyJ45x3ASP7cOB+aao90fcpxSv/EZFbniAbNgZGhIhpIo4H6MIH3MBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rLJKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5hcHBsZS5jb20vYXBwbGVyb290Y2FnMy5jcmwwHQYDVR0OBBYEFD8vlCNR01DJmig97bB85c+lkGKZMA4GA1UdDwEB/wQEAwIBBjAQBgoqhkiG92NkBgIBBAIFADAKBggqhkjOPQQDAwNoADBlAjBAXhSq5IyKogMCPtw490BaB677CaEGJXufQB/EqZGd6CSjiCtOnuMTbXVXmxxcxfkCMQDTSPxarZXvNrkxU3TkUMI33yzvFVVRT4wxWJC994OsdcZ4+RGNsYDyR5gmdr0nDGg="

    /// G7 (RSA, signed by the original Apple Root CA).
    private static let appleWWDRG7Base64 = "MIIEVTCCAz2gAwIBAgIUNBhY/wH+Bj+O8Z8f6TwBtMFG/8kwDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTIyMTExNzIwNDA1M1oXDTIzMTExNzIwNDA1MlowdTELMAkGA1UEBhMCVVMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAsMAkc3MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKyu0dO2irEbKJWt3lFRTD8z4U5cr7P8AtJlTyrUdGiMdRdlzyjkSAmYcVIyLBZOeI6SVmSp3YvN4tTHO6ISRTcCGWJkL39hxtNZIr+r+RSj7baembov8bHcMEJPtrayxnSqYla77UQ2D9HlIHSTVzpdntwB/HhvaRY1w24Bwp5y1HE2sXYJer4NKpfxsF4LGxKtK6sH32Mt9YjpMhKiVVhDdjw9F4AfKduxqZ+rlgWdFdzd204P5xN8WisuAkH27npqtnNg95cZFIuVMziT2gAlNq5VWnyf+fRiBAd06R2nlVcjrCsk2mRPKHLplrAIPIgbFGND14mumMHyLY7jUSUCAwEAAaOB7zCB7DASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFCvQaUeUdgn+9GuNLkCm90dNfwheMEQGCCsGAQUFBwEBBDgwNjA0BggrBgEFBQcwAYYoaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJvb3RjYTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmFwcGxlLmNvbS9yb290LmNybDAdBgNVHQ4EFgQUXUIQbBu7x1KXTkS9Eye5OhJ3gyswDgYDVR0PAQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBSowgpE2W3tR/mNAPt9hh3vD3KJ7Vw7OxsM0v2mSWUB54hMwNq9X0KLivfCKmC3kp/4ecLSwW4J5hJ3cEMhteBZK6CnMRF8eqPHCIw46IlYUSJ/oV6VvByknwMRFQkt7WknybwMvlXnWp5bEDtDzQGBkL/2A4xZW3mLgHZBr/Fyg2uR9QFF4g86ZzkGWRtipStEdwB9uV4r63ocNcNXYE+RiosriShx9Lgfb8d9TZrxd6pCpqAsRFesmR+s8FXzMJsWZm39LDdMdpI1mqB7rKLUDUW5udccWJusPJR4qht+CrLaHPGpsQaQ0kBPqmpAIqGbIOI0lxwV3ra+HbMGdWw"

    /// G8 (RSA, signed by the original Apple Root CA).
    private static let appleWWDRG8Base64 = "MIIEVTCCAz2gAwIBAgIUVLULr3kNjX+Mr2hMVi9QaQoaul8wDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTIzMDYyMDIzMzcxNVoXDTI1MDEyNDAwMDAwMFowdTELMAkGA1UEBhMCVVMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAsMAkc4MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANBAENQI+VIhY088aPfUnIICjINovLeNf4jnQk0s7yKlwonevQzXTWFQLTnkMHOl0tVomjPy79kqrS4fA7r4pfFCC1cuRsbQWNNwX/eyN+9qHz6/iTnCrf71BftYljHIhyzVI7p1sCz1q6C68iAMTOskY2npIkDwjlhb3mR7iRtREgTgF7JZzd/x586vLDLoacHQCH4dokdz0Us7/bmF3EenKIJ5KUiJAijiwewsH1uG/Ni2y3HAcwFL/AUREWwBAzRa9oHCXh98FA7eP2shy0/112HmhAOSvOclKZ7NWwzB2+PEOtl2V6wvOBQZyLexolVPX06OGVmp2v1y2rAEIQUCAwEAAaOB7zCB7DASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFCvQaUeUdgn+9GuNLkCm90dNfwheMEQGCCsGAQUFBwEBBDgwNjA0BggrBgEFBQcwAYYoaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJvb3RjYTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmFwcGxlLmNvbS9yb290LmNybDAdBgNVHQ4EFgQUtb28gMQM4zik9LetI7PvRM65WoUwDgYDVR0PAQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBMs+t6OZRKlWb6FjHqDYqPXUI4xgfN6MkirPwIQn5fk18xKqgiwXYZK+6ucum9Vs9JJJII980ZdcP5GicNDtwpjT+226VPTHLEYJGJEX4klUMiYGe83/+r5TwWF52CFE6d9HX+ULmtBbK4efaV1hDl9lP0zyPmdw/suEtp+OKeAjHZjtnKvmNeX+Ggac7BzW5Jo3hhrzk8aksKNCVk1TC1PKvdEYE5cejAw1iAERAaEdLCvFnwitk1c8DmbeTJfWIUPoICqRBpN3lhb/BGlD419ausY9DYXllXadG4S25d1F8TnHBOJRHcJCweFp6WWgTtRe467mddj8OGsPVMH2gQ"

    private static func embeddedWWDRCerts()
        -> [(der: Data, cert: SecCertificate, label: String)] {
        let blobs: [(String, String)] = [
            (appleWWDRG3Base64, "G3"),
            (appleWWDRG5Base64, "G5"),
            (appleWWDRG6Base64, "G6"),
            (appleWWDRG7Base64, "G7"),
            (appleWWDRG8Base64, "G8")
        ]
        var out: [(Data, SecCertificate, String)] = []
        for (blob, label) in blobs {
            guard let der = Data(base64Encoded: blob),
                  let cert = SecCertificateCreateWithData(nil, der as CFData) else { continue }
            out.append((der, cert, label))
        }
        return out
    }

    /// The embedded WWDR that must sit at CMS slot 1.
    ///
    /// We pick the candidate whose SUBJECT equals the leaf's ISSUER — the exact
    /// X.509 chaining test (parent's subject == child's issuer). This needs no
    /// AKID/SKID extension parsing (not uniformly exposed across SDK versions);
    /// `SecCertificateCopyNormalizedIssuerSequence` / `…SubjectSequence` give
    /// canonical, comparable DER name blobs.
    ///
    /// The chosen label is logged: `SubjectSummary` returns only the CN (all
    /// five WWDRs share one CN), so without it a device log cannot tell G3
    /// from G6.
    ///
    /// - Returns: the matched intermediate plus which candidate it came from
    ///   ("G3"…"G8"); `nil` only if no embedded blob parses.
    private static func preferredEmbeddedWWDR(for leaf: SecCertificate?)
        -> (der: Data, label: String)? {
        let candidates = embeddedWWDRCerts()
        guard let first = candidates.first else { return nil }
        guard let leaf = leaf else {
            RyLog.shared.log("sign  ⚠ 无叶子证书可比对签发者，WWDR 回落 \(first.label)",
                             level: .warn, tag: "sign")
            return (first.der, first.label)
        }
        guard let leafIssuer = SecCertificateCopyNormalizedIssuerSequence(leaf) as Data?
        else {
            RyLog.shared.log("sign  ⚠ 读不出 leaf 签发者，WWDR 回落 \(first.label)",
                             level: .warn, tag: "sign")
            return (first.der, first.label)
        }
        for (der, cert, label) in candidates {
            if let subj = SecCertificateCopyNormalizedSubjectSequence(cert) as Data?,
               subj == leafIssuer {
                RyLog.shared.log("sign  WWDR 匹配：leaf 签发者 == \(label) 主题 → CMS slot 1 嵌入 \(label)",
                                 level: .info, tag: "sign")
                return (der, label)
            }
        }
        RyLog.shared.log("sign  ⚠ WWDR 无匹配：leaf 的签发者不属于 G3/G5/G6/G7/G8，回落 \(first.label)",
                         level: .warn, tag: "sign")
        return (first.der, first.label)
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
        identityCertChain = nil
        signingLeafCert = nil
        // The keychain copy of the fallback key must go too: it is tagged, and
        // a re-import replaces the tag's key — but a reset that left it behind
        // would let the NEXT import find the PREVIOUS identity's key.
        Self.deleteFallbackKeychainItem()
        fallbackKeyType = "rsa"
        p12Data = nil
        p12Password = nil
        provisioningData = nil
        teamIdentifier = nil
        teamSource = nil
        profileTeamIdentifier = nil
        certificateInfo = nil
        refresh()
        try? fileManager.removeItem(at: keysDir)
    }
}
