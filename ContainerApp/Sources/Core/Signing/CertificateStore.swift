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
    private var fallbackCertDER: Data?
    private var fallbackKeyDER: Data?
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
            self.fallbackCertDER = nil
            self.fallbackKeyDER = nil
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
                self.fallbackCertDER = o.certDER
                self.fallbackKeyDER = o.keyDER
                self.fallbackKeyType = o.keyType
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
    public func fallbackCertDER() -> Data? { fallbackCertDER }
    public func fallbackKeyDER() -> Data? { fallbackKeyDER }
    public func fallbackKeyIsEC() -> Bool { fallbackKeyType == "ec" }

    /// Decode the provisioning profile (CMS-wrapped plist) into its outer dict.
    public func provisioningPlist() -> [String: Any]? {
        guard let data = provisioningData else { return nil }
        // The profile is PEM-like: the plist bytes are readable as text inside it.
        guard let str = String(data: data, encoding: .ascii) ??
                        String(data: data, encoding: .isoLatin1) else { return nil }
        guard let start = str.range(of: "<?xml"),
              let end = str.range(of: "</plist>") else { return nil }
        let xml = String(str[start.lowerBound...end.upperBound])
        guard let xmlData = xml.data(using: .utf8) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: xmlData,
                options: [], format: nil)) as? [String: Any]
    }

    /// Entitlements to apply to a guest: taken from the provisioning profile's
    /// embedded `Entitlements` dict. This already contains application-identifier
    /// (TEAMID.com.rybox.ios), get-task-allow=false, keychain-access-groups, etc.
    /// AMFI validates the guest's signature against exactly this set.
    public func guestEntitlements() -> [String: Any]? {
        guard let plist = provisioningPlist() else { return nil }
        return plist["Entitlements"] as? [String: Any]
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
        fallbackCertDER = nil
        fallbackKeyDER = nil
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
