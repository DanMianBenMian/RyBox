import Foundation
import Security

/// Holds the user-imported signing identity + provisioning profile.
/// Supports BOTH development and DISTRIBUTION certificates (Ad Hoc / Enterprise).
/// Distribution certs lack get-task-allow (no JIT) — acceptable for a runtime env.
public final class CertificateStore: ObservableObject {
    public static let shared = CertificateStore()

    private var identity: SecIdentity?
    private var provisioningData: Data?
    /// Raw p12 bytes (kept so CodeSigner can stage them for the bundled helper).
    private var p12Data: Data?
    private var p12Password: String?

    @Published public private(set) var isConfigured: Bool = false
    /// Team id extracted from the provisioning profile (e.g. "ABCDE12345").
    @Published public private(set) var teamIdentifier: String?

    /// Import a .p12 (distribution or development) using its password.
    public func importP12(_ data: Data, password: String) -> Bool {
        let opts = [kSecImportExportPassphrase as String: password] as CFDictionary
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, opts, &items)
        guard status == errSecSuccess, let items = items else { return false }

        let arr = items as NSArray
        guard let first = arr.firstObject as? NSDictionary,
              let ident = first[kSecImportItemIdentity as String] as? SecIdentity else {
            return false
        }
        self.identity = ident
        self.p12Data = data
        self.p12Password = password
        refresh()
        return true
    }

    /// Import a .mobileprovision (embedded entitlements are read from it).
    public func importProvisioning(_ data: Data) {
        self.provisioningData = data
        if let plist = provisioningPlist(),
           let teams = plist["TeamIdentifier"] as? [String], let t = teams.first {
            teamIdentifier = t
        }
        refresh()
    }

    private func refresh() {
        isConfigured = (identity != nil && provisioningData != nil)
    }

    // MARK: - Accessors used by CodeSigner

    public func identityRef() -> SecIdentity? { identity }
    public func p12RawData() -> Data? { p12Data }
    public func p12Passphrase() -> String? { p12Password }
    public func provisioningRawData() -> Data? { provisioningData }

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
}
