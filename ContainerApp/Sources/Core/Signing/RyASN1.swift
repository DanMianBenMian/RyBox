import Foundation

/// A tiny, dependency-free DER parser.
///
/// It exists because two Apple frameworks are unavailable on iOS and one
/// third-party format needs reading:
///
///   * `CMSDecoder` (used to unwrap a `.mobileprovision`) is **macOS-only** —
///     Apple's own header says "macOS 10.5+". A real provisioning profile is a
///     CMS `SignedData` whose *content* is a binary property list, so without a
///     decoder the profile cannot be read at all and the boot gate refuses to
///     proceed.
///   * PKCS#12 files written by OpenSSL 3 use PBES2 + AES-256-CBC, which
///     `SecPKCS12Import` refuses — `RyP12` parses those itself.
///
/// Only the pieces actually needed are implemented: TLV walking, child
/// enumeration, raw slicing and OID rendering.
enum RyASN1 {

    /// One TLV: tag, content range and end offset.
    typealias Element = (tag: UInt8, lo: Int, hi: Int, end: Int)

    static let SEQUENCE: UInt8 = 0x30
    static let SET: UInt8 = 0x31
    static let OID: UInt8 = 0x06
    static let OCTET_STRING: UInt8 = 0x04
    static let INTEGER: UInt8 = 0x02
    static let BIT_STRING: UInt8 = 0x03
    static let BOOLEAN: UInt8 = 0x01
    static let UTF8_STRING: UInt8 = 0x0C

    struct Reader {
        let bytes: [UInt8]

        init(_ data: Data) { bytes = [UInt8](data) }

        /// Read the TLV at `i`. Handles both short and long-form lengths.
        func at(_ i: Int) -> Element? {
            guard i + 2 <= bytes.count else { return nil }
            let tag = bytes[i]
            var p = i + 1
            let lb = bytes[p]
            p += 1
            var len = 0
            if lb & 0x80 != 0 {
                let n = Int(lb & 0x7f)
                guard n >= 1, n <= 8, p + n <= bytes.count else { return nil }
                for k in 0..<n { len = (len << 8) | Int(bytes[p + k]) }
                p += n
            } else {
                len = Int(lb)
            }
            guard p + len <= bytes.count else { return nil }
            return (tag, p, p + len, p + len)
        }

        /// The elements contained in `e`.
        func children(_ e: Element) -> [Element] {
            var out: [Element] = []
            var i = e.lo
            while i < e.hi, let c = at(i), c.end <= e.hi {
                out.append(c)
                i = c.end
            }
            return out
        }

        /// The raw content bytes of `e` (without tag/length).
        func slice(_ e: Element) -> [UInt8] { Array(bytes[e.lo..<e.hi]) }
    }

    /// Render an OID element as dotted decimal.
    static func oidString(_ e: Element, _ r: Reader) -> String {
        let c = r.slice(e)
        guard let first = c.first else { return "" }
        var parts: [String] = []
        if first < 80 {
            parts.append(String(first / 40))
            parts.append(String(first % 40))
        } else {
            parts.append("2")
            parts.append(String(first - 80))
        }
        var v: UInt64 = 0
        for byte in c.dropFirst() {
            v = (v << 7) | UInt64(byte & 0x7f)
            if byte & 0x80 == 0 { parts.append(String(v)); v = 0 }
        }
        return parts.joined(separator: ".")
    }

    // MARK: - X.509 subject

    /// The `organizationalUnitName` OID (2.5.4.11).
    ///
    /// In every Apple-issued signing certificate this attribute holds the
    /// **Team ID** — the 10-character string Apple binds to a developer
    /// account. Verified against a real certificate:
    ///
    ///     OID 2.5.4.11 = "PQQC56VX22"
    ///     OID 2.5.4.3  = "iPhone Developer: ... (XWS2FBQXYM)"
    ///
    /// (The parenthesised token in the CN is a *legacy* identifier and is NOT
    /// the team — the OU is.)
    static let oidOrganizationalUnit = "2.5.4.11"

    /// Extract the Team ID from a DER-encoded X.509 certificate.
    ///
    /// This is the **only** source of the team that does not need a
    /// provisioning profile. That matters because:
    ///
    ///   * A `.mobileprovision` is a *profile* artefact — it says which team
    ///     may sign an app, not which team the private key belongs to.
    ///   * CI builds and most side-loading tools produce an app with **no
    ///     embedded profile at all**, so a profile-only lookup returns nil
    ///     exactly in the case where the team is needed.
    ///
    /// The certificate itself always carries it.
    ///
    /// - Returns the team id (e.g. "PQQC56VX22") or nil.
    static func teamID(inCertificateDER data: Data) -> String? {
        let r = Reader(data)

        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        guard let cert = r.at(0), cert.tag == SEQUENCE else { return nil }
        let certParts = r.children(cert)
        guard let tbs = certParts.first else { return nil }

        // TBSCertificate ::= SEQUENCE {
        //   version [0] EXPLICIT OPTIONAL, serialNumber, signature,
        //   issuer, validity, subject, ... }
        let tb = r.children(tbs)
        var idx = 0
        if tb.first?.tag == 0xA0 { idx = 1 }        // skip the explicit [0] version
        // serialNumber, signature, issuer, validity → subject is next
        guard tb.count > idx + 4 else { return nil }
        let subject = tb[idx + 4]
        guard subject.tag == SEQUENCE else { return nil }

        // Subject ::= RDNSequence OF RelativeDistinguishedName
        // RDN ::= SET OF AttributeTypeAndValue
        // ATV ::= SEQUENCE { type OID, value ANY }
        for rdn in r.children(subject) {
            for atv in r.children(rdn) {
                let fields = r.children(atv)
                guard fields.count >= 2 else { continue }
                guard oidString(fields[0], r) == oidOrganizationalUnit else { continue }

                // The value is a DirectoryString; UTF8String / PrintableString
                // / IA5String all carry the text as raw bytes here.
                let raw = r.slice(fields[1])
                if let s = String(bytes: raw, encoding: .utf8),
                   s.rangeOfCharacter(from: .alphanumerics) != nil {
                    return s.trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
        }
        return nil
    }
}
