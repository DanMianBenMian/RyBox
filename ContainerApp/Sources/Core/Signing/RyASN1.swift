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
}
