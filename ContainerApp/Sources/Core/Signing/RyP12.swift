import Foundation
import Security

/// Minimal PKCS#12 (RFC 7292) reader — the FALLBACK for files that
/// `SecPKCS12Import` refuses.
///
/// The problem it solves: OpenSSL 3.x writes p12 files as
/// PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA256. Apple's `SecPKCS12Import` only
/// understands the pre-2010 schemes (RC2-40 / 3DES with the PKCS#12 KDF) and
/// fails on those with an opaque status code. Since almost every signing
/// service now exports with OpenSSL 3, "my distribution certificate is not
/// recognised" is that mismatch, not a bad password.
///
/// We do NOT reimplement the trust path: the certificate is still handed to
/// `SecCertificateCreateWithData` and the private key to
/// `SecKeyCreateWithData`, so nothing here weakens validation. We only perform
/// the decryption Apple skips, then prove the result is a real, well-formed
/// key by having Security parse it.
///
/// The heavy primitives (PBKDF2 / AES-CBC / 3DES-CBC / PKCS#12 KDF) live in
/// RyP12Crypto.c, reached through the bridging header.
enum RyP12 {

    struct Outcome {
        /// Which passphrase actually decrypted the file.
        let password: String
        /// Human readable encryption scheme, e.g. "PBES2 · AES-256-CBC · PBKDF2-SHA256".
        let scheme: String
        /// e.g. "RSA 2048".
        let keyDescription: String
        /// Certificate subject common name.
        let subject: String
        /// True when the file used the modern (OpenSSL 3) algorithms.
        let isModernEncryption: Bool
        /// Leaf certificate, DER. Hand this straight to
        /// `SecCertificateCreateWithData` — no need for a `SecIdentity`.
        let certDER: Data
        /// Private key in the exact form Security's `SecKeyCreateWithData`
        /// wants: PKCS#1 `RSAPrivateKey` for RSA, SEC1 `ECPrivateKey` for EC
        /// (i.e. the INNER key, not the PKCS#8 wrapper).
        let keyDER: Data
        /// The FULL decrypted PKCS#8 `PrivateKeyInfo` (wrapper included).
        ///
        /// Why both forms: the device log (2026-10-25, rc=8 "私钥无法创建")
        /// proved `SecKeyCreateWithData` can refuse a well-formed key — and we
        /// were throwing away the CFError that says which form it wanted, so
        /// nobody could tell PKCS#1 from PKCS#8 rejection. The signer now tries
        /// BOTH readings of the material, and the keychain importer takes the
        /// PKCS#8 first.
        let keyPKCS8: Data
        /// "rsa" or "ec".
        let keyType: String
        /// ALL certificates found in the p12's certBags (leaf + every
        /// intermediate), as DER. The signer needs the FULL chain — not just
        /// the leaf — so the embedded CMS can place the WWDR intermediate at
        /// slot 1 (the DR requires `certificate 1[1.2.840.113635.100.6.2.1
        /// exists]`). A leaf-only CMS fails trust evaluation on a non-jailbroken
        /// device → `code signature invalid (errno=85)` even though the
        /// CodeDirectory hashes are fine. `certDER` is the first entry; the
        /// rest (if any) are intermediates.
        let certChain: [Data]
    }

    // MARK: - Entry point

    /// Decode one p12 with ONE candidate passphrase.
    /// Returns .failure with a reason that is shown to the user as-is.
    static func decode(_ data: Data, password: String) -> Result<Outcome, RyMessageError> {
        let a = ASN1(data)
        guard let pfx = a.at(0) else {
            return .failure("文件无法按 DER 解析（不是 p12/pfx）")
        }
        guard pfx.tag == SEQUENCE else {
            return .failure("文件顶层不是 SEQUENCE，不是 PKCS#12 容器")
        }
        let top = a.children(pfx)
        guard top.count >= 2 else {
            return .failure("PKCS#12 结构不完整（缺少 authSafe）")
        }

        var outerScheme = ""
        guard let authDer = safeContents(a: a, ci: top[1],
                                        password: password, scheme: &outerScheme) else {
            return .failure("解不开 PKCS#12 内容容器：密码不对，或用了 RyBox 尚未支持的加密方式。")
        }

        let a2 = ASN1(Data(authDer))
        guard let safe = a2.at(0), safe.tag == SEQUENCE else {
            return .failure("PKCS#12 内容容器损坏（密码很可能不对）")
        }

        var certDER: [UInt8]?
        /// Every certificate found in the p12 (leaf + intermediates), in bag
        /// order. Drives `Outcome.certChain` — used to embed the full trust
        /// chain so the WWDR intermediate lands at CMS slot 1.
        var certChain: [[UInt8]] = []
        /// Already-decrypted PKCS#8. Decrypted in the loop because the
        /// AlgorithmIdentifier is only meaningful against the array it was
        /// parsed from (each nesting level has its own backing buffer).
        var shroudedKey: [UInt8]?
        var plainKey: [UInt8]?
        var usedScheme = outerScheme

        for ci in a2.children(safe) {
            var scheme = ""
            guard let sc = safeContents(a: a2, ci: ci,
                                        password: password, scheme: &scheme) else { continue }
            if !scheme.isEmpty { usedScheme = scheme }
            let a3 = ASN1(Data(sc))
            guard let scSeq = a3.at(0), scSeq.tag == SEQUENCE else { continue }

            for bag in a3.children(scSeq) {
                let bk = a3.children(bag)
                guard bk.count >= 2, bk[0].tag == OID else { continue }
                let bagId = RyASN1.oidString(bk[0], a3)
                let inner = a3.children(bk[1])          // [0] EXPLICIT bagValue

                switch bagId {
                case oidCertBag:
                    // SEQUENCE { certTypeOid, [0] EXPLICIT OCTET STRING }
                    if let s = inner.first, s.tag == SEQUENCE {
                        let ck = a3.children(s)
                        if ck.count >= 2, let wrapped = a3.children(ck[1]).first,
                           wrapped.tag == OCTET_STRING {
                            let c = a3.slice(wrapped)
                            certChain.append(c)
                            if certDER == nil { certDER = c }
                        }
                    }
                case oidShroudedKeyBag:
                    // SEQUENCE { AlgorithmIdentifier, OCTET STRING(encrypted) }
                    if let s = inner.first, s.tag == SEQUENCE {
                        let ek = a3.children(s)
                        if ek.count >= 2, ek[0].tag == SEQUENCE, ek[1].tag == OCTET_STRING,
                           shroudedKey == nil {
                            var s2 = ""
                            if let plain = decrypt(a: a3, algid: ek[0],
                                                   cipher: a3.slice(ek[1]),
                                                   password: password, scheme: &s2) {
                                shroudedKey = plain
                                if !s2.isEmpty { usedScheme = s2 }
                            }
                        }
                    }
                case oidKeyBag:
                    if let s = inner.first, plainKey == nil { plainKey = a3.slice(s) }
                default:
                    break
                }
            }
        }

        guard let certBytes = certDER else {
            return .failure("PKCS#12 里没有找到证书（certBag）")
        }
        guard let certRef = SecCertificateCreateWithData(nil, Data(certBytes) as CFData) else {
            return .failure("PKCS#12 里的证书无法被 Security 解析")
        }

        let pkcs8: [UInt8]? = plainKey ?? shroudedKey
        guard let key8 = pkcs8 else {
            return .failure("解不出私钥：密码不对，或私钥用了 RyBox 尚不支持的加密方式。")
        }
        guard let keyInfo = inspectPrivateKey(pkcs8: key8) else {
            return .failure("解出来的私钥不是可识别的 PKCS#8 结构（密码很可能不对）")
        }

        let subject = (SecCertificateCopySubjectSummary(certRef) as? String) ?? "证书"
        return .success(Outcome(password: password,
                                scheme: usedScheme.isEmpty ? "未加密 / 系统已解析" : usedScheme,
                                keyDescription: keyInfo.description,
                                subject: subject,
                                isModernEncryption: usedScheme.contains("PBES2"),
                                certDER: Data(certBytes),
                                keyDER: Data(keyInfo.inner),
                                keyPKCS8: Data(key8),
                                keyType: keyInfo.keyType,
                                certChain: certChain.map { Data($0) }))
    }

    // MARK: - ASN.1

    /// The DER primitives live in `RyASN1` — they are shared with the CMS
    /// unwrapper in `CertificateStore`, which needs the same TLV walking.
    private typealias ASN1 = RyASN1.Reader

    private static let SEQUENCE = RyASN1.SEQUENCE
    private static let OID = RyASN1.OID
    private static let OCTET_STRING = RyASN1.OCTET_STRING
    private static let INTEGER = RyASN1.INTEGER

    private static func intValue(_ c: [UInt8]) -> UInt64 {
        var v: UInt64 = 0
        for byte in c { v = (v << 8) | UInt64(byte) }
        return v
    }

    // MARK: - OID table

    private static let oidData            = "1.2.840.113549.1.7.1"
    private static let oidEncryptedData   = "1.2.840.113549.1.7.6"
    private static let oidKeyBag          = "1.2.840.113549.1.12.10.1.1"
    private static let oidShroudedKeyBag  = "1.2.840.113549.1.12.10.1.2"
    private static let oidCertBag         = "1.2.840.113549.1.12.10.1.3"
    private static let oidPBES2          = "1.2.840.113549.1.5.13"
    private static let oidPBKDF2         = "1.2.840.113549.1.5.12"
    private static let oidAES256CBC      = "2.16.840.1.101.3.4.1.42"
    private static let oidAES128CBC      = "2.16.840.1.101.3.4.1.2"
    private static let oid3DESCBC        = "1.2.840.113549.3.7"
    private static let oidP12SHA3DES     = "1.2.840.113549.1.12.1.3"
    private static let oidRSA             = "1.2.840.113549.1.1.1"
    private static let oidEC             = "1.2.840.10045.2.1"

    // MARK: - ContentInfo -> SafeContents bytes

    /// A ContentInfo is either plain `data` (an OCTET STRING holding DER) or
    /// `encryptedData` (which we have to decrypt first).
    private static func safeContents(a: ASN1, ci: RyASN1.Element,
                                     password: String,
                                     scheme: inout String) -> [UInt8]? {
        let kids = a.children(ci)
        guard kids.count >= 2, kids[0].tag == OID else { return nil }
        let type = RyASN1.oidString(kids[0], a)

        if type == oidData {
            guard let wrapped = a.children(kids[1]).first, wrapped.tag == OCTET_STRING else {
                return nil
            }
            return a.slice(wrapped)
        }
        guard type == oidEncryptedData else { return nil }

        // [0] EXPLICIT EncryptedData ::= SEQUENCE { version, EncryptedContentInfo }
        guard let ed = a.children(kids[1]).first, ed.tag == SEQUENCE else { return nil }
        let edKids = a.children(ed)
        guard edKids.count >= 2 else { return nil }
        // EncryptedContentInfo ::= SEQUENCE { type, algid, [0] IMPLICIT OCTET STRING }
        let eci = a.children(edKids[1])
        guard eci.count >= 3, eci[1].tag == SEQUENCE else { return nil }
        return decrypt(a: a, algid: eci[1], cipher: a.slice(eci[2]),
                       password: password, scheme: &scheme)
    }

    // MARK: - Decryption

    /// Tries PBES2 and the legacy PKCS#12 PBE schemes, with both password
    /// encodings (raw UTF-8 is what OpenSSL feeds PBES2; BMPString is the
    /// PKCS#12 rule for the legacy schemes). The first candidate whose
    /// plaintext is a complete, well-formed DER SEQUENCE wins — a wrong
    /// password almost never satisfies that.
    private static func decrypt(a: ASN1, algid: RyASN1.Element, cipher: [UInt8],
                                password: String, scheme: inout String) -> [UInt8]? {
        let kids = a.children(algid)
        guard kids.count >= 2, kids[0].tag == OID else { return nil }
        let alg = RyASN1.oidString(kids[0], a)

        if alg == oidPBES2 {
            return decryptPBES2(a: a, params: kids[1], cipher: cipher,
                                password: password, scheme: &scheme)
        }
        if alg == oidP12SHA3DES {
            return decryptP12SHA1(a: a, params: kids[1], cipher: cipher,
                                  password: password, scheme: &scheme)
        }
        return nil
    }

    private static func decryptPBES2(a: ASN1, params: RyASN1.Element, cipher: [UInt8],
                                     password: String, scheme: inout String) -> [UInt8]? {
        let pk = a.children(params)
        guard pk.count >= 2, pk[0].tag == SEQUENCE, pk[1].tag == SEQUENCE else { return nil }

        // --- PBKDF2 params ---
        let kdf = a.children(pk[0])
        guard kdf.count >= 2, kdf[0].tag == OID, RyASN1.oidString(kdf[0], a) == oidPBKDF2,
              kdf[1].tag == SEQUENCE else { return nil }
        let pb = a.children(kdf[1])
        guard pb.count >= 2, pb[0].tag == OCTET_STRING, pb[1].tag == INTEGER else { return nil }
        let salt = a.slice(pb[0])
        let rounds = UInt32(clamping: intValue(a.slice(pb[1])))

        var prf = 1                                    // SHA-1 unless stated
        var keyLen = 0
        var idx = 2
        if pb.count > idx, pb[idx].tag == INTEGER {
            keyLen = Int(intValue(a.slice(pb[idx])))
            idx += 1
        }
        if pb.count > idx, pb[idx].tag == SEQUENCE {
            let prfKids = a.children(pb[idx])
            if prfKids.count >= 1, prfKids[0].tag == OID {
                switch RyASN1.oidString(prfKids[0], a) {
                case "1.2.840.113549.2.7":  prf = 1
                case "1.2.840.113549.2.8":  prf = 4
                case "1.2.840.113549.2.9":  prf = 2
                case "1.2.840.113549.2.10": prf = 5
                case "1.2.840.113549.2.11": prf = 3
                default:                    prf = 2
                }
            }
        }

        // --- encryption scheme ---
        let enc = a.children(pk[1])
        guard enc.count >= 2, enc[0].tag == OID else { return nil }
        let encOid = RyASN1.oidString(enc[0], a)
        var ccAlg: Int32 = 1
        var defaultKeyLen = 32
        var ivLen = 16
        var cipherName = "AES-256-CBC"
        switch encOid {
        case oidAES256CBC:
            ccAlg = 1; defaultKeyLen = 32; ivLen = 16; cipherName = "AES-256-CBC"
        case oidAES128CBC:
            ccAlg = 1; defaultKeyLen = 16; ivLen = 16; cipherName = "AES-128-CBC"
        case oid3DESCBC:
            ccAlg = 2; defaultKeyLen = 24; ivLen = 8;  cipherName = "3DES-CBC"
        default:
            return nil
        }
        if keyLen <= 0 || keyLen > 64 { keyLen = defaultKeyLen }

        var iv: [UInt8] = []
        if enc[1].tag == OCTET_STRING {
            iv = a.slice(enc[1])
        } else if enc[1].tag == SEQUENCE, let o2 = a.children(enc[1]).first, o2.tag == OCTET_STRING {
            iv = a.slice(o2)
        }
        guard iv.count >= ivLen else { return nil }
        iv = Array(iv.prefix(ivLen))

        for pw in passwordEncodings(password) {
            var key = [UInt8](repeating: 0, count: keyLen)
            guard ry_pbkdf2(Int32(prf), pw, pw.count, salt, salt.count,
                            rounds, &key, keyLen) == 0 else { continue }
            var outBuf = [UInt8](repeating: 0, count: cipher.count + 32)
            let n = Int(ry_cbc_decrypt(ccAlg, key, keyLen, iv, cipher, cipher.count,
                                       &outBuf, outBuf.count))
            guard n > 0 else { continue }
            let plain = Array(outBuf.prefix(n))
            guard looksLikeCompleteDER(plain) else { continue }
            scheme = "PBES2 · \(cipherName) · PBKDF2-\(prfName(prf))"
            return plain
        }
        return nil
    }

    private static func decryptP12SHA1(a: ASN1, params: RyASN1.Element, cipher: [UInt8],
                                        password: String, scheme: inout String) -> [UInt8]? {
        let pk = a.children(params)
        guard pk.count >= 2, pk[0].tag == OCTET_STRING, pk[1].tag == INTEGER else { return nil }
        let salt = a.slice(pk[0])
        let rounds = UInt32(clamping: intValue(a.slice(pk[1])))
        let pw = bmpString(password)

        var key = [UInt8](repeating: 0, count: 24)
        var iv = [UInt8](repeating: 0, count: 8)
        guard ry_p12_kdf_sha1(pw, pw.count, salt, salt.count, rounds, 1, &key, 24, 8) == 24,
              ry_p12_kdf_sha1(pw, pw.count, salt, salt.count, rounds, 2, &iv, 8, 8) == 8 else {
            return nil
        }
        var outBuf = [UInt8](repeating: 0, count: cipher.count + 16)
        let n = Int(ry_cbc_decrypt(2, key, 24, iv, cipher, cipher.count, &outBuf, outBuf.count))
        guard n > 0 else { return nil }
        let plain = Array(outBuf.prefix(n))
        guard looksLikeCompleteDER(plain) else { return nil }
        scheme = "PKCS#12 · 3DES-CBC · SHA-1"
        return plain
    }

    /// A decrypted PKCS#12 blob is always exactly one DER SEQUENCE — a solid
    /// "wrong password" detector since a bad key leaves garbage behind.
    private static func looksLikeCompleteDER(_ plain: [UInt8]) -> Bool {
        guard let firstByte = plain.first, firstByte == SEQUENCE else { return false }
        let a = ASN1(Data(plain))
        guard let e = a.at(0) else { return false }
        return e.end == plain.count
    }

    private static func prfName(_ prf: Int) -> String {
        switch prf {
        case 1: return "SHA1"
        case 2: return "SHA256"
        case 3: return "SHA512"
        case 4: return "SHA224"
        case 5: return "SHA384"
        default: return "SHA256"
        }
    }

    // MARK: - Passwords

    /// OpenSSL hands PBES2 the raw UTF-8 password; the legacy PKCS#12 schemes
    /// mandate BMPString. Try both so we match whatever the exporter did.
    private static func passwordEncodings(_ password: String) -> [[UInt8]] {
        var out: [[UInt8]] = [Array(password.utf8)]
        out.append(bmpString(password))
        return out
    }

    /// UTF-16BE + two NUL bytes (the PKCS#12 BMPString convention).
    private static func bmpString(_ password: String) -> [UInt8] {
        var bmp: [UInt8] = []
        for scalar in password.unicodeScalars {
            let v = scalar.value
            if v > 0xFFFF {
                let d = v - 0x10000
                let hi = 0xD800 + (d >> 10)
                let lo = 0xDC00 + (d & 0x3FF)
                bmp.append(UInt8(hi >> 8)); bmp.append(UInt8(hi & 0xff))
                bmp.append(UInt8(lo >> 8)); bmp.append(UInt8(lo & 0xff))
            } else {
                bmp.append(UInt8(v >> 8)); bmp.append(UInt8(v & 0xff))
            }
        }
        bmp.append(0); bmp.append(0)
        return bmp
    }

    // MARK: - Private key

    /// Validate the decrypted PKCS#8 PrivateKeyInfo and hand back the pieces the
    /// on-device signer needs. Returns nil when the structure is wrong (the usual
    /// sign of a wrong password).
    ///
    /// `inner` is the PKCS#1 `RSAPrivateKey` (RSA) or SEC1 `ECPrivateKey` (EC) —
    /// exactly what `SecKeyCreateWithData` accepts, so the C signer can rebuild a
    /// usable `SecKey` from it without a `SecIdentity` ever existing.
    ///
    /// `key` may legitimately come back nil for EC keys on some iOS versions
    /// even though the DER is fine — we still accept those, because getting a
    /// parseable PKCS#8 out of the ciphertext already proves the password.
    private struct KeyMaterial {
        let description: String
        let keyType: String      // "rsa" / "ec"
        let inner: [UInt8]
    }

    private static func inspectPrivateKey(pkcs8: [UInt8]) -> KeyMaterial? {
        let a = ASN1(Data(pkcs8))
        guard let top = a.at(0), top.tag == SEQUENCE else { return nil }
        let kids = a.children(top)
        guard kids.count >= 3, kids[1].tag == SEQUENCE, kids[2].tag == OCTET_STRING else { return nil }
        let algKids = a.children(kids[1])
        guard algKids.count >= 1, algKids[0].tag == OID else { return nil }
        let algOid = RyASN1.oidString(algKids[0], a)
        let inner = a.slice(kids[2])            // PKCS#1 RSAPrivateKey / SEC1 ECPrivateKey

        var attrs: [String: Any] = [kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        var description = ""
        var keyType = "rsa"

        if algOid == oidRSA {
            keyType = "rsa"
            attrs[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
            var bits = 2048
            let rsa = ASN1(Data(inner))
            if let r = rsa.at(0), r.tag == SEQUENCE {
                let rk = rsa.children(r)
                // PKCS#1: version, modulus, publicExponent, privateExponent...
                if rk.count >= 2, rk[1].tag == INTEGER {
                    let m = rsa.slice(rk[1])
                    var computed = m.count * 8
                    if m.first == 0 { computed -= 8 }
                    if computed > 0 { bits = computed }
                }
            }
            attrs[kSecAttrKeySizeInBits as String] = bits
            description = "RSA \(bits)"
        } else if algOid == oidEC {
            keyType = "ec"
            attrs[kSecAttrKeyType as String] = kSecAttrKeyTypeECSECPrimeRandom
            var bits = 256
            var curveName = "P-256"
            let ec = ASN1(Data(inner))
            if let e = ec.at(0), e.tag == SEQUENCE {
                let ek = ec.children(e)
                // SEC1: version, privateKey, [0] parameters OID, [1] publicKey
                if ek.count >= 3, ek[2].tag == 0xA0, let po = ec.children(ek[2]).first, po.tag == OID {
                    switch RyASN1.oidString(po, ec) {
                    case "1.2.840.10045.3.1.7": bits = 256; curveName = "P-256"
                    case "1.3.132.0.34":        bits = 384; curveName = "P-384"
                    case "1.3.132.0.35":        bits = 521; curveName = "P-521"
                    default: break
                    }
                }
            }
            attrs[kSecAttrKeySizeInBits as String] = bits
            description = "EC \(curveName)"
        } else {
            return nil
        }

        var error: Unmanaged<CFError>?
        // Returns nil (rather than throwing) when Security dislikes the blob;
        // for EC keys that happens on some iOS versions even with valid DER,
        // which is why a nil key here is not treated as a hard failure.
        //
        // 2026-10-25: the device then went on to fail with rc=8 "私钥无法创建"
        // and we had NO idea why, because this CFError was being dropped on the
        // floor (and the C signer dropped its copy too). Log it: the domain +
        // code + description distinguish "unsupported key format" from
        // "parameters rejected" — which is the difference between feeding
        // Security the PKCS#1 inner vs the full PKCS#8.
        let probe = SecKeyCreateWithData(Data(inner) as CFData, attrs as CFDictionary, &error)
        if probe != nil {
            // Security accepted the inner blob. Swift ARC owns the returned
            // SecKey — CFRelease is unavailable in Swift (Core Foundation
            // objects are automatically memory managed).
        } else if let e = error?.takeRetainedValue() {
            // CFError is not directly castable to NSError in Swift; read the
            // domain / code / description through the CF accessors instead.
            let code = CFErrorGetCode(e)
            let domain = (CFErrorGetDomain(e) as String?) ?? "(unknown domain)"
            let desc = (CFErrorCopyDescription(e) as String?) ?? "(no description)"
            RyLog.shared.log("RyP12 探测 SecKeyCreateWithData 失败：[\(domain)] 错误码 \(code)：\(desc)——仍继续，签名器会尝试完整 PKCS#8 与钥匙串两条路",
                             level: .warn, tag: "sign")
        } else {
            RyLog.shared.log("RyP12 探测 SecKeyCreateWithData 返回 nil 且无 CFError", level: .warn, tag: "sign")
        }
        return KeyMaterial(description: description, keyType: keyType, inner: inner)
    }
}
