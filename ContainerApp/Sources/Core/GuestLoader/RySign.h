#ifndef RySign_h
#define RySign_h
#ifdef __cplusplus
extern "C" {
#endif

/// Re-sign every Mach-O in `bundlePath` (main executable + frameworks/dylibs)
/// with the identity from `p12Path`/`password` and the provisioning profile at
/// `provPath`. Optional `entitlementsPath` overrides the guest entitlements.
///
/// This is the on-device signing helper ("codesign") RyBox bundles so imported
/// guests pass AMFI on a non-jailbroken device. It uses only Security +
/// CommonCrypto (no OpenSSL / third-party deps) so it compiles cleanly for iOS.
///
/// Returns 0 on success, non-zero on failure.
///
/// ⚠️ This entry goes through `SecPKCS12Import`, which cannot read a p12 written
/// by OpenSSL 3.x (PBES2 / AES-256-CBC / PBKDF2) — it returns 3 for those.
/// Prefer `rysign_sign_bundle_with_der` below.
int rysign_sign_bundle(const char *bundlePath,
                       const char *p12Path,
                       const char *password,
                       const char *provPath,
                       const char *entitlementsPath);

/// Re-sign a bundle from ALREADY-DECODED identity material: a DER certificate
/// and a DER private key (PKCS#1 `RSAPrivateKey` for RSA, SEC1 `ECPrivateKey`
/// for EC — the inner key, not the PKCS#8 wrapper).
///
/// RyBox decodes the p12 itself (`RyP12`) precisely because Apple's importer
/// rejects modern p12 files, so this is the normal path. `keyIsEC` selects the
/// key type; the CMS builder picks the signature algorithm by key type
/// (RSA → PKCS#1 v1.5 SHA-256, EC → ECDSA X9.62 SHA-256).
///
/// Returns 0 on success, non-zero on failure.
int rysign_sign_bundle_with_der(const char *bundlePath,
                                const char *certDerPath,
                                const char *keyDerPath,
                                int keyIsEC,
                                const char *provPath,
                                const char *entitlementsPath);

/// Re-sign a bundle from identity material whose profile has ALREADY been
/// decoded by Swift (`CMSDecoder` + `PropertyListSerialization`, which handle
/// the CMS-wrapped *binary* plist that the in-C parser cannot read).
///
/// `leafCertDerPath` / `keyDerPath` are the DER leaf cert + private key,
/// `entitlementsPath` is an XML plist of the guest entitlements, `team` is the
/// TeamIdentifier string, and `certsDir` is a directory of `*.der` files (the
/// rest of the trust chain: intermediate + root). The provisioning profile at
/// `provPath` is embedded (AMFI requires it) but no longer parsed.
///
/// This is the normal path now — `rysign_sign_bundle_with_der` is retained only
/// for the legacy p12 import.
int rysign_sign_bundle_robust(const char *bundlePath,
                              const char *leafCertDerPath,
                              const char *keyDerPath,
                              int keyIsEC,
                              const char *provPath,
                              const char *entitlementsPath,
                              const char *team,
                              const char *certsDir);

/// Override the CodeDirectory identifier used for every Mach-O signed by this
/// module.
///
/// LiveContainer parity: ZSign is driven with `bundleId: NSBundle.mainBundle
/// .bundleIdentifier` — the HOST app's id, because the guest is signed with the
/// host's certificate AND the host's provisioning profile. Passing NULL (or an
/// empty string) restores the default, which is the guest's own
/// `CFBundleIdentifier` read from its Info.plist.
void rysign_set_code_identity(const char *ident);

/// Hand the signer the guest's Info.plist FILE BYTES (special slot -1). If not
/// called, the signer reads Info.plist from the bundle on disk. Provided so the
/// Swift side can pass a binary plist's raw bytes directly; the in-C fallback
/// uses CoreFoundation, which parses BOTH XML and binary plists (this is what
/// fixed the old rc=6 on Sileo, whose Info.plist is `bplist00`).
void rysign_set_info_plist(const char *exeName,
                           const unsigned char *plist, size_t len);

/// The sub-code of the last failure inside the main-executable signing step
/// (the outer exit code 6 covers many causes). Values are the internal
/// `sign_slice` / `sign_macho_file_at` return codes:
///   -1  file unreadable or truncated      -6  SuperBlob assembly failed
///   -2  no LC_CODE_SIGNATURE (no room)    -7  buffer growth failed
///   -3  Requirements build failed         -8  path is not a regular file
///   -4  CodeDirectory build failed        -9  not a 64-bit Mach-O
///   -5  CMS build failed (key refused)   -10  write-back failed
/// 0 means the last run succeeded. Call it right after a non-zero return from
/// any `rysign_sign_bundle*` to tell the user WHERE signing died.
int rysign_last_subcode(void);

#ifdef __cplusplus
}
#endif
#endif /* RySign_h */
