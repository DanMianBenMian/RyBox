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
/// key type; the CMS builder assumes RSA.
///
/// Returns 0 on success, non-zero on failure.
int rysign_sign_bundle_with_der(const char *bundlePath,
                                const char *certDerPath,
                                const char *keyDerPath,
                                int keyIsEC,
                                const char *provPath,
                                const char *entitlementsPath);

/// Override the CodeDirectory identifier used for every Mach-O signed by this
/// module.
///
/// LiveContainer parity: ZSign is driven with `bundleId: NSBundle.mainBundle
/// .bundleIdentifier` — the HOST app's id, because the guest is signed with the
/// host's certificate AND the host's provisioning profile. Passing NULL (or an
/// empty string) restores the default, which is the guest's own
/// `CFBundleIdentifier` read from its Info.plist.
void rysign_set_code_identity(const char *ident);

#ifdef __cplusplus
}
#endif
#endif /* RySign_h */
