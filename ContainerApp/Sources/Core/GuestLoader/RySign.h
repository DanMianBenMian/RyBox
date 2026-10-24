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
int rysign_sign_bundle(const char *bundlePath,
                       const char *p12Path,
                       const char *password,
                       const char *provPath,
                       const char *entitlementsPath);

#ifdef __cplusplus
}
#endif
#endif /* RySign_h */
