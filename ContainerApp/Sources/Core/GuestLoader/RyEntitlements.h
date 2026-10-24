#ifndef RyEntitlements_h
#define RyEntitlements_h

// `size_t` is used in the API below. A bridging header is included very early
// in the translation unit, before <stddef.h> may have been pulled in, so the
// type has to be pulled in explicitly.
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Extract the entitlements blob embedded in a Mach-O's code signature.
///
/// The blob is an XML property list (the same one `codesign -d --entitlements`
/// prints). It is the app's ORIGINAL, developer-signed entitlement set — the
/// one an IPA shipped with. Reading it is what lets RyBox preserve an app's
/// capabilities (HealthKit, App Groups, keychain groups, background modes,
/// …) instead of silently dropping them when the bundle is re-signed with the
/// user's own distribution certificate.
///
/// - Returns 0 on success and fills `*out` with a malloc'd NUL-terminated
///   buffer the caller must `free()`. Returns non-zero when the file is not a
///   Mach-O, carries no code signature, or has no entitlements blob.
int ry_macho_entitlements(const char *path, char **out, size_t *outLen);

#ifdef __cplusplus
}
#endif
#endif /* RyEntitlements_h */
