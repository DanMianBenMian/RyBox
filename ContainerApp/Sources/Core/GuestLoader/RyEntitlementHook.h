#ifndef RyEntitlementHook_h
#define RyEntitlementHook_h
#ifdef __cplusplus
extern "C" {
#endif

/// Callback the Swift side installs to answer "what entitlement does the
/// running guest hold?". The returned string is a property-list fragment
/// (XML plist) describing the value, or NULL when the key is unknown.
typedef const char *(*RyEntitlementLookup)(const char *key);

/// Install the lookup used by `RyEntitlementAnswer`.
void RyInstallEntitlementLookup(RyEntitlementLookup lookup);

/// Ask the container for an entitlement value of the running guest.
/// Returns a malloc'd NUL-terminated plist string, or NULL when the guest
/// does not hold that entitlement. The caller frees the buffer.
char *RyEntitlementAnswer(const char *key);

#ifdef __cplusplus
}
#endif
#endif /* RyEntitlementHook_h */
