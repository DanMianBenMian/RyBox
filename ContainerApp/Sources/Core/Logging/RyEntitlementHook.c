// RyEntitlementHook — the container's entitlement oracle.
//
// The guest runs INSIDE RyBox's process, so its code signature entitlements
// are the container's, not the app's. An app that asks the system "do I have
// HealthKit / App Groups / my keychain group?" would get the WRONG answer
// (RyBox's set) and degrade itself.
//
// This hook lets the guest ask the CONTAINER instead: the container knows the
// original entitlement set of the imported app (captured from the app's own
// code signature before it was re-signed) and answers from that.
//
// The C side is deliberately tiny: it stores the Swift callback and asks it.

#include "../GuestLoader/RyEntitlementHook.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static RyEntitlementLookup g_lookup = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void RyInstallEntitlementLookup(RyEntitlementLookup lookup) {
    pthread_mutex_lock(&g_lock);
    g_lookup = lookup;
    pthread_mutex_unlock(&g_lock);
}

char *RyEntitlementAnswer(const char *key) {
    if (!key) return NULL;
    pthread_mutex_lock(&g_lock);
    RyEntitlementLookup lookup = g_lookup;
    pthread_mutex_unlock(&g_lock);
    if (!lookup) return NULL;

    const char *answer = lookup(key);
    if (!answer) return NULL;
    size_t len = strlen(answer);
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, answer, len + 1);
    return out;
}
