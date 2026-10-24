// RyEntitlements — read the ORIGINAL entitlements out of a Mach-O.
//
// Problem this solves: when RyBox re-signs a guest app with the user's own
// distribution certificate, the entitlements that ship with the IPA (the
// developer's own, from the original signature) are thrown away. AMFI then
// sees a binary that claims capabilities it no longer has, and the app either
// refuses to launch or silently loses features (HealthKit, App Groups,
// keychain sharing, background modes, push, …).
//
// The fix is to READ the original entitlements blob out of the guest's
// code signature BEFORE re-signing, then merge it with the entitlements the
// user's provisioning profile grants (see CodeSigner / EntitlementMerger).
//
// Layout of an embedded code signature (all big-endian):
//
//   LC_CODE_SIGNATURE -> SuperBlob (0xFADE0CC0)
//       count, BlobIndex[] { type, offset }
//       BlobIndex[CSSLOT_ENTITLEMENTS] -> Blob (0xFADE7171) -> XML plist
//
// The XML plist payload is exactly what `codesign -d --entitlements` prints.

#include "../GuestLoader/RyEntitlements.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#ifndef MH_DYLIB
#define MH_DYLIB 0x6
#endif

#define CSMAGIC_EMBEDDED_SIGNATURE   0xFADE0CC0u
#define CSMAGIC_EMBEDDED_ENTITLEMENTS 0xFADE7171u
#define CSSLOT_ENTITLEMENTS 5

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/// Read the entitlements XML out of a mapped Mach-O image.
/// Returns a malloc'd NUL-terminated buffer, or NULL.
static char *entitlements_from_image(const uint8_t *base, size_t size) {
    if (size < sizeof(struct mach_header_64)) return NULL;

    uint32_t magic;
    memcpy(&magic, base, 4);
    if (magic == MH_MAGIC_64) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)base;
        if (h->ncmds == 0) return NULL;
        const uint8_t *cmd = base + sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < h->ncmds; i++) {
            if (cmd + sizeof(struct load_command) > base + size) return NULL;
            uint32_t cmdv, cmdsize;
            memcpy(&cmdv, cmd, 4);
            memcpy(&cmdsize, cmd + 4, 4);
            if (cmdsize == 0) return NULL;
            if (cmdv == LC_CODE_SIGNATURE) {
                uint32_t dataoff, datasize;
                memcpy(&dataoff, cmd + 8, 4);
                memcpy(&datasize, cmd + 12, 4);
                if ((size_t)dataoff + datasize > size) return NULL;
                const uint8_t *sig = base + dataoff;
                if (datasize < 12) return NULL;
                if (be32(sig) != CSMAGIC_EMBEDDED_SIGNATURE) return NULL;
                uint32_t count = be32(sig + 8);
                if (count > 64) return NULL;
                for (uint32_t k = 0; k < count; k++) {
                    const uint8_t *idx = sig + 12 + (size_t)k * 8;
                    if (idx + 8 > sig + datasize) return NULL;
                    uint32_t type = be32(idx);
                    uint32_t off = be32(idx + 4);
                    if (type != CSSLOT_ENTITLEMENTS) continue;
                    if ((size_t)off + 8 > datasize) return NULL;
                    const uint8_t *blob = sig + off;
                    if (be32(blob) != CSMAGIC_EMBEDDED_ENTITLEMENTS) return NULL;
                    uint32_t blen = be32(blob + 4);
                    if (blen < 8 || (size_t)off + blen > datasize) return NULL;
                    uint32_t plen = blen - 8;
                    if (plen == 0) return NULL;
                    char *out = (char *)malloc(plen + 1);
                    if (!out) return NULL;
                    memcpy(out, blob + 8, plen);
                    out[plen] = 0;
                    return out;
                }
                return NULL;
            }
            cmd += cmdsize;
        }
    }
    return NULL;
}

int ry_macho_entitlements(const char *path, char **out, size_t *outLen) {
    if (!path || !out) return 1;
    *out = NULL;
    if (outLen) *outLen = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return 2;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return 3; }

    size_t size = (size_t)st.st_size;
    void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return 4;

    const uint8_t *base = (const uint8_t *)map;
    char *result = NULL;

    uint32_t magic;
    memcpy(&magic, base, 4);
    if (magic == MH_MAGIC_64) {
        result = entitlements_from_image(base, size);
    } else if (magic == FAT_MAGIC || magic == FAT_MAGIC_64) {
        // Fat binary: scan every slice, take the first one that has
        // entitlements (arm64 slice preferred but any works).
        uint32_t nfat = be32(base + 4);
        if (nfat > 16) nfat = 16;
        for (uint32_t i = 0; i < nfat; i++) {
            const uint8_t *a = base + 8 + (size_t)i * 20;
            if (a + 20 > base + size) break;
            uint32_t off = be32(a + 8);
            uint32_t sz = be32(a + 12);
            if ((size_t)off + sz > size) continue;
            result = entitlements_from_image(base + off, sz);
            if (result) break;
        }
    }

    munmap(map, size);
    if (!result) return 5;
    *out = result;
    if (outLen) *outLen = strlen(result);
    return 0;
}
