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
#define CSMAGIC_CODEDIRECTORY        0xFADE0C02u
#define CSSLOT_ENTITLEMENTS 5
#define CSSLOT_CODEDIRECTORY 0

/// Offset of the `teamOffset` FIELD inside a CodeDirectory blob.
///
/// CodeDirectory header layout (big-endian, matches RySignCore.c's builder):
///   magic 0 | length 4 | version 8 | flags 12 | hashOffset 16 | identOffset 20
///   | nSpecialSlots 24 | nCodeSlots 28 | codeLimit 32 | hashSize 36
///   | hashType 37 | platform 38 | pageSize 39 | spare2 40 | scatterOffset 44
///   | teamOffset 48
///
/// The VALUE of that field is the byte offset of the NUL-terminated team id
/// string, relative to the start of the CodeDirectory blob. It is 0 when the
/// signature carries no team (ad-hoc signatures).
#define CD_TEAM_OFFSET_FIELD 48

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/// Read the team id out of a single (thin) Mach-O image.
static char *team_id_from_image(const uint8_t *base, size_t size);

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

/// Locate the embedded code signature (SuperBlob) inside a mapped Mach-O.
///
/// On success `*sigOut` points at the SuperBlob, `*sigLen` is its size.
/// Returns 0 on success.
static int find_superblob(const uint8_t *base, size_t size,
                           const uint8_t **sigOut, uint32_t *sigLen) {
    if (size < sizeof(struct mach_header_64)) return 1;

    uint32_t magic;
    memcpy(&magic, base, 4);
    if (magic != MH_MAGIC_64) return 1;

    const struct mach_header_64 *h = (const struct mach_header_64 *)base;
    if (h->ncmds == 0) return 1;
    const uint8_t *cmd = base + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (cmd + sizeof(struct load_command) > base + size) return 1;
        uint32_t cmdv, cmdsize;
        memcpy(&cmdv, cmd, 4);
        memcpy(&cmdsize, cmd + 4, 4);
        if (cmdsize == 0) return 1;
        if (cmdv == LC_CODE_SIGNATURE) {
            uint32_t dataoff, datasize;
            memcpy(&dataoff, cmd + 8, 4);
            memcpy(&datasize, cmd + 12, 4);
            if ((size_t)dataoff + datasize > size) return 1;
            const uint8_t *sig = base + dataoff;
            if (datasize < 12) return 1;
            if (be32(sig) != CSMAGIC_EMBEDDED_SIGNATURE) return 1;
            *sigOut = sig;
            *sigLen = datasize;
            return 0;
        }
        cmd += cmdsize;
    }
    return 1;
}

/// Walk the SuperBlob's index and return the first blob of the wanted type.
///
/// `magic` is the expected blob magic (0 to accept any). `*blobOut` /
/// `*blobLen` describe the blob header (magic + length included).
static int find_superblob_blob(const uint8_t *sig, uint32_t sigLen,
                                uint32_t wantType, uint32_t wantMagic,
                                const uint8_t **blobOut, uint32_t *blobLen) {
    uint32_t count = be32(sig + 8);
    if (count > 64) return 1;
    for (uint32_t k = 0; k < count; k++) {
        const uint8_t *idx = sig + 12 + (size_t)k * 8;
        if (idx + 8 > sig + sigLen) return 1;
        uint32_t type = be32(idx);
        uint32_t off = be32(idx + 4);
        if (type != wantType) continue;
        if ((size_t)off + 8 > sigLen) return 1;
        const uint8_t *blob = sig + off;
        uint32_t bm = be32(blob);
        uint32_t blen = be32(blob + 4);
        if (wantMagic && bm != wantMagic) continue;
        if (blen < 8 || (size_t)off + blen > sigLen) return 1;
        *blobOut = blob;
        *blobLen = blen;
        return 0;
    }
    return 1;
}

/// Read the TEAM ID out of a mapped Mach-O's code signature.
///
/// The team id lives in the CodeDirectory (`teamOffset` field) and is written
/// by whoever signed the binary. It is the single most reliable source for
/// "which team signed this image" — it needs no provisioning profile, so it
/// works for ad-hoc builds, for side-loaders that do not embed a profile, and
/// for App Store builds alike.
///
/// - Returns 0 on success and fills `*out` with a malloc'd NUL-terminated
///   buffer the caller must `free()`. Returns non-zero when the image has no
///   code signature, no CodeDirectory, or no team id (ad-hoc signature).
int ry_macho_team_id(const char *path, char **out) {
    if (!path || !out) return 1;
    *out = NULL;

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
        result = team_id_from_image(base, size);
    } else if (magic == FAT_MAGIC || magic == FAT_MAGIC_64) {
        uint32_t nfat = be32(base + 4);
        if (nfat > 16) nfat = 16;
        for (uint32_t i = 0; i < nfat; i++) {
            const uint8_t *a = base + 8 + (size_t)i * 20;
            if (a + 20 > base + size) break;
            uint32_t off = be32(a + 8);
            uint32_t sz = be32(a + 12);
            if ((size_t)off + sz > size) continue;
            result = team_id_from_image(base + off, sz);
            if (result) break;
        }
    }

    munmap(map, size);
    if (!result) return 5;
    *out = result;
    return 0;
}

/// Read the team id out of a single Mach-O image (thin slice).
static char *team_id_from_image(const uint8_t *base, size_t size) {
    const uint8_t *sig = NULL;
    uint32_t sigLen = 0;
    if (find_superblob(base, size, &sig, &sigLen) != 0) return NULL;

    const uint8_t *cd = NULL;
    uint32_t cdLen = 0;
    if (find_superblob_blob(sig, sigLen, CSSLOT_CODEDIRECTORY,
                            CSMAGIC_CODEDIRECTORY, &cd, &cdLen) != 0)
        return NULL;

    if (cdLen < CD_TEAM_OFFSET_FIELD + 4) return NULL;
    uint32_t teamOff = be32(cd + CD_TEAM_OFFSET_FIELD);
    if (teamOff == 0 || teamOff >= cdLen) return NULL;   // ad-hoc: no team

    // The team string is NUL-terminated and lives inside the CD blob.
    size_t maxLen = cdLen - teamOff;
    size_t len = 0;
    while (len < maxLen && cd[teamOff + len] != 0) len++;
    if (len == 0) return NULL;

    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, cd + teamOff, len);
    out[len] = 0;
    return out;
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
