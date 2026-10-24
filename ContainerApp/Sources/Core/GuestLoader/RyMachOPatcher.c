#include "RyMachOPatcher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <mach-o/loader.h>
#include <mach-o/fixups.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>
#include <libkern/OSByteOrder.h>

#ifndef MH_DYLIB
#define MH_DYLIB 0x6
#endif

// A command id that exists in no Mach-O spec. dyld skips load commands it does
// not recognise, which is how LiveContainer neutralises a duplicate
// LC_LOAD_DYLIB — dyld otherwise aborts with "duplicate dylib" and the guest
// never starts (LiveContainer issue #582).
#define RY_DEAD_COMMAND 0x114515

static uint32_t rnd32(uint32_t v, uint32_t r) { r--; return (v + r) & ~r; }

// ---------------------------------------------------------------------------
// Load-command helpers
// ---------------------------------------------------------------------------

/// Walk the load commands. Returns the file offset of the first byte that is
/// NOT load commands (the `__text` section, or 0 when it cannot be determined).
///
/// The old code used `__TEXT`'s `fileoff`, which is 0 for essentially every
/// Mach-O executable — so every "is there room for another command" test
/// silently failed and the rpath injection never ran at all.
static uint32_t loadCommandsEndOffset(const struct mach_header_64 *hdr) {
    const struct load_command *lc =
        (const struct load_command *)((const uint8_t *)hdr + sizeof(*hdr));
    uint32_t best = 0;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            const struct section_64 *sects = (const struct section_64 *)(seg + 1);
            for (uint32_t s = 0; s < seg->nsects; s++) {
                if (sects[s].offset > 0 && (best == 0 || sects[s].offset < best)) {
                    best = sects[s].offset;
                }
            }
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    return best;
}

/// Does the header already carry a command of this type?
static bool hasCommand(const struct mach_header_64 *hdr, uint32_t cmd) {
    const struct load_command *lc =
        (const struct load_command *)((const uint8_t *)hdr + sizeof(*hdr));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == cmd) return true;
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    return false;
}

/// Insert a dylib command at the FRONT of the load-command list, like dylibify
/// and LiveContainer both do. Returns true when it was inserted.
static bool insertDylibCommandAtFront(uint32_t cmd, const char *name,
                                      struct mach_header_64 *hdr,
                                      uint32_t boundary) {
    if (boundary == 0) return false;
    size_t cmdsize = sizeof(struct dylib_command) + rnd32((uint32_t)strlen(name) + 1, 8);
    uint8_t *first = (uint8_t *)hdr + sizeof(*hdr);
    size_t used = hdr->sizeofcmds;
    if ((uintptr_t)first + used + cmdsize > (uintptr_t)hdr + boundary) return false; // no room

    memmove(first + cmdsize, first, used);
    memset(first, 0, cmdsize);
    struct dylib_command *d = (struct dylib_command *)first;
    d->cmd = cmd;
    d->cmdsize = (uint32_t)cmdsize;
    d->dylib.name.offset = sizeof(struct dylib_command);
    d->dylib.compatibility_version = 0x10000;
    d->dylib.current_version = 0x10000;
    d->dylib.timestamp = 2;
    strncpy((char *)d + d->dylib.name.offset, name, strlen(name));
    hdr->ncmds++;
    hdr->sizeofcmds += (uint32_t)cmdsize;
    return true;
}

/// LiveContainer's `replaceDylinkerWithIDDylibCommand`: when there is no room
/// for a fresh LC_ID_DYLIB, reuse the (useless-for-a-dylib) LC_LOAD_DYLINKER's
/// space for it.
///
/// A dylinker_command is only 12 + path bytes (28 for "/usr/lib/dyld"), while a
/// dylib_command is 32 + path — so the "reuse" can only ever hold a very short
/// name, and a naive port of LiveContainer's version underflows its `nameSize`
/// and writes far past the command. Guard the size, and fall back to deleting
/// the command outright (see `deleteLoadCommand`) when it does not fit.
static bool reuseDylinkerForIDDylib(struct dylinker_command *dylinkerCommand,
                                    const char *name) {
    uint32_t size = dylinkerCommand->cmdsize;
    uint32_t need = (uint32_t)sizeof(struct dylib_command) + 8;  // header + NUL-padded name
    if (size < need) return false;

    struct dylib_command *d = (struct dylib_command *)dylinkerCommand;
    d->cmd = LC_ID_DYLIB;
    d->cmdsize = size;
    d->dylib.name.offset = sizeof(struct dylib_command);
    d->dylib.compatibility_version = 0x10000;
    d->dylib.current_version = 0x10000;
    d->dylib.timestamp = 2;
    uint32_t nameSize = size - (uint32_t)sizeof(struct dylib_command);
    strncpy((char *)d + d->dylib.name.offset, name, nameSize - 1);
    *((char *)d + d->dylib.name.offset + nameSize - 1) = 0;
    return true;
}

/// Remove the first load command of the given type, compacting the rest down.
/// Returns the bytes freed (0 when the command was not present).
static uint32_t deleteLoadCommand(struct mach_header_64 *hdr, uint32_t cmd) {
    uint8_t *base = (uint8_t *)hdr + sizeof(*hdr);
    struct load_command *lc = (struct load_command *)base;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == cmd) {
            uint32_t csz = lc->cmdsize;
            size_t rest = hdr->sizeofcmds - (((uint8_t *)lc - base) + csz);
            memmove(lc, (uint8_t *)lc + csz, rest);
            hdr->ncmds--;
            hdr->sizeofcmds -= csz;
            return csz;
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return 0;
}

/// Neutralise duplicate dependency commands. dyld aborts on a repeated
/// LC_LOAD_DYLIB; marking the extras with an unknown id makes it skip them.
static void dedupeLoadDylibs(struct mach_header_64 *hdr) {
    struct load_command *lc =
        (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));
    int depCount = 0;
    const char **depPaths = malloc(sizeof(char *) * (hdr->ncmds + 1));
    if (!depPaths) return;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        bool isDep = (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB ||
                      lc->cmd == LC_REEXPORT_DYLIB || lc->cmd == LC_LOAD_UPWARD_DYLIB);
        if (isDep) {
            const char *loadPath =
                (const char *)lc + ((struct dylib_command *)lc)->dylib.name.offset;
            bool duplicate = false;
            for (int j = 0; j < depCount; ++j) {
                if (strcmp(loadPath, depPaths[j]) == 0) { duplicate = true; break; }
            }
            if (duplicate) {
                lc->cmd = RY_DEAD_COMMAND;      // dyld skips unknown commands
            } else if (depCount < (int)hdr->ncmds) {
                depPaths[depCount++] = loadPath;
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    free(depPaths);
}

/// LiveContainer's `LCChangeMachOUUID`: bump the first byte of LC_UUID so iOS
/// does not consider two executables the same image. RyBox patches and re-signs
/// the same guest on every launch, so without this the UUID is stable and the
/// OS-level image bookkeeping can collide with a previous (torn-down) copy.
static void changeMachOUUID(struct mach_header_64 *hdr) {
    struct load_command *lc =
        (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_UUID) {
            struct uuid_command *u = (struct uuid_command *)lc;
            u->uuid[0] = (uint8_t)(u->uuid[0] + 1);
            return;
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
}

/// iOS 27's dyld4 rejects an image whose chained-fixups segment count disagrees
/// with the number of LC_SEGMENT_64 commands in the header
/// (`PATCH_EXEC_RESULT_SEG_COUNT_MISMATCH` in LiveContainer, which then has to
/// bypass the check at dlopen time). We make the two numbers agree instead —
/// a pure data fix that needs no runtime hook.
///
/// Returns true when a mismatch was found (and repaired).
static bool fixChainedFixupsSegCount(struct mach_header_64 *hdr) {
    uint32_t segCount = 0;
    struct linkedit_data_command *fixups = NULL;
    struct load_command *lc =
        (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            segCount++;
        } else if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) {
            fixups = (struct linkedit_data_command *)lc;
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    if (!fixups || fixups->dataoff == 0 ||
        fixups->datasize < sizeof(struct dyld_chained_fixups_header)) {
        return false;
    }
    struct dyld_chained_fixups_header *fh =
        (struct dyld_chained_fixups_header *)((uint8_t *)hdr + fixups->dataoff);
    if (fh->starts_offset == 0 ||
        fh->starts_offset + sizeof(struct dyld_chained_starts_in_image) > fixups->datasize) {
        return false;
    }
    uint32_t *declared =
        (uint32_t *)((uint8_t *)hdr + fixups->dataoff + fh->starts_offset);
    if (*declared == segCount) return false;

    fprintf(stderr, "rybox: chained-fixups seg count %u != LC_SEGMENT_64 count %u, normalising\n",
            *declared, segCount);
    *declared = segCount;
    return true;
}

/// Does this Mach-O already carry an LC_RPATH with exactly this string?
static bool hasRPath(const char *path, const struct mach_header_64 *hdr) {
    const struct load_command *lc =
        (const struct load_command *)((const uint8_t *)hdr + sizeof(*hdr));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_RPATH) {
            const struct rpath_command *rp = (const struct rpath_command *)lc;
            const char *p = (const char *)rp + rp->path.offset;
            if (strcmp(p, path) == 0) return true;
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    return false;
}

/// Append an LC_RPATH at the end of the load commands when there is room.
static void injectRPath(const char *path, struct mach_header_64 *hdr, uint32_t boundary) {
    if (boundary == 0) return;
    if (hasRPath(path, hdr)) return;

    size_t cmdSize = sizeof(struct rpath_command) + rnd32((uint32_t)strlen(path) + 1, 8);
    uint8_t *cmdEnd = (uint8_t *)hdr + sizeof(*hdr) + hdr->sizeofcmds;
    if ((uintptr_t)cmdEnd + cmdSize > (uintptr_t)hdr + boundary) return; // no room, skip

    struct rpath_command *rp = (struct rpath_command *)cmdEnd;
    memset(rp, 0, cmdSize);
    rp->cmd = LC_RPATH;
    rp->cmdsize = (uint32_t)cmdSize;
    rp->path.offset = sizeof(struct rpath_command);
    strncpy((char *)rp + rp->path.offset, path, strlen(path));
    hdr->ncmds++;
    hdr->sizeofcmds += (uint32_t)cmdSize;
}

// ---------------------------------------------------------------------------
// The patch itself — LiveContainer's LCPatchExecSlice, ported
// ---------------------------------------------------------------------------
static int patchSlice(const char *path, struct mach_header_64 *hdr) {
    if (hdr->magic != MH_MAGIC_64) return -1;

    // Literally convert an executable to a dylib.
    hdr->filetype = MH_DYLIB;
    hdr->flags |= MH_NO_REEXPORTED_DYLIBS;
    hdr->flags &= ~MH_PIE;

    // Shrink __PAGEZERO to a single zero page so the guest fits inside the
    // host address space ("out of address space" otherwise).
    struct load_command *lc = (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (seg->vmaddr == 0) {            // __PAGEZERO
                seg->vmaddr = 0x100000000 - 0x4000;
                seg->vmsize = 0x4000;
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    uint32_t boundary = loadCommandsEndOffset(hdr);

    // A Mach-O with filetype MH_DYLIB MUST carry LC_ID_DYLIB: dyld reads it as
    // the image's install name and refuses a converted executable that has
    // none. This is the single biggest thing the old patcher was missing, and
    // it is why Sileo never came up.
    if (!hasCommand(hdr, LC_ID_DYLIB)) {
        char name[1024] = {0};
        // basename() may modify its argument and is not thread-safe — copy first.
        snprintf(name, sizeof(name), "%s", path ? path : "Guest");
        char *slash = strrchr(name, '/');
        const char *base = slash ? slash + 1 : name;
        if (*base == 0) base = "Guest";

        if (!insertDylibCommandAtFront(LC_ID_DYLIB, base, hdr, boundary)) {
            // No room for a new command. Two ways out, in order of preference:
            //   1. reuse the LC_LOAD_DYLINKER slot — it is meaningless for a
            //      dylib anyway (LiveContainer issue #1042);
            //   2. delete LC_LOAD_DYLINKER and try the insert again.
            struct load_command *scan =
                (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));
            for (uint32_t i = 0; i < hdr->ncmds; i++) {
                if (scan->cmd == LC_LOAD_DYLINKER) {
                    if (reuseDylinkerForIDDylib((struct dylinker_command *)scan, base)) break;
                    deleteLoadCommand(hdr, LC_LOAD_DYLINKER);
                    insertDylibCommandAtFront(LC_ID_DYLIB, base, hdr, boundary);
                    break;
                }
                scan = (struct load_command *)((uint8_t *)scan + scan->cmdsize);
            }
        }
        // Recompute: inserting at the front may have consumed the last bytes.
        boundary = loadCommandsEndOffset(hdr);
    }

    dedupeLoadDylibs(hdr);

    // Frameworks / plugins inside the guest bundle.
    injectRPath("@loader_path", hdr, boundary);
    injectRPath("@executable_path/Frameworks", hdr, boundary);

    changeMachOUUID(hdr);
    fixChainedFixupsSegCount(hdr);

    return 0;
}

int RyPatchGuestExecutable(const char *execPath) {
    if (!execPath) return -1;
    int fd = open(execPath, O_RDWR, 0);
    if (fd < 0) { perror("RyPatch open"); return -2; }

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -3; }

    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("RyPatch mmap"); close(fd); return -4; }

    uint32_t magic = *(uint32_t *)map;
    int rc = 0;

    if (magic == MH_MAGIC_64) {
        rc = patchSlice(execPath, (struct mach_header_64 *)map);
    } else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        int swap = (magic == FAT_CIGAM);
        struct fat_header *fh = (struct fat_header *)map;
        uint32_t n = swap ? OSSwapInt32(fh->nfat_arch) : fh->nfat_arch;
        struct fat_arch *arch = (struct fat_arch *)(fh + 1);
        bool patched = false;
        for (uint32_t i = 0; i < n; i++) {
            struct fat_arch a = arch[i];
            if (swap) {
                a.cputype    = OSSwapInt32(a.cputype);
                a.cpusubtype = OSSwapInt32(a.cpusubtype);
                a.offset     = OSSwapInt32(a.offset);
                a.size       = OSSwapInt32(a.size);
            }
            if (a.cputype == CPU_TYPE_ARM64) {
                if (patchSlice(execPath, (struct mach_header_64 *)((uint8_t *)map + a.offset)) == 0) {
                    patched = true;
                }
            }
        }
        rc = patched ? 0 : -5;
    } else {
        rc = -6; // unknown magic
    }

    if (rc == 0) {
        if (msync(map, (size_t)st.st_size, MS_SYNC) != 0) rc = -7;
    }
    munmap(map, (size_t)st.st_size);
    close(fd);
    return rc;
}
