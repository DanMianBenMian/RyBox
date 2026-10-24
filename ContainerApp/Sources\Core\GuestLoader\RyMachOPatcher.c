#include "RyMachOPatcher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>
#include <libkern/OSByteOrder.h>

#ifndef MH_DYLIB
#define MH_DYLIB 0x6
#endif

static uint32_t rnd32(uint32_t v, uint32_t r) { r--; return (v + r) & ~r; }

/// Patch a single 64-bit Mach-O slice that is already mapped RW.
static int patchSlice(struct mach_header_64 *hdr) {
    if (hdr->magic != MH_MAGIC_64) return -1;

    // Convert executable -> dylib, exactly like LiveContainer.
    hdr->filetype = MH_DYLIB;
    hdr->flags |= MH_NO_REEXPORTED_DYLIBS;
    hdr->flags &= ~MH_PIE;

    // Shrink __PAGEZERO so the guest loads inside the host address space.
    struct load_command *lc = (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (seg->vmaddr == 0) {            // __PAGEZERO
                seg->vmaddr = 0xFFFFC000;       // 0x100000000 - 0x4000
                seg->vmsize = 0x4000;
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return 0;
}

/// Inject an LC_RPATH if there is room before __TEXT (best-effort).
static void injectRPath(const char *path, struct mach_header_64 *hdr) {
    // Only inject if there is free space between the load commands and __TEXT,
    // otherwise skip silently (guest already signed with the needed rpaths, or we
    // rely on @loader_path which is implicit).
    struct load_command *lc = (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));
    uint32_t textOffset = 0;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) { textOffset = (uint32_t)seg->fileoff; break; }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    if (textOffset == 0) return;

    size_t cmdSize = sizeof(struct rpath_command) + rnd32((uint32_t)strlen(path) + 1, 8);
    // Free space left before __TEXT?
    uint8_t *cmdEnd = (uint8_t *)hdr + sizeof(*hdr) + hdr->sizeofcmds;
    if ((uintptr_t)cmdEnd + cmdSize > (uintptr_t)hdr + textOffset) return; // no room, skip

    struct rpath_command *rp = (struct rpath_command *)cmdEnd;
    memset(rp, 0, cmdSize);
    rp->cmd = LC_RPATH;
    rp->cmdsize = (uint32_t)cmdSize;
    rp->path.offset = sizeof(struct rpath_command);
    strncpy((char *)rp + rp->path.offset, path, strlen(path));
    hdr->ncmds++;
    hdr->sizeofcmds += (uint32_t)cmdSize;
}

int RyPatchGuestExecutable(const char *execPath) {
    int fd = open(execPath, O_RDWR, 0);
    if (fd < 0) { perror("RyPatch open"); return -2; }

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -3; }

    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("RyPatch mmap"); close(fd); return -4; }

    uint32_t magic = *(uint32_t *)map;
    int rc = 0;

    if (magic == MH_MAGIC_64) {
        struct mach_header_64 *hdr = (struct mach_header_64 *)map;
        rc = patchSlice(hdr);
        if (rc == 0) { injectRPath("@loader_path", hdr); injectRPath("@executable_path/Frameworks", hdr); }
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
                struct mach_header_64 *slice = (struct mach_header_64 *)((uint8_t *)map + a.offset);
                if (patchSlice(slice) == 0) patched = true;
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
