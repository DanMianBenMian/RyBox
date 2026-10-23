#ifndef LITEHOOK_DYLD_CACHE_FORMAT_H
#define LITEHOOK_DYLD_CACHE_FORMAT_H
// Minimal, layout-faithful reproduction of the structs Apple's `dyld_cache_format.h`
// defines (from the open-source dyld project). This header is NOT part of the public
// iOS SDK, so litehook.c cannot `#include <dyld_cache_format.h>` against the iOS
// toolchain. We vendor the subset litehook references, keeping the stable field
// order (magic -> mappingOffset -> imagesOffset -> localSymbolsOffset ...) identical
// to the real header so on-disk offsets read correctly.
//
// Note: litehook_rebind_symbol (the path RyBox uses) resolves symbols via dladdr +
// __DATA/__AUTH_CONST section walking and does NOT depend on this DSC code; this
// header only exists so the file compiles cleanly.
#include <stdint.h>

struct dyld_cache_image_info
{
    uint8_t    uuid[16];
    uint64_t   address;          // unslid address of the image
    uint64_t   modTime;
    uint32_t   inode;
    uint32_t   pathFileOffset;   // file offset of the image path string
    uint32_t   pad;
};

struct dyld_cache_local_symbols_info
{
    uint32_t   nlistOffset;      // file offset to the nlist array
    uint32_t   nlistCount;       // number of nlist entries
    uint32_t   stringsOffset;    // file offset to the string pool
    uint32_t   stringsSize;      // size of the string pool
    uint32_t   entriesOffset;    // file offset to dyld_cache_local_symbols_entry[_64]
    uint32_t   entriesCount;     // number of per-image entries
};

// Old (32-bit dylib offset) per-image local-symbols entry.
struct dyld_cache_local_symbols_entry
{
    uint32_t   dylibOffset;
    uint32_t   nlistStartIndex;
    uint32_t   nlistCount;
};

// New (64-bit dylib offset) per-image local-symbols entry.
struct dyld_cache_local_symbols_entry_64
{
    uint64_t   dylibOffset;
    uint32_t   nlistStartIndex;
    uint32_t   nlistCount;
};

// NOTE: `struct dyld_uuid_info` is provided by <mach-o/dyld_images.h> (already
// included by litehook.c); do NOT redefine it here.

struct dyld_cache_header
{
    char       magic[16];               // e.g. "dyld_v1   arm64e"
    uint32_t   mappingOffset;           // file offset to first dyld_cache_mapping_info
    uint32_t   mappingCount;
    uint32_t   imagesOffset;            // file offset to first dyld_cache_image_info
    uint32_t   imagesCount;
    uint64_t   dyldBaseAddress;
    uint64_t   codeSignatureOffset;
    uint64_t   codeSignatureSize;
    uint64_t   slideInfoOffset;
    uint64_t   slideInfoSize;
    uint64_t   localSymbolsOffset;      // file offset to dyld_cache_local_symbols_info
    uint64_t   localSymbolsSize;
    uint8_t    uuid[16];
    uint64_t   cacheType;
    uint32_t   branchPoolsOffset;
    uint32_t   branchPoolsCount;
    uint64_t   accelerateInfoAddr;
    uint64_t   accelerateInfoSize;
    uint64_t   imagesTextOffset;
    uint64_t   imagesTextCount;
    uint64_t   patchInfoAddr;
    uint64_t   patchInfoSize;
    uint64_t   otherImageOverlaysAddr;
    uint64_t   otherImageOverlaysSize;
    uint64_t   progClosuresAddr;
    uint64_t   progClosuresSize;
    uint64_t   progClosuresTrieAddr;
    uint64_t   progClosuresTrieSize;
    uint32_t   platform;
    uint32_t   formatVersion;
    uint32_t   dylibsExpectedOnDisk;
    uint32_t   simulator;
    uint64_t   locallyBuiltCache;
    uint8_t    builtByChain[32];
    uint8_t    cacheSubType;
    uint8_t    cacheSubTypePadding[15];
    uint64_t   subCacheArrayOffset;
    uint32_t   subCacheArrayCount;
    uint32_t   dynamicConfigOffset;
    uint32_t   dynamicConfigCount;
    struct dyld_uuid_info symbolFileUUID;  // uuid of the accompanying .symbols file
};

#endif /* LITEHOOK_DYLD_CACHE_FORMAT_H */
