#ifndef RyMachOPatcher_h
#define RyMachOPatcher_h

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Patch a guest Mach-O executable IN PLACE so it can be dlopen()'d as a dylib
/// inside the already-running RyBox host process (LiveContainer model).
///
/// Operations (mirrors LiveContainer's proven LCPatchExecSlice, NOT a from-scratch
/// reimplementation):
///   - filetype  MH_EXECUTE -> MH_DYLIB
///   - clear     MH_PIE  (dylibs are not PIE in the same sense)
///   - set       MH_NO_REEXPORTED_DYLIBS
///   - shrink __PAGEZERO to a single zero page (vmaddr = 0xFFFFC000, vmsize = 0x4000)
///     so the guest loads inside the host's address space ("out of address space" fix)
///   - inject LC_RPATH "@loader_path" and "@executable_path/Frameworks" so the
///     guest's own embedded dylibs resolve
///
/// IMPORTANT: editing the binary invalidates its code signature. After patching
/// you MUST re-sign the guest (CodeSigner -> zsign helper). Returns 0 on success,
/// negative on error.
int RyPatchGuestExecutable(const char *execPath);

#ifdef __cplusplus
}
#endif

#endif /* RyMachOPatcher_h */
