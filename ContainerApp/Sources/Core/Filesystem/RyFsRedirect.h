#ifndef RyFsRedirect_h
#define RyFsRedirect_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Install the filesystem-redirect hooks (open / openat / fopen / stat / lstat /
/// access / statfs / readlink / realpath / posix_spawn / execve). Idempotent.
/// Hooks are GATED by ry_fs_set_enabled(): until enabled they pass every call
/// straight through to the original libc implementation, so RyBox's own file
/// operations are never touched.
///
/// In the MAIN app, RyBox calls ry_fs_set_enabled(1) only while an in-process
/// guest (e.g. Sileo) is active. In the CHILD dylib, the constructor enables
/// redirection from the RYBOX_ROOT environment variable.
void ry_fs_install_hooks(void);

/// Set the jbroot directory that absolute paths are redirected into.
void ry_fs_set_root(const char *root);

/// Enable (1) / disable (0) redirection. In the main app this is toggled around
/// guest execution; in the child dylib the constructor sets it from RYBOX_ROOT.
void ry_fs_set_enabled(int enabled);

/// Enable (1) / disable (0) the DYLD_INSERT_LIBRARIES=RyFsRedirect.dylib
/// injection for spawned children.
///
/// The bundled dylib ships inside an UNSIGNED RyBox build, so a child that
/// loads it is immediately subject to library validation (the injected
/// library must be signed by the same team as the process loading it) and
/// dies before reaching its main(). A guest we re-sign ourselves therefore
/// runs with the injection OFF — its own paths already live under the
/// virtual root, so it does not need the redirection shim.
void ry_fs_set_inject_dylib(int enabled);

#ifdef __cplusplus
}
#endif

#endif /* RyFsRedirect_h */
