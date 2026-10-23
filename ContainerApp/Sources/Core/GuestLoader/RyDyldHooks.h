#ifndef RyDyldHooks_h
#define RyDyldHooks_h

#ifdef __cplusplus
extern "C" {
#endif

/// Set the (already-patched) guest executable path. Must be called before
/// RyInstallGuestDyldHooks so the hooks can find the guest image by path.
void RySetGuestMainExecutablePath(const char *guestExecPath);

/// Install the dyld + dlsym + UIKit hooks that make the dlopen'd guest appear as
/// the process's main executable to itself (LiveContainer Dyld.m model):
///   - litehook_rebind_symbol on dlsym / _dyld_get_image_* to translate image
///     indices so the guest's patched dylib is reported as the main image.
///   - overwriteAppExecutableFileType so dlsym(RTLD_MAIN_ONLY, MH_EXECUTE_SYM)
///     returns the guest header.
///   - rebind _NSGetExecutablePath so the guest sees its own executable path.
///   - rebind UIApplicationMain: the GUEST's UIApplicationMain call is intercepted
///     (gated by a launch flag) and hosted inside the already-running RyBox
///     UIApplication instead of re-entering the run loop.
///
/// Safe to call once per guest launch; it is idempotent for the symbol rebinds.
void RyInstallGuestDyldHooks(void);

/// dlopen the patched guest and jump to its LC_MAIN entry (its `main`). The guest
/// `main` will call UIApplicationMain, which the hook above intercepts.
/// Returns the dlopen handle (non-NULL on success) or NULL on failure.
void *RyLaunchGuestExecutable(const char *execPath);

#ifdef __cplusplus
}
#endif

#endif /* RyDyldHooks_h */
