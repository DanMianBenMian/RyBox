#import "RyDyldHooks.h"

#import "litehook.h"
#import <dlfcn.h>
#import <string.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ----------------------------------------------------------------------------
// State
// ----------------------------------------------------------------------------
static int  lcImageIndex = -1;       // RyBox host executable (MH_EXECUTE)
static int  appMainImageIndex = -1;  // guest patched dylib
static void *appExecutableHandle = NULL;
static bool appExecutableFileTypeOverwritten = false;
static const char *gGuestExecPath = NULL;

// Guest launch gate: only the GUEST's UIApplicationMain call is intercepted.
static volatile bool gGuestLaunching = false;

// Notification posted when the guest's UI is up, so Swift can hide the
// SpringBoard window and install the eject overlay.
static NSString *const kRyGuestDidLaunch = @"rybox.guestDidLaunch";

// ----------------------------------------------------------------------------
// Original function pointers (captured at load, like LiveContainer)
// ----------------------------------------------------------------------------
void *(*orig_dlopen)(const char *, int) = dlopen;
void *(*orig_dlsym)(void *, const char *) = dlsym;
uint32_t (*orig_dyld_image_count)(void) = _dyld_image_count;
const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = _dyld_get_image_header;
intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t) = _dyld_get_image_vmaddr_slide;
const char *(*orig_dyld_get_image_name)(uint32_t) = _dyld_get_image_name;
int (*orig_NSGetExecutablePath)(char *, uint32_t *) = NULL;
int (*orig_UIApplicationMain)(int, char **, NSString *, NSString *) = NULL;

// ----------------------------------------------------------------------------
// _NSGetExecutablePath redirect
// ----------------------------------------------------------------------------
static int Ry_NSGetExecutablePath(char *buf, uint32_t *bufsize) {
    if (gGuestExecPath) {
        size_t len = strlen(gGuestExecPath) + 1;
        if (buf && *bufsize >= (uint32_t)len) {
            strlcpy(buf, gGuestExecPath, *bufsize);
            return 0;
        }
        *bufsize = (uint32_t)len;
        return -1; // caller must reallocate
    }
    return orig_NSGetExecutablePath ? orig_NSGetExecutablePath(buf, bufsize) : -1;
}

// ----------------------------------------------------------------------------
// Header writability (builtin_vm_protect + TPRO, exactly like LiveContainer)
// ----------------------------------------------------------------------------
static void overwriteAppExecutableFileType(void) {
    struct mach_header_64 *h = (struct mach_header_64 *)orig_dyld_get_image_header(appMainImageIndex);
    kern_return_t k = builtin_vm_protect(mach_task_self(),
                                         (vm_address_t)h, sizeof(*h), false,
                                         PROT_READ | PROT_WRITE | VM_PROT_COPY);
    if (k != KERN_SUCCESS) {
        // TPRO-protected: temporarily drop to RW.
        os_thread_self_restrict_tpro_to_rw();
        h->filetype = MH_EXECUTE;
        os_thread_self_restrict_tpro_to_ro();
    } else {
        h->filetype = MH_EXECUTE;
        builtin_vm_protect(mach_task_self(),
                           (vm_address_t)h, sizeof(*h), false, PROT_READ);
    }
    appExecutableFileTypeOverwritten = true;
}

static inline int translateImageIndex(int origin) {
    if (origin == lcImageIndex) {
        if (!appExecutableFileTypeOverwritten) overwriteAppExecutableFileType();
        return appMainImageIndex;
    }
    return origin;
}

// ----------------------------------------------------------------------------
// Replacement functions (fishhook/litehook-style GOT rebind)
// ----------------------------------------------------------------------------
static void *hook_dlsym(void *handle, const char *sym) {
    if (handle == (void *)RTLD_MAIN_ONLY) {
        if (sym && strcmp(sym, MH_EXECUTE_SYM) == 0) {
            if (!appExecutableFileTypeOverwritten) overwriteAppExecutableFileType();
            return (void *)orig_dyld_get_image_header(appMainImageIndex);
        }
        handle = appExecutableHandle;
    } else if (handle != (void *)RTLD_SELF && handle != (void *)RTLD_NEXT) {
        void *ans = orig_dlsym(handle, sym);
        if (ans) return ans;
    }
    return orig_dlsym(handle, sym);
}

static const struct mach_header *hook_dyld_get_image_header(uint32_t i) {
    return orig_dyld_get_image_header(translateImageIndex((int)i));
}

static uint32_t hook_dyld_image_count(void) {
    // Hide the RyBox host image so the guest believes it is image 0.
    return orig_dyld_image_count() - 1;
}

static intptr_t hook_dyld_get_image_vmaddr_slide(uint32_t i) {
    return orig_dyld_get_image_vmaddr_slide(translateImageIndex((int)i));
}

static const char *hook_dyld_get_image_name(uint32_t i) {
    return orig_dyld_get_image_name(translateImageIndex((int)i));
}

// ----------------------------------------------------------------------------
// UIApplicationMain interception: host the GUEST app inside RyBox's UIApplication
// ----------------------------------------------------------------------------
static int Ry_UIApplicationMain(int argc, char *argv[],
                                NSString *principalClassName,
                                NSString *delegateClassName) {
    if (!gGuestLaunching) {
        return orig_UIApplicationMain(argc, argv, principalClassName, delegateClassName);
    }
    gGuestLaunching = false; // only intercept this one guest launch

    @autoreleasepool {
        UIApplication *app = UIApplication.sharedApplication;

        Class delCls = NSClassFromString(delegateClassName);
        if (!delCls && principalClassName) delCls = NSClassFromString(principalClassName);
        id<UIApplicationDelegate> delegate = delCls ? [[delCls alloc] init] : nil;

        // Tell the Swift side to hide the SpringBoard window + install eject button.
        [[NSNotificationCenter defaultCenter] postNotificationName:kRyGuestDidLaunch object:nil];

        if (delegate) {
            app.delegate = delegate;
            if ([delegate respondsToSelector:@selector(application:didFinishLaunchingWithOptions:)]) {
                [delegate application:app didFinishLaunchingWithOptions:nil];
            }
        }

        UIWindow *w = delegate.window;
        if (!w) {
            w = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
            if ([delegate respondsToSelector:@selector(setWindow:)]) delegate.window = w;

            NSBundle *main = NSBundle.mainBundle;
            NSDictionary *info = main.infoDictionary;
            NSString *sbName = info[@"UIMainStoryboardFile"] ?: info[@"UILaunchStoryboardName"];
            if (sbName.length) {
                UIStoryboard *sb = [UIStoryboard storyboardWithName:sbName bundle:main];
                w.rootViewController = [sb instantiateInitialViewController];
            } else if (NSString *pc = info[@"NSPrincipalClass"]) {
                Class vc = NSClassFromString(pc);
                w.rootViewController = vc ? [[vc alloc] init] : [UIViewController new];
            } else {
                w.rootViewController = [UIViewController new];
            }
        }
        w.windowLevel = UIWindowLevelAlert; // above the container
        [w makeKeyAndVisible];
    }
    return 0; // do NOT re-enter the run loop; RyBox's loop drives the guest
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------
void RySetGuestMainExecutablePath(const char *guestExecPath) {
    gGuestExecPath = guestExecPath;
}

void RyInstallGuestDyldHooks(void) {
    int count = (int)_dyld_image_count();

    // Find RyBox host (the MH_EXECUTE image) and the guest dylib by path.
    for (int i = 0; i < count; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) { lcImageIndex = i; break; }
    }
    if (gGuestExecPath) {
        for (int i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strcmp(name, gGuestExecPath) == 0) {
                appMainImageIndex = i;
                appExecutableHandle = (void *)_dyld_get_image_header(i);
                break;
            }
        }
    }

    // GOT rebinds (fishhook-style via litehook; gives us orig_ pointers).
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, dlsym, hook_dlsym, NULL);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, _dyld_image_count, hook_dyld_image_count, NULL);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, _dyld_get_image_header, hook_dyld_get_image_header, NULL);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, _dyld_get_image_vmaddr_slide, hook_dyld_get_image_vmaddr_slide, NULL);
    litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, _dyld_get_image_name, hook_dyld_get_image_name, NULL);

    void *nsgep = dlsym(RTLD_DEFAULT, "_NSGetExecutablePath");
    if (nsgep) {
        orig_NSGetExecutablePath = (int (*)(char *, uint32_t *))nsgep;
        litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, nsgep, Ry_NSGetExecutablePath, NULL);
    }

    void *uam = dlsym(RTLD_DEFAULT, "UIApplicationMain");
    if (uam) {
        orig_UIApplicationMain = (int (*)(int, char **, NSString *, NSString *))uam;
        litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, uam, Ry_UIApplicationMain, NULL);
    }
}

void *RyLaunchGuestExecutable(const char *execPath) {
    void *handle = dlopen(execPath, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        NSLog(@"[RyBox] dlopen guest failed: %s", dlerror());
        return NULL;
    }

    // Re-scan: the freshly dlopen'd guest must now be the appMainImageIndex.
    int count = (int)_dyld_image_count();
    for (int i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strcmp(name, execPath) == 0) {
            appMainImageIndex = i;
            appExecutableHandle = (void *)_dyld_get_image_header(i);
            break;
        }
    }

    // Find the LC_MAIN entry offset and call the guest's `main`.
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)_dyld_get_image_header(appMainImageIndex);
    if (!hdr) return handle;

    struct load_command *lc = (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));
    uint64_t entryoff = 0;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_MAIN) {
            entryoff = ((struct entry_point_command *)lc)->entryoff;
            break;
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    if (entryoff == 0) {
        NSLog(@"[RyBox] guest has no LC_MAIN");
        return handle;
    }

    uintptr_t base = (uintptr_t)hdr; // dylib __TEXT vmaddr is 0 -> entry ~ base + entryoff
    int (*guestMain)(int, char **, char **, char **) =
        (int (*)(int, char **, char **, char **))(base + entryoff);

    // Gate the UIApplicationMain interception for THIS call.
    gGuestLaunching = true;

    char *argv[] = { (char *)execPath, NULL };
    guestMain(1, argv, NULL, NULL);

    return handle;
}
