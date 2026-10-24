#import "RyDyldHooks.h"

#import "litehook.h"
#import <dlfcn.h>
#import <string.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// ---- shims needed to flip the guest Mach-O header filetype ----
// TPRO write-enable shims are implemented in litehook.c (same target); declared
// here because litehook.h doesn't expose them. We use the public vm_protect()
// (not the private builtin_vm_protect) for the non-PPL case.
void os_thread_self_restrict_tpro_to_rw(void);
void os_thread_self_restrict_tpro_to_ro(void);

// MH_EXECUTE_SYM (the "_mh_execute_header" name dyld uses for the main
// executable) is not part of the public iOS SDK headers.
#ifndef MH_EXECUTE_SYM
#define MH_EXECUTE_SYM "_mh_execute_header"
#endif

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
// Window-scene association (LiveContainer "updateWindowScene" fix)
//
// On iOS 13+ a UIWindow only renders reliably once it is bound to a
// UIWindowScene. RyBox itself is now scene-capable (see UIApplicationSceneManifest
// in Info.plist), so a real scene exists to attach guest windows to. A guest
// window created with plain -initWithFrame: + -makeKeyAndVisible — or one the
// guest builds itself in its (scene) delegate — is otherwise invisible on modern
// iOS, which is exactly the "only a launch image shows" symptom. We mirror
// LiveContainer's fix: bind the window to the host scene before it is shown.
// ----------------------------------------------------------------------------
static UIWindowScene *RyFirstWindowScene(void) {
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if (![s isKindOfClass:[UIWindowScene class]]) continue;
        UIWindowScene *ws = (UIWindowScene *)s;
        if (ws.screen == UIScreen.mainScreen) return ws;
    }
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]]) return (UIWindowScene *)s;
    }
    return nil;
}

/// Bind `w` to the host's window scene if it has none (no-op otherwise).
static void RyAttachWindowScene(UIWindow *w) {
    if (!w || w.windowScene) return;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if (![s isKindOfClass:[UIWindowScene class]]) continue;
        UIWindowScene *ws = (UIWindowScene *)s;
        if (w.screen == ws.screen) { w.windowScene = ws; break; }
    }
}

// ----------------------------------------------------------------------------
// UIKit swizzles installed once per guest launch. They route every window the
// guest shows through RyAttachWindowScene, and fix the status-bar frame for apps
// that never adopted UISceneDelegate (LiveContainer parity).
// ----------------------------------------------------------------------------
static BOOL ryUIKitSwizzlesInstalled = NO;

@interface UIWindow (RyGuestScene)
- (void)ry_makeKeyAndVisible;
- (void)ry_makeKeyWindow;
- (void)ry_setHidden:(BOOL)hidden;
@end

@implementation UIWindow (RyGuestScene)
- (void)ry_makeKeyAndVisible { RyAttachWindowScene(self); [self ry_makeKeyAndVisible]; }
- (void)ry_makeKeyWindow    { RyAttachWindowScene(self); [self ry_makeKeyWindow]; }
- (void)ry_setHidden:(BOOL)hidden { RyAttachWindowScene(self); [self ry_setHidden:hidden]; }
@end

@interface UIApplication (RyGuestScene)
- (CGRect)ry_statusBarFrame;
@end

@implementation UIApplication (RyGuestScene)
- (CGRect)ry_statusBarFrame {
    for (UIScene *s in self.connectedScenes) {
        if (![s isKindOfClass:[UIWindowScene class]]) continue;
        UIStatusBarManager *m = [(UIWindowScene *)s statusBarManager];
        if (m) return m.statusBarFrame;
    }
    return [self ry_statusBarFrame];
}
@end

static void RyInstallUIKitSwizzles(void) {
    if (ryUIKitSwizzlesInstalled) return;
    ryUIKitSwizzlesInstalled = YES;
    Class win = objc_getClass("UIWindow");
    Method a = class_getInstanceMethod(win, @selector(makeKeyAndVisible));
    Method b = class_getInstanceMethod(win, @selector(ry_makeKeyAndVisible));
    if (a && b) method_exchangeImplementations(a, b);
    a = class_getInstanceMethod(win, @selector(makeKeyWindow));
    b = class_getInstanceMethod(win, @selector(ry_makeKeyWindow));
    if (a && b) method_exchangeImplementations(a, b);
    a = class_getInstanceMethod(win, @selector(setHidden:));
    b = class_getInstanceMethod(win, @selector(ry_setHidden:));
    if (a && b) method_exchangeImplementations(a, b);
    Class app = objc_getClass("UIApplication");
    a = class_getInstanceMethod(app, @selector(statusBarFrame));
    b = class_getInstanceMethod(app, @selector(ry_statusBarFrame));
    if (a && b) method_exchangeImplementations(a, b);
}

/// The guest's SceneDelegate class name, read from its UISceneManifest.
static NSString *RyGuestSceneDelegateClassName(void) {
    NSDictionary *info = NSBundle.mainBundle.infoDictionary;
    NSDictionary *manifest = info[@"UIApplicationSceneManifest"];
    NSDictionary *configs = manifest[@"UISceneConfigurations"];
    NSArray *appConfigs = configs[@"UIWindowSceneSessionRoleApplication"];
    NSDictionary *cfg = appConfigs.firstObject;
    NSString *name = cfg[@"UISceneDelegateClassName"];
    return [name isKindOfClass:[NSString class]] ? name : nil;
}

/// Best-effort: run the guest's SceneDelegate so a scene-based app builds its
/// REAL window inside RyBox's scene. This is the iOS 13+ scene lifecycle the
/// early-return UIApplicationMain hook otherwise skips. Returns YES when the
/// guest produced its own on-screen window (so the caller must not add a
/// fallback window on top of it).
static BOOL RyDriveGuestSceneDelegate(void) {
    @try {
        NSString *name = RyGuestSceneDelegateClassName();
        if (!name.length) return NO;
        Class cls = NSClassFromString(name);
        if (!cls) return NO;
        UIWindowScene *scene = RyFirstWindowScene();
        if (!scene) return NO;
        id sceneDel = [[cls alloc] init];
        SEL sel = @selector(scene:willConnectToSession:options:);
        if (![sceneDel respondsToSelector:sel]) return NO;

        NSUInteger before = UIApplication.sharedApplication.windows.count;
        // Preserve + restore the host scene's delegate: a guest scene delegate
        // often assigns itself as scene.delegate, which must not permanently
        // steal RyBox's scene for the next guest launch.
        id savedDelegate = scene.delegate;
        NSMethodSignature *sig = [sceneDel methodSignatureForSelector:sel];
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        inv.target = sceneDel;
        inv.selector = sel;
        id s = scene;
        id sess = scene.session;
        id opts = nil;
        [inv setArgument:&s atIndex:2];
        [inv setArgument:&sess atIndex:3];
        [inv setArgument:&opts atIndex:4];
        [inv invoke];
        scene.delegate = savedDelegate;
        return UIApplication.sharedApplication.windows.count > before;
    } @catch (NSException *e) {
        NSLog(@"[RyBox] guest scene delegate drive failed: %@", e.reason);
        return NO;
    }
}

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
    kern_return_t k = vm_protect(mach_task_self(),
                                 (vm_address_t)h, sizeof(*h), false,
                                 PROT_READ | PROT_WRITE);
    if (k != KERN_SUCCESS) {
        // PPL/TPRO-protected page: temporarily drop the thread to RW.
        os_thread_self_restrict_tpro_to_rw();
        h->filetype = MH_EXECUTE;
        os_thread_self_restrict_tpro_to_ro();
    } else {
        h->filetype = MH_EXECUTE;
        vm_protect(mach_task_self(), (vm_address_t)h, sizeof(*h), false, PROT_READ);
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
        NSDictionary *info = NSBundle.mainBundle.infoDictionary;

        Class delCls = NSClassFromString(delegateClassName);
        if (!delCls && principalClassName) delCls = NSClassFromString(principalClassName);
        id<UIApplicationDelegate> delegate = delCls ? [[delCls alloc] init] : nil;

        // Tell the Swift side to hide the SpringBoard window + install the Home chrome.
        [[NSNotificationCenter defaultCenter] postNotificationName:kRyGuestDidLaunch object:nil];

        if (delegate) {
            app.delegate = delegate;
            if ([delegate respondsToSelector:@selector(application:didFinishLaunchingWithOptions:)]) {
                [delegate application:app didFinishLaunchingWithOptions:nil];
            }
        }

        // Scene-based guest (UISceneManifest): run its SceneDelegate so the REAL
        // UI is built inside RyBox's scene. This is the iOS 13+ scene lifecycle the
        // early-return hook otherwise skips — the fix for "只有一张启动图".
        BOOL guestOwnsWindow = NO;
        if (info[@"UIApplicationSceneManifest"] != nil) {
            guestOwnsWindow = RyDriveGuestSceneDelegate();
        }

        UIWindow *w = [delegate respondsToSelector:@selector(window)] ? delegate.window : nil;
        if (w && !guestOwnsWindow) {
            // The guest's app delegate built its own window — just bind + show it.
            RyAttachWindowScene(w);
            w.windowLevel = UIWindowLevelAlert; // above the container
            [w makeKeyAndVisible];
        } else if (!w && !guestOwnsWindow) {
            // Legacy delegate path (or the scene drive failed): build a window here.
            w = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
            if ([delegate respondsToSelector:@selector(setWindow:)]) delegate.window = w;

            // Prefer the app's MAIN storyboard; else its principal class; NEVER the
            // launch storyboard (showing a launch screen forever was the old bug).
            NSString *sbName = info[@"UIMainStoryboardFile"];
            if (sbName.length) {
                UIStoryboard *sb = [UIStoryboard storyboardWithName:sbName bundle:NSBundle.mainBundle];
                w.rootViewController = [sb instantiateInitialViewController] ?: [UIViewController new];
            } else {
                NSString *pc = info[@"NSPrincipalClass"];
                Class vcCls = pc.length ? NSClassFromString(pc) : nil;
                w.rootViewController = vcCls ? [[vcCls alloc] init] : [UIViewController new];
            }
            RyAttachWindowScene(w);   // bind to the host scene so it actually renders
            w.windowLevel = UIWindowLevelAlert; // above the container
            [w makeKeyAndVisible];
        }
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

    // Route every guest-shown UIWindow through RyAttachWindowScene, and fix the
    // status-bar frame for non-scene guests. Installed once; idempotent.
    RyInstallUIKitSwizzles();

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
