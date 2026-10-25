#import "RyFsRedirect.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <stdio.h>       // FILE / fopen (ry_fopen)
#import <stdarg.h>      // va_list / va_start / va_arg (ry_open / ry_openat)
#import <unistd.h>
#import <limits.h>
#import <sys/stat.h>
#import <sys/mount.h>   // statfs / struct statfs live here on Darwin
#import <fcntl.h>
#import <spawn.h>
#import "litehook.h"
#import <crt_externs.h>

// ---------------------------------------------------------------------------
// Original (real) libc function pointers. Captured once at install time. The
// redirect hooks resolve a path, then call THESE — never the hooked symbol — so
// there is no recursion.
// ---------------------------------------------------------------------------
static int       (*orig_open)(const char *, int, ...) = NULL;
static int       (*orig_openat)(int, const char *, int, ...) = NULL;
static FILE *    (*orig_fopen)(const char *, const char *) = NULL;
static int       (*orig_stat)(const char *, struct stat *) = NULL;
static int       (*orig_lstat)(const char *, struct stat *) = NULL;
static int       (*orig_access)(const char *, int) = NULL;
static int       (*orig_statfs)(const char *, struct statfs *) = NULL;
static ssize_t   (*orig_readlink)(const char *, char *, size_t) = NULL;
static char *    (*orig_realpath)(const char *, char *) = NULL;
static int       (*orig_posix_spawn)(pid_t *restrict, const char *restrict,
                                     const posix_spawn_file_actions_t *,
                                     const posix_spawnattr_t *,
                                     char *const[], char *const[]) = NULL;
static int       (*orig_execve)(const char *, char *const[], char *const[]) = NULL;

// jbroot root (no trailing slash) + enable flag.
static char  gRoot[PATH_MAX] = {0};
static int   gEnabled = 0;
static int   gInstalled = 0;

// Real paths that MUST keep pointing at the genuine filesystem. The guest's own
// sandboxed data and every system framework RyBox/guest load live here, so they
// are never redirected. `gRoot`, `gBundlePath`, `gHomeDir` are filled at runtime.
static const char *gWhite[24] = {
    NULL,  // gRoot
    NULL,  // gBundlePath
    NULL,  // gHomeDir (NSHomeDirectory — covers guest + RyBox containers)
    "/System",
    "/usr/lib",
    "/usr/libexec",
    "/private/var/mobile/Containers",
    "/var/mobile/Containers",
    "/private/var/mobile/Library",
    "/var/mobile/Library",
    "/private/var/containers",
    "/var/containers",
    "/dev",
    "/proc",
    "/tmp",
    "/private/tmp",
    NULL
};
static char *gBundlePath = NULL;
static char *gHomeDir = NULL;
/// Whether spawned children get DYLD_INSERT_LIBRARIES=RyFsRedirect.dylib.
///
/// The bundled dylib is part of an UNSIGNED RyBox build, so a child that
/// loads it is immediately subject to library validation — the injected
/// library must be signed by the same team as the process that loads it, and
/// a guest we just re-signed with the user's certificate usually does NOT
/// match RyBox's own signature. The child would die before reaching its
/// main(). The guest process path therefore turns the injection OFF (the
/// guest's own paths already live under the virtual root, so it does not
/// need the redirection shim).
static int gInjectDylib = 1;

// Returns the whitelist prefix that matches `p`, or NULL.
static const char *ry_fs_whitelisted(const char *p) {
    for (int i = 0; gWhite[i]; i++) {
        size_t n = strlen(gWhite[i]);
        if (strncmp(p, gWhite[i], n) == 0 && (p[n] == '/' || p[n] == '\0'))
            return gWhite[i];
    }
    return NULL;
}

/// Core resolver. Returns:
///   - the ORIGINAL pointer if disabled / relative / whitelisted / no shadow; or
///   - a heap-allocated candidate (root + path) when a jbroot shadow exists.
/// The caller MUST free() the result when it differs from the input.
static char *ry_fs_resolve(const char *path) {
    if (!gEnabled) return (char *)path;
    if (!path || path[0] != '/') return (char *)path;     // relative: untouched
    if (ry_fs_whitelisted(path)) return (char *)path;      // real path: untouched
    char cand[PATH_MAX];
    snprintf(cand, sizeof(cand), "%s%s", gRoot, path);
    struct stat st;
    if (orig_stat(cand, &st) == 0) return strdup(cand);    // shadow exists → redirect
    return (char *)path;                                   // no shadow → fall back
}

/// In the child dylib, the constructor installs + enables redirection from
/// RYBOX_ROOT (set by the parent's posix_spawn hook). In the main app,
/// RYBOX_ROOT is absent at launch, so the constructor is a no-op and RyBox
/// enables redirection explicitly when a guest becomes active.
__attribute__((constructor))
static void ry_fs_ctor(void) {
    const char *r = getenv("RYBOX_ROOT");
    if (r && r[0]) {
        ry_fs_set_root(r);
        ry_fs_install_hooks();
        gEnabled = 1;
    }
}

// ---------------------------------------------------------------------------
// Replacement functions (gated by gEnabled; resolve then call orig).
// ---------------------------------------------------------------------------
static int ry_open(const char *path, int flags, ...) {
    char *r = ry_fs_resolve(path);
    va_list ap; va_start(ap, flags);
    mode_t mode = (flags & O_CREAT) ? va_arg(ap, mode_t) : 0;
    va_end(ap);
    int fd = orig_open ? orig_open(r, flags, mode) : open(r, flags, mode);
    if (r != path) free(r);
    return fd;
}

static int ry_openat(int dirfd, const char *path, int flags, ...) {
    // Only rewrite absolute paths; relative-to-dirfd are left alone.
    char *r = (path && path[0] == '/') ? ry_fs_resolve(path) : (char *)path;
    va_list ap; va_start(ap, flags);
    mode_t mode = (flags & O_CREAT) ? va_arg(ap, mode_t) : 0;
    va_end(ap);
    int fd = orig_openat ? orig_openat(dirfd, r, flags, mode) : openat(dirfd, r, flags, mode);
    if (r != path) free(r);
    return fd;
}

static FILE *ry_fopen(const char *path, const char *mode) {
    char *r = ry_fs_resolve(path);
    FILE *f = orig_fopen ? orig_fopen(r, mode) : fopen(r, mode);
    if (r != path) free(r);
    return f;
}

static int ry_stat(const char *path, struct stat *buf) {
    char *r = ry_fs_resolve(path);
    int rc = orig_stat ? orig_stat(r, buf) : stat(r, buf);
    if (r != path) free(r);
    return rc;
}

static int ry_lstat(const char *path, struct stat *buf) {
    char *r = ry_fs_resolve(path);
    int rc = orig_lstat ? orig_lstat(r, buf) : lstat(r, buf);
    if (r != path) free(r);
    return rc;
}

static int ry_access(const char *path, int amode) {
    char *r = ry_fs_resolve(path);
    int rc = orig_access ? orig_access(r, amode) : access(r, amode);
    if (r != path) free(r);
    return rc;
}

static int ry_statfs(const char *path, struct statfs *buf) {
    char *r = ry_fs_resolve(path);
    int rc = orig_statfs ? orig_statfs(r, buf) : statfs(r, buf);
    if (r != path) free(r);
    return rc;
}

static ssize_t ry_readlink(const char *path, char *buf, size_t bufsize) {
    char *r = ry_fs_resolve(path);
    ssize_t n = orig_readlink ? orig_readlink(r, buf, bufsize) : readlink(r, buf, bufsize);
    if (r != path) free(r);
    return n;
}

static char *ry_realpath(const char *path, char *resolved) {
    char *r = ry_fs_resolve(path);
    char *out = orig_realpath ? orig_realpath(r, resolved) : realpath(r, resolved);
    if (r != path) free(r);
    return out;
}

static int ry_posix_spawn(pid_t *restrict pid, const char *restrict path,
                          const posix_spawn_file_actions_t *file_actions,
                          const posix_spawnattr_t *attr,
                          char *const argv[], char *const envp[]) {
    // When a guest is active, route a spawned tool to its jbroot binary if one
    // shadows the requested absolute path. The child also receives RYBOX_ROOT
    // (and, when the RyFsRedirect child dylib is bundled, DYLD_INSERT_LIBRARIES)
    // so ITS file operations redirect into the jbroot as well. When disabled we
    // pass straight through.
    const char *realPath = path;
    if (gEnabled && path && path[0] == '/' && !ry_fs_whitelisted(path)) {
        char cand[PATH_MAX];
        snprintf(cand, sizeof(cand), "%s%s", gRoot, path);
        struct stat st;
        if (orig_stat(cand, &st) == 0) realPath = cand;
    }

    // Build the child environment: copy the parent's, then inject RYBOX_ROOT,
    // RYBOX_FS and (if the bundled dylib exists) DYLD_INSERT_LIBRARIES so the
    // child loads RyFsRedirect and keeps redirecting. Cheap + best-effort.
    char *injected[4];
    int nInjected = 0;
    char rootEnv[PATH_MAX + 16];
    char fsEnv[16];
    snprintf(rootEnv, sizeof(rootEnv), "RYBOX_ROOT=%s", gRoot);
    snprintf(fsEnv, sizeof(fsEnv), "RYBOX_FS=1");
    injected[nInjected++] = rootEnv;
    injected[nInjected++] = fsEnv;
    char dylibEnv[PATH_MAX + 32];
    if (gInjectDylib && gBundlePath) {
        snprintf(dylibEnv, sizeof(dylibEnv), "%s/RyFsRedirect.dylib", gBundlePath);
        struct stat dst;
        if (orig_stat(dylibEnv, &dst) == 0) {
            char setenv[PATH_MAX + 32];
            snprintf(setenv, sizeof(setenv), "DYLD_INSERT_LIBRARIES=%s", dylibEnv);
            injected[nInjected++] = setenv;
        }
    }

    char **childEnv = (char **)envp;
    char **ownedEnv = NULL;
    if (nInjected > 0) {
        char **src = (char **)envp;
        int srcCount = 0;
        if (src) { while (src[srcCount]) srcCount++; }
        else { char **en = *_NSGetEnviron(); while (en[srcCount]) srcCount++; src = en; }
        ownedEnv = (char **)calloc(srcCount + nInjected + 1, sizeof(char *));
        for (int i = 0; i < srcCount; i++) ownedEnv[i] = src[i];          // borrow
        for (int i = 0; i < nInjected; i++) ownedEnv[srcCount + i] = injected[i]; // stack-local (valid through call)
        ownedEnv[srcCount + nInjected] = NULL;
        childEnv = ownedEnv;
    }

    int rc;
    if (!orig_posix_spawn)
        rc = posix_spawn(pid, realPath, file_actions, attr, (char *const *)argv, childEnv);
    else
        rc = orig_posix_spawn(pid, realPath, file_actions, attr, (char *const *)argv, childEnv);
    free(ownedEnv);
    return rc;
}

static int ry_execve(const char *path, char *const argv[], char *const envp[]) {
    const char *realPath = path;
    if (gEnabled && path && path[0] == '/' && !ry_fs_whitelisted(path)) {
        char cand[PATH_MAX];
        snprintf(cand, sizeof(cand), "%s%s", gRoot, path);
        struct stat st;
        if (orig_stat(cand, &st) == 0) realPath = cand;
    }
    if (!orig_execve) return execve(realPath, argv, envp);
    return orig_execve(realPath, argv, envp);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
void ry_fs_set_root(const char *root) {
    if (!root) return;
    size_t n = strlen(root);
    if (n >= sizeof(gRoot)) n = sizeof(gRoot) - 1;
    memcpy(gRoot, root, n);
    gRoot[n] = '\0';
    // Strip a trailing slash so "root + /usr/bin" composes correctly.
    if (n > 1 && gRoot[n - 1] == '/') gRoot[n - 1] = '\0';
}

void ry_fs_set_enabled(int enabled) {
    gEnabled = enabled ? 1 : 0;
}

void ry_fs_set_inject_dylib(int enabled) {
    gInjectDylib = enabled ? 1 : 0;
}

void ry_fs_install_hooks(void) {
    if (gInstalled) return;
    gInstalled = 1;

    // Capture whitelist paths (real, must never redirect).
    @autoreleasepool {
        NSString *bundle = NSBundle.mainBundle.bundlePath;
        NSString *home = NSHomeDirectory();
        if (bundle.length) {
            free(gBundlePath);
            gBundlePath = strdup(bundle.UTF8String);
        }
        if (home.length) {
            free(gHomeDir);
            gHomeDir = strdup(home.UTF8String);
        }
    }
    // Insert the three runtime prefixes into the whitelist table (slots 0..2).
    gWhite[0] = gRoot;          // never double-redirect into the jbroot
    gWhite[1] = gBundlePath;    // the RyBox.app bundle + its Preinstalled assets
    gWhite[2] = gHomeDir;       // all app containers (RyBox + guest sandbox)

    void *h;
    h = dlsym(RTLD_DEFAULT, "open");            if (h) { orig_open = (void *)h;            litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_open, NULL); }
    h = dlsym(RTLD_DEFAULT, "openat");          if (h) { orig_openat = (void *)h;          litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_openat, NULL); }
    h = dlsym(RTLD_DEFAULT, "fopen");           if (h) { orig_fopen = (void *)h;           litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_fopen, NULL); }
    h = dlsym(RTLD_DEFAULT, "stat");            if (h) { orig_stat = (void *)h;            litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_stat, NULL); }
    h = dlsym(RTLD_DEFAULT, "lstat");           if (h) { orig_lstat = (void *)h;           litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_lstat, NULL); }
    h = dlsym(RTLD_DEFAULT, "access");          if (h) { orig_access = (void *)h;          litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_access, NULL); }
    h = dlsym(RTLD_DEFAULT, "statfs");          if (h) { orig_statfs = (void *)h;          litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_statfs, NULL); }
    h = dlsym(RTLD_DEFAULT, "readlink");        if (h) { orig_readlink = (void *)h;        litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_readlink, NULL); }
    h = dlsym(RTLD_DEFAULT, "realpath");        if (h) { orig_realpath = (void *)h;        litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_realpath, NULL); }
    h = dlsym(RTLD_DEFAULT, "posix_spawn");     if (h) { orig_posix_spawn = (void *)h;     litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_posix_spawn, NULL); }
    h = dlsym(RTLD_DEFAULT, "execve");          if (h) { orig_execve = (void *)h;          litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, h, ry_execve, NULL); }
}
