import UIKit
import Foundation
import Darwin
import os

/// How RyBox starts a guest app.
///
/// Two fundamentally different validation regimes live here:
///
///  * `.executeProcess` — the guest stays the executable it already is
///    (MH_EXECUTE) and is started with `posix_spawn` as its own process.
///    The kernel validates it exactly like it validates every app on the
///    device: the designated requirement against its own certificate chain.
///  * `.inProcessDylib` — the LiveContainer model: the guest is patched to
///    MH_DYLIB, re-signed, `dlopen`ed into RyBox and its entry point is
///    called. A library loaded into an arbitrary host process is validated
///    far more strictly than a standalone executable — it must additionally
///    pass AMFI's **library validation**, which only fails when the guest's
///    team differs from the host's AND the host is not exempt
///    (`get-task-allow` / `disable-library-validation`). Same team ⇒ loads
///    fine with **either** a development or a distribution cert (this is the
///    RyBox default and the recommended production path). The errno=85
///    Sileo saw was library validation, not a certificate-type ban.
///
/// The choice is persisted so it can be flipped on the device (Settings →
/// 启动方式) without a rebuild — the two paths fail in different ways and
/// the log tells them apart.
enum GuestLaunchMode: String, CaseIterable, Identifiable {
    case executeProcess
    case inProcessDylib

    var id: String { rawValue }

    var title: String {
        switch self {
        case .executeProcess: return "可执行文件进程"
        case .inProcessDylib:  return "进程内动态库"
        }
    }

    var detail: String {
        switch self {
        case .executeProcess:
            return "guest 保持 MH_EXECUTE，用 posix_spawn 起成独立进程：可执行文件只按指定要求校验证书链，不涉及库验证。缺点是容器界面无法与 guest 共存，guest 也不能访问容器的虚拟根。"
        case .inProcessDylib:
            return "LiveContainer 模式：把 guest 改成 MH_DYLIB 后 dlopen 进 RyBox 进程，界面能和容器共存。库验证只比对 team id：只要宿主与 guest 用「同一 Apple 账号」的侧载/分发证书（同 team），哪怕都是分发证书（get-task-allow=false）也能直接加载；只有 team 不同且宿主又没 get-task-allow 豁免时才会被拒（errno=85）。"
        }
    }

    /// The mode in force right now (persisted across relaunches).
    ///
    /// Default is `.inProcessDylib` — the LiveContainer model. That is the
    /// mode the container is BUILT for (guest UI lives inside RyBox's process,
    /// the container never exits), and it is the mode LiveContainer itself
    /// uses.
    ///
    /// The in-process path's strictness is **the library validation, not the
    /// certificate type**. AMFI only refuses a guest dylib when BOTH hold:
    ///   (1) the guest's team differs from the host's, AND
    ///   (2) the host is NOT exempt from library validation
    ///       (no `get-task-allow` and no `disable-library-validation`).
    /// Two ways satisfy this:
    ///   * **Channel A — same team (distribution certs are fine):** sign the
    ///     RyBox.ipa and import the guest-resign p12 with the **same Apple
    ///     account**. Same team ⇒ AMFI library validation passes regardless
    ///     of whether either cert is development or distribution. This is the
    ///     recommended, production-friendly path.
    ///   * **Channel B — host exemption:** sign the host with a development
    ///     profile (`get-task-allow = true`). A debuggable host is exempt
    ///     from library validation and may load any team's guest dylib.
    ///
    /// The old "distribution certs won't work at all" line comes from
    /// LiveContainer's own AltStore/SideStore flow, which always sideloads
    /// LiveContainer with a *different* account than the apps it installs —
    /// that is a flow constraint, not a platform rule. RyBox controls both
    /// the host and the guest cert, so it can always arrange Channel A.
    ///
    /// `HostIdentity.inspect()` reads the host's own signature at launch and
    /// reports which channel is open (`可用通路`), so the failure mode is
    /// self-explaining instead of being a mystery.
    static var current: GuestLaunchMode {
        get {
            let raw = UserDefaults.standard.string(forKey: "rybox.guestLaunchMode") ?? ""
            return GuestLaunchMode(rawValue: raw) ?? .inProcessDylib
        }
        set {
            UserDefaults.standard.set(newValue.rawValue, forKey: "rybox.guestLaunchMode")
        }
    }
}

/// In-process GUI guest loader.
///
/// A GUI IPA runs INSIDE RyBox's already-running process. The container UI stays
/// alive and the virtual Home button (or "弹出 App") just dismisses the guest
/// window — the process never exits.
///
/// Pipeline (mirrors LiveContainer, built on vendored ChOma/litehook + zsign):
///   1. RyPatchGuestExecutable  — MH_EXECUTE -> MH_DYLIB, shrink __PAGEZERO.
///                                (RyMachOPatcher.c, proven LCPatchExecSlice logic)
///   2. CodeSigner.sign         — re-sign the patched binary with the user's
///                                distribution cert (JIT-less, AMFI-satisfied).
///                                (zsign helper — see codesign-helper-README.txt)
///   3. RySetGuestMainExecutablePath + RyBoxGuestBundle.activate — redirect
///                                +[NSBundle mainBundle] to the guest.
///   4. RyInstallGuestDyldHooks — litehook rebinds (dlsym / _dyld_* /
///                                _NSGetExecutablePath / UIApplicationMain) so the
///                                guest believes it is the main app AND is hosted
///                                inside RyBox's already-running UIApplication.
///   5. RyLaunchGuestExecutable — dlopen the patched guest + jump to its LC_MAIN
///                                entry. The guest's UIApplicationMain call is
///                                intercepted and hosted (no re-entrant run loop).
///
/// The MH_EXECUTE path (`.executeProcess`) skips steps 1, 4 and 5 entirely: the
/// binary is never patched, it is signed AS an executable (the signer keeps the
/// entitlements blob and sets CS_EXECSEG_MAIN_BINARY), and it is started with
/// `posix_spawn` like any other managed guest process.
enum GuestRuntime {

    /// The guest process started by `.executeProcess`, so "弹出 App" can end it.
    private static var spawnedGuest: NKProcess?

    /// Launch a GUI app with the currently selected launch mode.
    static func launch(_ app: ImportedApp) {
        switch GuestLaunchMode.current {
        case .executeProcess: launchAsProcess(app)
        case .inProcessDylib:  launchInProcess(app)
        }
    }

    // MARK: - MH_EXECUTE process path

    /// Launch the guest AS the executable it already is.
    ///
    /// No `MH_EXECUTE -> MH_DYLIB` patch, no `dlopen`, no entry-point jump:
    /// the binary is re-signed with the executable's CodeDirectory (entitlements
    /// kept in slot 5, `CS_EXECSEG_MAIN_BINARY` set, `execSegBase` = __TEXT
    /// vmaddr) and started with `posix_spawn`, so the kernel validates it the
    /// way it validates every app — designated requirement against the
    /// certificate chain, no transmute, no library validation.
    static func launchAsProcess(_ app: ImportedApp) {
        let exePath = app.executablePath
        guard FileManager.default.fileExists(atPath: exePath) else {
            RyLog.shared.log("guest 可执行文件不存在：\(exePath)", level: .error, tag: "guest")
            return
        }
        let bundleURL = URL(fileURLWithPath: exePath).deletingLastPathComponent()

        RyLog.shared.log("准备以可执行文件方式启动 \(app.name)（\(app.bundleIdentifier)）",
                         level: .info, tag: "guest")

        // Re-signing is the slow part (whole bundle), so keep it off the main
        // thread; the spawn itself happens on the main thread.
        DispatchQueue.global(qos: .userInitiated).async {
            // The guest's executable must carry the +x bit or posix_spawn
            // refuses it (ProcessManager guards on isExecutableFile). A bundle
            // extracted into the virtual root does not always keep the mode.
            try? FileManager.default.setAttributes([.posixPermissions: 0o755],
                                                   ofItemAtPath: exePath)

            // NOTE: no Mach-O patch here. The binary stays MH_EXECUTE, so the
            // signer sees filetype == MH_EXECUTE and emits the executable's
            // CodeDirectory instead of the dylib one.
            if case .failure(let err) = CodeSigner.shared.sign(bundleAt: bundleURL.path) {
                RyLog.shared.log("guest 重新签名失败：\(err.localizedDescription)", level: .error, tag: "guest")
                DispatchQueue.main.async {
                    GuestWindowHost.shared.presentScaffold(bundleURL,
                        reason: err.localizedDescription)
                }
                return
            }
            RyLog.shared.log("ks  WRITE  \(bundleURL.path) (bundle re-signed, 保持 MH_EXECUTE)",
                             level: .info, tag: "guest")

            DispatchQueue.main.async {
                let env = GuestEnvironment.build(for: app)

                // The bundled RyFsRedirect.dylib ships inside an UNSIGNED
                // RyBox build. Injecting it into the child would subject the
                // INJECTED LIBRARY to library validation (it must be signed by
                // the same team as the process loading it) and the child would
                // be killed before reaching its main(). The guest's own paths
                // already live under the virtual root, so it does not need the
                // shim.
                ry_fs_set_inject_dylib(0)
                defer { ry_fs_set_inject_dylib(1) }

                let proc = ProcessManager.shared.spawn(
                    executable: exePath,
                    arguments: [],
                    environment: env,
                    workingDirectory: app.containerPath,
                    captureOutput: true,
                    onOutput: { line in
                        // The child's stderr is the whole story when it refuses
                        // to start (an AMFI refusal, a bad profile, a missing
                        // symbol) — mirror it into the container log.
                        RyLog.shared.log("guest | \(line)", level: .debug, tag: "guest")
                    },
                    onExit: { status in
                        RyLog.shared.log("guest 进程已退出，status=\(status)", level: .info, tag: "guest")
                    })

                guard let proc = proc else {
                    RyLog.shared.log("posix_spawn 失败：无法启动 \(exePath)", level: .error, tag: "guest")
                    GuestWindowHost.shared.presentScaffold(bundleURL,
                        reason: "posix_spawn 失败：无法以可执行文件方式启动")
                    return
                }
                spawnedGuest = proc
                RyLog.shared.log("ks  EXEC   \(exePath) (MH_EXECUTE 独立进程, pid=\(proc.pid))",
                                 level: .info, tag: "guest")
            }
        }
    }

    // MARK: - in-process (LiveContainer) path

    /// Launch a GUI app in-process. Container keeps running.
    static func launchInProcess(_ app: ImportedApp) {
        let exePath = app.executablePath
        guard FileManager.default.fileExists(atPath: exePath) else {
            RyLog.shared.log("guest 可执行文件不存在：\(exePath)", level: .error, tag: "guest")
            return
        }
        let bundleURL = URL(fileURLWithPath: exePath).deletingLastPathComponent()

        RyLog.shared.log("准备启动 \(app.name)（\(app.bundleIdentifier)）", level: .info, tag: "guest")

        // Pre-flight: the in-process path's ONE hard requirement is that the
        // guest dylib passes AMFI's library validation. Apple only compares
        // the guest's team id against the host's, so EITHER of these works:
        //
        //   * channel A — the guest is signed by the SAME team as the host
        //     (a distribution certificate is fine here; the team id belongs to
        //     the Apple developer account, not to the certificate type),
        //   * channel B — the host carries get-task-allow and is therefore
        //     exempt from the check.
        //
        // When neither holds, AMFI refuses the guest with the opaque
        // `code signature invalid (errno=85)` — and that error names the
        // GUEST's CodeDirectory, so it looks like "our signature is broken".
        //
        // Check it BEFORE spending 30 seconds on Mach-O patching and signing,
        // and turn the failure into an actionable sentence instead of a raw
        // errno.
        let preflight = HostIdentity.preflightWarning()
        if let preflight {
            RyLog.shared.log("启动前检查失败：\(preflight)", level: .error, tag: "guest")
            DispatchQueue.main.async {
                GuestWindowHost.shared.presentScaffold(bundleURL, reason: preflight)
            }
            return
        }
        HostIdentity.logSummary()

        // Heavy, potentially slow work (Mach-O patch + re-sign of the whole
        // bundle) runs OFF the main thread so the UI never freezes while a guest
        // binary is being prepared — a large IPA signature previously blocked the
        // main thread and made the launch look "frozen". Only the dyld/UIKit
        // hooking + dlopen stays on the main thread, because UIKit expects to be
        // touched from there.
        DispatchQueue.global(qos: .userInitiated).async {
            // 1) Patch the guest executable in place (MH_EXECUTE -> MH_DYLIB, PAGEZERO).
            RyLog.shared.log("fs  READ   \(exePath) (guest executable)", level: .debug, tag: "guest")
            let patchRC = RyPatchGuestExecutable(exePath)
            guard patchRC == 0 else {
                RyLog.shared.log("Mach-O 补丁失败 (rc=\(patchRC))：\(exePath)", level: .error, tag: "guest")
                DispatchQueue.main.async {
                    GuestWindowHost.shared.presentScaffold(bundleURL,
                        reason: "Mach-O 补丁失败（退出码 \(patchRC)）")
                }
                return
            }
            RyLog.shared.log("fs  WRITE  \(exePath) (Mach-O patched MH_EXECUTE->MH_DYLIB)", level: .info, tag: "guest")

            // 2) Re-sign the patched binary (JIT-less; required by AMFI).
            if case .failure(let err) = CodeSigner.shared.sign(bundleAt: bundleURL.path) {
                RyLog.shared.log("guest 重新签名失败：\(err.localizedDescription)", level: .error, tag: "guest")
                DispatchQueue.main.async {
                    // Show the REAL reason. This screen used to render the
                    // guest's storyboard instead, which looked like the app
                    // half-launched (Sileo: black screen + tab bar) while none
                    // of its code had run.
                    GuestWindowHost.shared.presentScaffold(bundleURL,
                        reason: err.localizedDescription)
                }
                return
            }
            RyLog.shared.log("ks  WRITE  \(bundleURL.path) (bundle re-signed)", level: .info, tag: "guest")

            DispatchQueue.main.async {
                // Make this guest's ORIGINAL entitlements the active set, so the
                // container answers the app's entitlement queries with what the
                // app was actually built for (see EntitlementPolicy).
                EntitlementPolicy.shared.setActive(bundleID: app.bundleIdentifier)

                // 3) Redirect mainBundle + set the guest executable path for the hooks.
                RyBoxGuestBundle.activate(bundleURL)
                RySetGuestMainExecutablePath(exePath)

                // 4) Install dyld / UIKit hooks (best installed before the guest's
                //    dlopen-time symbol resolution).
                RyInstallGuestDyldHooks()

                // 4b) Turn ON filesystem redirection for the duration of the
                //     guest: the guest's absolute path opens (and any tools it
                //     spawns) now route into the jbroot. RyBox's own paths are
                //     whitelisted, so the shell keeps working untouched.
                ry_fs_set_enabled(1)

                // 5) dlopen + jump to the guest entry. The guest UIApplicationMain is
                //    intercepted and hosted; by the time this returns the guest UI is up.
                RyLog.shared.log("ks  EXEC   \(exePath) (guest entry point)", level: .info, tag: "guest")
                if RyLaunchGuestExecutable(exePath) == nil {
                    RyLog.shared.log("guest dlopen/启动失败", level: .error, tag: "guest")
                    GuestWindowHost.shared.presentScaffold(bundleURL,
                        reason: "dlopen 或入口跳转失败（签名后的二进制仍无法载入）")
                }
            }
        }
    }

    /// Tear down the guest (the "弹出 App" action). Process survives.
    static func eject() {
        // Turn filesystem redirection back off so RyBox's own file operations
        // are no longer routed into the jbroot.
        ry_fs_set_enabled(0)
        GuestWindowHost.shared.dismissGuest()
        EntitlementPolicy.shared.setActive(bundleID: nil)
        // The MH_EXECUTE path runs the guest as a real child process — it has
        // to be stopped explicitly, otherwise it keeps running behind the
        // container UI.
        if let proc = spawnedGuest {
            ProcessManager.shared.kill(proc, signal: SIGTERM)
            spawnedGuest = nil
        }
    }
}
