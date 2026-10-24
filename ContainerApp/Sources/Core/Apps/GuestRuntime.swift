import UIKit
import Foundation
import os

/// In-process GUI guest loader — the LiveContainer model, fully wired.
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
enum GuestRuntime {

    /// Launch a GUI app in-process. Container keeps running.
    static func launchInProcess(_ app: ImportedApp) {
        let exePath = app.executablePath
        guard FileManager.default.fileExists(atPath: exePath) else {
            RyLog.shared.log("guest 可执行文件不存在：\(exePath)", level: .error, tag: "guest")
            return
        }
        let bundleURL = URL(fileURLWithPath: exePath).deletingLastPathComponent()

        RyLog.shared.log("准备启动 \(app.name)（\(app.bundleIdentifier)）", level: .info, tag: "guest")

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
                DispatchQueue.main.async { GuestWindowHost.shared.presentScaffold(bundleURL) }
                return
            }
            RyLog.shared.log("fs  WRITE  \(exePath) (Mach-O patched MH_EXECUTE->MH_DYLIB)", level: .info, tag: "guest")

            // 2) Re-sign the patched binary (JIT-less; required by AMFI).
            if case .failure(let err) = CodeSigner.shared.sign(bundleAt: bundleURL.path) {
                RyLog.shared.log("guest 重新签名失败：\(err.localizedDescription)", level: .error, tag: "guest")
                DispatchQueue.main.async { GuestWindowHost.shared.presentScaffold(bundleURL) }
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

                // 5) dlopen + jump to the guest entry. The guest UIApplicationMain is
                //    intercepted and hosted; by the time this returns the guest UI is up.
                RyLog.shared.log("ks  EXEC   \(exePath) (guest entry point)", level: .info, tag: "guest")
                if RyLaunchGuestExecutable(exePath) == nil {
                    RyLog.shared.log("guest dlopen/启动失败", level: .error, tag: "guest")
                    GuestWindowHost.shared.presentScaffold(bundleURL)
                }
            }
        }
    }

    /// Tear down the in-process guest (the "弹出 App" action). Process survives.
    static func eject() {
        GuestWindowHost.shared.dismissGuest()
        EntitlementPolicy.shared.setActive(bundleID: nil)
    }
}
