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
            os_log("RyBox: guest executable missing: %@", exePath)
            return
        }
        let bundleURL = URL(fileURLWithPath: exePath).deletingLastPathComponent()

        // Heavy, potentially slow work (Mach-O patch + re-sign of the whole
        // bundle) runs OFF the main thread so the UI never freezes while a guest
        // binary is being prepared — a large IPA signature previously blocked the
        // main thread and made the launch look "frozen". Only the dyld/UIKit
        // hooking + dlopen stays on the main thread, because UIKit expects to be
        // touched from there.
        DispatchQueue.global(qos: .userInitiated).async {
            // 1) Patch the guest executable in place (MH_EXECUTE -> MH_DYLIB, PAGEZERO).
            let patchRC = RyPatchGuestExecutable(exePath)
            guard patchRC == 0 else {
                os_log("RyBox: Mach-O patch failed (rc=%d) for %@", patchRC, exePath)
                DispatchQueue.main.async { GuestWindowHost.shared.presentScaffold(bundleURL) }
                return
            }

            // 2) Re-sign the patched binary (JIT-less; required by AMFI).
            if case .failure(let err) = CodeSigner.shared.sign(bundleAt: bundleURL.path) {
                os_log("RyBox: guest re-sign failed: %@", err.localizedDescription)
                DispatchQueue.main.async { GuestWindowHost.shared.presentScaffold(bundleURL) }
                return
            }

            DispatchQueue.main.async {
                // 3) Redirect mainBundle + set the guest executable path for the hooks.
                RyBoxGuestBundle.activate(bundleURL)
                RySetGuestMainExecutablePath(exePath)

                // 4) Install dyld / UIKit hooks (best installed before the guest's
                //    dlopen-time symbol resolution).
                RyInstallGuestDyldHooks()

                // 5) dlopen + jump to the guest entry. The guest UIApplicationMain is
                //    intercepted and hosted; by the time this returns the guest UI is up.
                if RyLaunchGuestExecutable(exePath) == nil {
                    os_log("RyBox: guest dlopen/launch failed")
                    GuestWindowHost.shared.presentScaffold(bundleURL)
                }
            }
        }
    }

    /// Tear down the in-process guest (the "弹出 App" action). Process survives.
    static func eject() {
        GuestWindowHost.shared.dismissGuest()
    }
}
