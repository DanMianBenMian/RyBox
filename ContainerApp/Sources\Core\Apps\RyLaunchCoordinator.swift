import Foundation
import UIKit

/// Launch coordinator for RyBox's two guest models.
///
///  - GUI guest (LiveContainer in-process model): run INSIDE RyBox's already
///    running process via dlopen + entry-point jump. The container UI stays
///    alive; "弹出 App" tears down the guest window — it does NOT exit the app.
///    (See GuestRuntime + RyBoxGuestBundle.)
///  - CLI guest: spawn as a managed microkernel process (see ProcessManager).
///
/// NOTE: the earlier "relaunch RyBox as the guest" design was wrong — it lost
/// container state and prevented multitasking. Do not reintroduce exit(0)
/// relaunch for GUI guests.
public final class RyLaunchCoordinator: ObservableObject {
    public static let shared = RyLaunchCoordinator()

    public enum LaunchError: Error, LocalizedError {
        case guestNotFound
        public var errorDescription: String? {
            switch self { case .guestNotFound: return "找不到 guest App" }
        }
    }

    /// Find an imported app by bundle id.
    public func app(bundleID: String) -> ImportedApp? {
        AppImporter.shared.importedApps.first(where: { $0.bundleIdentifier == bundleID })
    }

    /// User confirmed running a GUI app: launch it IN-PROCESS (no relaunch).
    public func requestRun(_ app: ImportedApp) {
        GuestRuntime.launchInProcess(app)
    }

    /// "弹出 App": tear down the in-process guest window and return to container.
    /// The RyBox process keeps running (container UI is restored).
    public func ejectToContainer() {
        GuestRuntime.eject()
    }

    /// Run a CLI guest INSIDE the running container (spawn, no relaunch).
    @discardableResult
    public func runCLIGuest(_ app: ImportedApp) -> NKProcess? {
        let env = GuestEnvironment.build(for: app)
        return ProcessManager.shared.spawn(executable: app.executablePath,
                                           arguments: [],
                                           environment: env,
                                           workingDirectory: app.containerPath,
                                           captureOutput: true)
    }
}
