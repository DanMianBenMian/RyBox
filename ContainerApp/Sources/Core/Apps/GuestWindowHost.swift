import UIKit

/// Coordinates the on-screen windows for the in-process guest:
///   - hides the container (SpringBoard) window when a guest UI comes up,
///   - installs the floating Home-key chrome above the guest,
///   - restores the container window when the guest is dismissed.
///
/// The guest's actual UIWindow is created by the UIApplicationMain interception
/// hook in RyDyldHooks.m (it loads the guest's storyboard / principal VC, or
/// drives the guest's own SceneDelegate). This host only manages the chrome
/// around it.
final class GuestWindowHost {
    static let shared = GuestWindowHost()

    /// Posted by the dyld hook (RyDyldHooks.m) once the guest UI is up.
    private let guestDidLaunch = Notification.Name("rybox.guestDidLaunch")
    /// Posted by the dyld hook when the guest produced NO window.
    private let guestDidFail = Notification.Name("rybox.guestDidFail")

    private var overlayWindow: UIWindow?
    private var scaffoldWindow: UIWindow?

    init() {
        NotificationCenter.default.addObserver(
            self, selector: #selector(onGuestDidLaunch),
            name: guestDidLaunch, object: nil)
        NotificationCenter.default.addObserver(
            self, selector: #selector(onGuestDidFail),
            name: guestDidFail, object: nil)
    }

    /// Called from the dyld hook: the guest UIWindow is already key+visible.
    /// Hide the container window and show the floating Home-key chrome.
    @objc private func onGuestDidLaunch() {
        RyLog.shared.log("guest launched — handing the screen over", level: .info, tag: "ui")
        RyBoxAppDelegate.containerWindow?.isHidden = true
        installGuestChrome()
    }

    /// The guest never produced a window. Restore the container so the user is
    /// NOT stranded on a black screen, and say what happened.
    @objc private func onGuestDidFail() {
        RyLog.shared.log("guest failed to show any UI — restoring SpringBoard", level: .error, tag: "ui")
        restoreContainer()
        GuestChromeWindow.shared.teardown()
    }

    /// Fallback: when the guest cannot be patched/signed/launched, still present
    /// its storyboard / principal VC in a hosted window so the user sees a result.
    func presentScaffold(_ bundleURL: URL) {
        let guestBundle = Bundle(url: bundleURL) ?? Bundle.main
        // NOTE: a window created without a windowScene is NOT rendered on
        // iOS 13+ — it must be bound to the host's scene or it stays invisible
        // (this is why the floating Home key used to vanish).
        let win = UIWindow(frame: UIScreen.main.bounds)
        if let scene = Self.hostWindowScene() {
            win.windowScene = scene
        }
        win.windowLevel = .alert

        let sbName = (guestBundle.object(forInfoDictionaryKey: "UIMainStoryboardFile")
                  ?? guestBundle.object(forInfoDictionaryKey: "UILaunchStoryboardName")) as? String
        if let sbName = sbName,
           let sb = UIStoryboard(name: sbName, bundle: guestBundle) as? UIStoryboard {
            win.rootViewController = sb.instantiateInitialViewController()
        } else if let principal = guestBundle.object(forInfoDictionaryKey: "NSPrincipalClass") as? String,
                  let cls = NSClassFromString(principal) as? UIViewController.Type {
            win.rootViewController = cls.init()
        } else {
            let vc = UIViewController()
            vc.view.backgroundColor = .systemBackground
            let label = UILabel()
            label.text = "Guest 已载入（沙箱视图）"
            label.textAlignment = .center
            vc.view.addSubview(label)
            label.frame = vc.view.bounds
            win.rootViewController = vc
        }
        win.makeKeyAndVisible()
        self.scaffoldWindow = win
        RyBoxAppDelegate.containerWindow?.isHidden = true
        installGuestChrome()
        RyLog.shared.log("scaffold window shown for \(bundleURL.lastPathComponent)", level: .warn, tag: "ui")
    }

    /// Floating Home-key chrome shown while a guest owns the screen. The virtual
    /// Home key (tap) tears the guest down and returns to the SpringBoard.
    private func installGuestChrome() {
        GuestChromeWindow.shared.install()
    }

    /// The host's UIWindowScene — every window RyBox creates must be bound to
    /// one, otherwise iOS 13+ refuses to draw it.
    static func hostWindowScene() -> UIWindowScene? {
        for s in UIApplication.shared.connectedScenes {
            if let ws = s as? UIWindowScene, ws.screen == UIScreen.main { return ws }
        }
        return UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first
    }

    /// Bring the container window back (the SpringBoard is alive again).
    func restoreContainer() {
        if let container = RyBoxAppDelegate.containerWindow {
            container.isHidden = false
            container.makeKeyAndVisible()
        }
    }

    /// Dismiss the guest entirely; the container window beneath is restored.
    func dismissGuest() {
        // Hide the guest-runtime chrome and any guest-level windows.
        GuestChromeWindow.shared.teardown()
        overlayWindow?.isHidden = true
        overlayWindow = nil
        scaffoldWindow?.isHidden = true
        scaffoldWindow = nil
        // Hide EVERY window except the container (SpringBoard). A scene-based
        // guest builds its window at .normal level (not .alert), so the old
        // "windowLevel >= .alert" filter left it on screen after Home.
        if let container = RyBoxAppDelegate.containerWindow {
            for w in UIApplication.shared.windows where w !== container {
                w.isHidden = true
            }
            container.isHidden = false
            container.makeKeyAndVisible()
            // The floating log ball lives in its own (non-key) windows, which
            // the sweep above also hid. Bring it back — it is meant to float
            // above the desktop as much as above a guest.
            FloatingLogBall.shared.reshow()
        } else {
            for w in UIApplication.shared.windows { w.isHidden = true }
        }
        // Drop the hook's strong references so the guest's UI objects die.
        RyReleaseGuestReferences()
        RyLog.shared.log("guest ejected, SpringBoard restored", level: .info, tag: "ui")
    }
}
