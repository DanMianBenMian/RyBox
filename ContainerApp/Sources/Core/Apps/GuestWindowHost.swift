import UIKit

/// Coordinates the on-screen windows for the in-process guest:
///   - hides the container (SpringBoard) window when a guest UI comes up,
///   - installs the "弹出 App" eject overlay above the guest,
///   - restores the container window when the guest is ejected.
///
/// The guest's actual UIWindow is created by the UIApplicationMain interception
/// hook in RyDyldHooks.m (it loads the guest's storyboard / principal VC). This
/// host only manages the chrome around it.
final class GuestWindowHost {
    static let shared = GuestWindowHost()

    /// Posted by the dyld hook (RyDyldHooks.m) once the guest UI is up.
    private let guestDidLaunch = Notification.Name("rybox.guestDidLaunch")

    private var overlayWindow: UIWindow?
    private var scaffoldWindow: UIWindow?

    init() {
        NotificationCenter.default.addObserver(
            self, selector: #selector(onGuestDidLaunch),
            name: guestDidLaunch, object: nil)
    }

    /// Called from the dyld hook: the guest UIWindow is already key+visible.
    /// Hide the container window and show the eject button.
    @objc private func onGuestDidLaunch() {
        RyBoxAppDelegate.containerWindow?.isHidden = true
        installEjectOverlay()
    }

    /// Fallback: when the guest cannot be patched/signed/launched, still present
    /// its storyboard / principal VC in a hosted window so the user sees a result.
    func presentScaffold(_ bundleURL: URL) {
        let guestBundle = Bundle(url: bundleURL) ?? Bundle.main
        let win = UIWindow(frame: UIScreen.main.bounds)
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
        installEjectOverlay()
    }

    /// "弹出 App" floating button: dismiss the guest, return to container.
    private func installEjectOverlay() {
        let overlay = UIWindow(frame: UIScreen.main.bounds)
        overlay.windowLevel = .alert + 1
        let vc = UIViewController()
        vc.view = PassThroughView()   // keep the guest UI beneath interactive
        vc.view.backgroundColor = .clear
        let btn = UIButton(type: .system)
        btn.setTitle("弹出 App", for: .normal)
        btn.addTarget(self, action: #selector(ejectTapped), for: .touchUpInside)
        btn.backgroundColor = UIColor.systemBackground.withAlphaComponent(0.9)
        btn.layer.cornerRadius = 16
        btn.translatesAutoresizingMaskIntoConstraints = false
        vc.view.addSubview(btn)
        NSLayoutConstraint.activate([
            btn.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor, constant: -16),
            btn.bottomAnchor.constraint(equalTo: vc.view.safeAreaLayoutGuide.bottomAnchor, constant: -16)
        ])
        overlay.rootViewController = vc
        overlay.isHidden = false
        overlay.makeKeyAndVisible()
        self.overlayWindow = overlay
    }

    @objc private func ejectTapped() {
        RyLaunchCoordinator.shared.ejectToContainer()
    }

    /// Dismiss the guest entirely; the container window beneath is restored.
    func dismissGuest() {
        // Hide the eject overlay and any guest-level windows.
        overlayWindow?.isHidden = true
        overlayWindow = nil
        scaffoldWindow?.isHidden = true
        scaffoldWindow = nil
        for w in UIApplication.shared.windows where w.windowLevel >= .alert {
            w.isHidden = true
        }
        // Restore the container (SpringBoard) window.
        if let c = RyBoxAppDelegate.containerWindow {
            c.isHidden = false
            c.makeKeyAndVisible()
        }
    }
}
