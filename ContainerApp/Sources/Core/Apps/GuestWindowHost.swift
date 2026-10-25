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

    /// Fallback: when the guest cannot be patched/signed/launched, tell the user
    /// WHAT failed — never fake the app's UI.
    ///
    /// This used to instantiate the guest's storyboard in a hosted window. For
    /// Sileo that produced a black screen WITH ITS TAB BAR: the storyboard's
    /// initial view controller is a custom tab-bar controller, the guest binary
    /// was never dlopen'd, so UIKit logged "Unknown class" and fell back to the
    /// BASE UITabBarController — a skeleton that looks like the app half
    /// launched. The user reasonably asked "都没签上，怎么能看到画面": the
    /// answer was this scaffold, running none of the guest's code. An honest
    /// error page is strictly better than a convincing fake.
    func presentScaffold(_ bundleURL: URL, reason: String) {
        let guestBundle = Bundle(url: bundleURL) ?? Bundle.main
        let appName = (guestBundle.object(forInfoDictionaryKey: "CFBundleDisplayName")
                    ?? guestBundle.object(forInfoDictionaryKey: "CFBundleName")) as? String
                   ?? bundleURL.lastPathComponent.replacingOccurrences(of: ".app", with: "")

        // NOTE: a window created without a windowScene is NOT rendered on
        // iOS 13+ — it must be bound to the host's scene or it stays invisible
        // (this is why the floating Home key used to vanish).
        let win = UIWindow(frame: UIScreen.main.bounds)
        if let scene = Self.hostWindowScene() {
            win.windowScene = scene
        }
        win.windowLevel = .alert
        win.rootViewController = GuestErrorViewController(appName: appName, reason: reason)
        win.makeKeyAndVisible()
        self.scaffoldWindow = win
        RyBoxAppDelegate.containerWindow?.isHidden = true
        installGuestChrome()
        RyLog.shared.log("启动失败，向用户显示原因：\(reason)", level: .warn, tag: "ui")
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

/// Shown instead of a guest that could not be patched / signed / launched.
///
/// The screen states the app, the failure reason verbatim (the same string the
/// log carries), and offers one action: back to the SpringBoard. It deliberately
/// looks nothing like the guest — see `presentScaffold` for why the old
/// storyboard-skeleton fallback was removed.
final class GuestErrorViewController: UIViewController {

    private let appName: String
    private let reason: String

    init(appName: String, reason: String) {
        self.appName = appName
        self.reason = reason
        super.init(nibName: nil, bundle: nil)
    }

    // Never decoded from a storyboard — created in code only.
    required init?(coder: NSCoder) {
        fatalError("GuestErrorViewController is created in code only")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        let stack = UIStackView()
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false

        let title = UILabel()
        title.text = "无法启动「\(appName)」"
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        title.textColor = .white
        title.textAlignment = .center

        let body = UILabel()
        body.text = reason
        body.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        body.textColor = UIColor(white: 0.75, alpha: 1)
        body.textAlignment = .center
        body.numberOfLines = 0
        // The reason is a log-grade string (exit codes, osstatus); keep it
        // readable but never let it overflow the screen.
        body.lineBreakMode = .byCharWrapping

        let back = UIButton(type: .system)
        back.setTitle("返回桌面", for: .normal)
        back.titleLabel?.font = .systemFont(ofSize: 16, weight: .medium)
        back.setTitleColor(.white, for: .normal)
        back.backgroundColor = UIColor(white: 0.18, alpha: 1)
        back.layer.cornerRadius = 12
        back.contentEdgeInsets = UIEdgeInsets(top: 10, left: 22, bottom: 10, right: 22)
        back.addTarget(self, action: #selector(backToSpringBoard), for: .touchUpInside)

        stack.addArrangedSubview(title)
        stack.addArrangedSubview(body)
        stack.addArrangedSubview(back)
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: -20),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -28),
            back.heightAnchor.constraint(equalToConstant: 44)
        ])
    }

    @objc private func backToSpringBoard() {
        GuestWindowHost.shared.dismissGuest()
    }
}
