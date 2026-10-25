import UIKit
import SwiftUI

/// A transparent, full-screen container view that ONLY lets its own subviews
/// (the Home / eject buttons, the floating log ball) receive touches; every
/// other touch passes THROUGH to the window(s) beneath. Used by the guest-runtime
/// chrome window and the floating log ball, which are KEY (so their controls
/// work) while the app underneath stays live.
/// Real bottom safe-area inset of the app's main window.
///
/// A hand-built `UIWindow` that is not laid out by a scene (like the guest
/// chrome window) reports `safeAreaInsets` of 0, which made the floating Home
/// key float ~20pt off from the SpringBoard key. We therefore read the inset
/// from whichever window in the app actually has a non-zero bottom inset (the
/// SpringBoard host window) and fall back to 0. Both the SwiftUI desktop key
/// and the UIKit floating key call this, so they can never drift apart.
enum DeviceSafeArea {
    static func bottomInset() -> CGFloat {
        let windows = UIApplication.shared.windows
        for w in windows where w.safeAreaInsets.bottom > 0 {
            return w.safeAreaInsets.bottom
        }
        return windows.first?.safeAreaInsets.bottom ?? 0
    }
}

final class PassThroughView: UIView {
    override func hitTest(_ point: CGPoint, with event: UIEvent?) -> UIView? {
        let hit = super.hitTest(point, with: event)
        // If the only thing hit is this transparent container itself, let the
        // touch fall through to windows below. Its SUBVIEWS (buttons, the ball)
        // still hit normally — that is what makes them usable.
        return (hit === self) ? nil : hit
    }
}

/// Floating chrome shown WHILE A GUEST UI IS ON SCREEN (the container window is
/// hidden at that point): a single liquid-glass 主屏 key.
///
/// The old "弹出 App" button has been removed — the virtual Home key IS the way
/// out (it tears down the in-process guest and returns to SpringBoard), so a
/// second eject control was redundant and confused the UI.
///
/// 2026-10-25 (user requirement 「为啥要两种不同的Home键，直接用SpringBoard就
/// 行，一直置于顶部即可」): the key is no longer a hand-drawn UIKit pill. It
/// hosts THE SAME SwiftUI view the SpringBoard uses (`HomeKeyButton`) through a
/// UIHostingController, so the two can never drift apart again — same 46×46
/// ultraThinMaterial square, same continuous cornerRadius 13, same house.fill
/// glyph, same shadow. Its position also matches the SpringBoard key exactly
/// (bottom-center, 4pt above the safe area), so opening or closing a guest no
/// longer makes the key jump.
///
/// "一直置于顶部": the window sits at `.alert + 100`, above the guest's own
/// windows (scene guests build at `.normal`, the error scaffold at `.alert`),
/// and is made key so its button stays tappable while every other touch falls
/// through to the guest window beneath.
///
/// This window is intentionally NEVER installed at cold start. The container's
/// Home key is the shared SwiftUI view rendered INSIDE the SpringBoard window;
/// this chrome exists only while a guest owns the screen.
final class GuestChromeWindow {
    static let shared = GuestChromeWindow()
    private var window: UIWindow?
    /// Keeps the hosting controller alive for the window's lifetime.
    private var hosting: UIHostingController<HomeKeyButton>?

    /// Install the floating chrome. Called when a guest UI comes up; teardown()
    /// removes it. Safe to call repeatedly (installs once).
    func install() {
        guard window == nil else { return }

        let win = UIWindow(frame: UIScreen.main.bounds)
        // CRITICAL: bind the window to the host's UIWindowScene. On iOS 13+ a
        // window WITHOUT a scene is never rendered — it stays invisible, which
        // is exactly why the Home key disappeared once RyBox became
        // scene-capable. A window with no scene also cannot become key, so the
        // button would be dead even if it drew.
        if let scene = GuestWindowHost.hostWindowScene() {
            win.windowScene = scene
        }
        // Above the guest's own windows (`.normal` for scene guests, `.alert`
        // for the error scaffold) — the key is always on top.
        win.windowLevel = .alert + 100
        win.isUserInteractionEnabled = true

        let vc = UIViewController()
        vc.view = PassThroughView()
        vc.view.backgroundColor = .clear

        // The ONE home-key design — the same SwiftUI view the SpringBoard
        // renders, hosted so the pixels cannot diverge.
        let hosted = UIHostingController(
            rootView: HomeKeyButton(action: { [weak self] in self?.homeTapped() })
        )
        hosted.view.backgroundColor = .clear
        hosted.view.translatesAutoresizingMaskIntoConstraints = false
        vc.addChild(hosted)
        vc.view.addSubview(hosted.view)
        // Match the SpringBoard key EXACTLY: read the device's real safe-area
        // bottom inset from the host window (DeviceSafeArea), NOT this
        // hand-built window's safeAreaLayoutGuide (which reports 0 here and
        // made the key float off-position when a guest was open). The desktop
        // key uses the same source, so the key can never jump between the two.
        let bottomInset = DeviceSafeArea.bottomInset()
        NSLayoutConstraint.activate([
            hosted.view.widthAnchor.constraint(equalToConstant: 46),
            hosted.view.heightAnchor.constraint(equalToConstant: 46),
            hosted.view.centerXAnchor.constraint(equalTo: vc.view.centerXAnchor),
            hosted.view.bottomAnchor.constraint(
                equalTo: vc.view.bottomAnchor, constant: -(bottomInset + 4))
        ])
        hosted.didMove(toParent: vc)

        win.rootViewController = vc
        // Key + pass-through root: the button receives touches, everything
        // else falls through to the guest window beneath.
        win.makeKeyAndVisible()
        self.window = win
        self.hosting = hosted
        RyLog.shared.log("guest chrome (主屏 button) installed", level: .info, tag: "ui")
    }

    func teardown() {
        hosting?.willMove(toParent: nil)
        hosting?.view.removeFromSuperview()
        hosting?.removeFromParent()
        hosting = nil
        window?.isHidden = true
        window = nil
    }

    @objc private func homeTapped() {
        // Tears down the in-process guest AND posts goHome so the SpringBoard resets.
        SpringBoardController.shared.goHome()
    }
}
