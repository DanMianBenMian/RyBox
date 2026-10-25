import UIKit

/// A transparent, full-screen container view that ONLY lets its own subviews
/// (the Home / eject buttons, the floating log ball) receive touches; every
/// other touch passes THROUGH to the window(s) beneath. Used by the guest-runtime
/// chrome window and the floating log ball, which are KEY (so their controls
/// work) while the app underneath stays live.
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
/// Placement (2026-10-25, user requirement): the key sits at the BOTTOM CENTER
/// as a SQUARE (~48pt, rounded-rect) key — NOT the old bottom-right capsule.
/// This matches the SpringBoard's own home key shape and position, so the
/// control stays in the same spot when a guest app opens and closes.
///
/// This window is intentionally NEVER installed at cold start. The container's
/// Home key is a SwiftUI liquid-glass pill rendered INSIDE the SpringBoard
/// window; this chrome exists only while a guest owns the screen, where it is
/// made key so its button stays tappable while every other touch falls through
/// to the guest window beneath.
final class GuestChromeWindow {
    static let shared = GuestChromeWindow()
    private var window: UIWindow?

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
        win.windowLevel = .alert + 100
        win.isUserInteractionEnabled = true

        let vc = UIViewController()
        vc.view = PassThroughView()
        vc.view.backgroundColor = .clear

        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false

        // Icon-only square key, bottom-center — same look and spot as the
        // SpringBoard home key, so opening/closing a guest doesn't move it.
        let home = chromeButton(title: nil, systemImage: "house.fill")
        home.addTarget(self, action: #selector(homeTapped), for: .touchUpInside)

        stack.addArrangedSubview(home)
        vc.view.addSubview(stack)
        NSLayoutConstraint.activate([
            home.widthAnchor.constraint(equalToConstant: 48),
            home.heightAnchor.constraint(equalToConstant: 48),
            stack.centerXAnchor.constraint(equalTo: vc.view.centerXAnchor),
            stack.bottomAnchor.constraint(equalTo: vc.view.safeAreaLayoutGuide.bottomAnchor,
                                          constant: -14)
        ])

        win.rootViewController = vc
        // Key + pass-through root: the button receives touches, everything
        // else falls through to the guest window beneath.
        win.makeKeyAndVisible()
        self.window = win
        RyLog.shared.log("guest chrome (主屏 button) installed", level: .info, tag: "ui")
    }

    func teardown() {
        window?.isHidden = true
        window = nil
    }

    private func chromeButton(title: String?, systemImage: String) -> UIButton {
        let btn = UIButton(type: .system)
        var config = UIButton.Configuration.filled()
        // nil title → icon-only SQUARE key (bottom-center home key);
        // a titled call keeps the old capsule pill shape.
        config.title = title
        config.image = UIImage(systemName: systemImage)
        config.imagePadding = title == nil ? 0 : 6
        config.cornerStyle = title == nil ? .medium : .capsule
        config.baseBackgroundColor = UIColor.secondarySystemBackground.withAlphaComponent(0.92)
        config.baseForegroundColor = .label
        btn.configuration = config
        btn.layer.shadowColor = UIColor.black.cgColor
        btn.layer.shadowOpacity = 0.3
        btn.layer.shadowRadius = 6
        btn.layer.shadowOffset = CGSize(width: 0, height: 2)
        return btn
    }

    @objc private func homeTapped() {
        // Tears down the in-process guest AND posts goHome so the SpringBoard resets.
        SpringBoardController.shared.goHome()
    }
}
