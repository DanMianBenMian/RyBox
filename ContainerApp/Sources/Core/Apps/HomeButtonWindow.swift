import UIKit

/// A transparent, full-screen container view that ONLY lets its own subviews
/// (the Home / eject buttons) receive touches; every other touch passes
/// THROUGH to the window(s) beneath. Used by the guest-runtime chrome window,
/// which is KEY (so its buttons work) while the guest UI below stays live.
final class PassThroughView: UIView {
    override func hitTest(_ point: CGPoint, with event: UIEvent?) -> UIView? {
        let hit = super.hitTest(point, with: event)
        // If the only thing hit is this transparent container itself, let the
        // touch fall through to windows below.
        return (hit === self) ? nil : hit
    }
}

/// Floating chrome shown WHILE A GUEST UI IS ON SCREEN (the container window is
/// hidden at that point): a liquid-glass 主屏 key and a 弹出 App button.
///
/// This window is intentionally NEVER installed at cold start. An always-on
/// overlay window used to sit above the SpringBoard and swallow every touch in
/// the container (document pickers, sheets, the desktop itself) — the UI only
/// became interactive after tapping Home, which re-keyed the container window.
/// The container's Home key is now a SwiftUI liquid-glass pill rendered INSIDE
/// the SpringBoard window; this chrome exists only while a guest owns the
/// screen, where it is made key so its own buttons stay tappable.
final class GuestChromeWindow {
    static let shared = GuestChromeWindow()
    private var window: UIWindow?

    /// Install the floating chrome. Called when a guest UI comes up; teardown()
    /// removes it. Safe to call repeatedly (installs once).
    func install() {
        guard window == nil else { return }

        let win = UIWindow(frame: UIScreen.main.bounds)
        win.windowLevel = .alert + 100
        win.isUserInteractionEnabled = true

        let vc = UIViewController()
        vc.view = PassThroughView()
        vc.view.backgroundColor = .clear

        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false

        let home = chromeButton(title: "主屏", systemImage: "house.fill")
        home.addTarget(self, action: #selector(homeTapped), for: .touchUpInside)

        let eject = chromeButton(title: "弹出 App", systemImage: "xmark")
        eject.addTarget(self, action: #selector(ejectTapped), for: .touchUpInside)

        stack.addArrangedSubview(home)
        stack.addArrangedSubview(eject)
        vc.view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.trailingAnchor.constraint(equalTo: vc.view.safeAreaLayoutGuide.trailingAnchor,
                                            constant: -16),
            stack.bottomAnchor.constraint(equalTo: vc.view.safeAreaLayoutGuide.bottomAnchor,
                                          constant: -16)
        ])

        win.rootViewController = vc
        // Key + pass-through root: the buttons receive touches, everything
        // else falls through to the guest window beneath.
        win.makeKeyAndVisible()
        self.window = win
    }

    func teardown() {
        window?.isHidden = true
        window = nil
    }

    private func chromeButton(title: String, systemImage: String) -> UIButton {
        let btn = UIButton(type: .system)
        var config = UIButton.Configuration.filled()
        config.title = title
        config.image = UIImage(systemName: systemImage)
        config.imagePadding = 6
        config.cornerStyle = .capsule
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
        // Ejects the guest AND posts goHome so the SpringBoard resets.
        SpringBoardController.shared.goHome()
    }

    @objc private func ejectTapped() {
        RyLaunchCoordinator.shared.ejectToContainer()
    }
}
