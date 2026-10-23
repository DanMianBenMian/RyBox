import UIKit

/// A floating "virtual Home button" that stays ABOVE both the container UI and
/// any in-process guest window. Tapping it returns to the SpringBoard
/// (SpringBoardController.goHome) without terminating the process.
///
/// Implemented as an always-visible UIWindow overlay (not key, so it does not
/// steal keyboard/first-responder from the container or guest beneath it — only
/// the button itself is interactive). Position/size adapt to iPad vs iPhone.
final class HomeButtonWindow {
    static let shared = HomeButtonWindow()
    private var window: UIWindow?

    /// Install the overlay once. Safe to call repeatedly.
    func install() {
        guard window == nil else { return }

        let win = UIWindow(frame: UIScreen.main.bounds)
        win.windowLevel = .alert + 200   // above guest window (.alert+1) & container
        win.isHidden = false
        win.isUserInteractionEnabled = true

        let vc = UIViewController()
        vc.view.backgroundColor = .clear

        let isIPad = UITraitCollection.current.horizontalSizeClass == .regular
        let btn = UIButton(type: .system)
        btn.setImage(UIImage(systemName: "house.fill"), for: .normal)
        btn.tintColor = .label
        btn.backgroundColor = UIColor.secondarySystemBackground.withAlphaComponent(0.92)
        btn.layer.shadowColor = UIColor.black.cgColor
        btn.layer.shadowOpacity = 0.35
        btn.layer.shadowRadius = 5
        btn.layer.shadowOffset = CGSize(width: 0, height: 2)

        if isIPad {
            // Centered pill on iPad.
            btn.setTitle(" 主屏", for: .normal)
            btn.titleLabel?.font = .systemFont(ofSize: 15, weight: .medium)
            btn.layer.cornerRadius = 18
            btn.translatesAutoresizingMaskIntoConstraints = false
            btn.contentEdgeInsets = UIEdgeInsets(top: 8, left: 16, bottom: 8, right: 16)
        } else {
            btn.layer.cornerRadius = 22
            btn.translatesAutoresizingMaskIntoConstraints = false
            btn.widthAnchor.constraint(equalToConstant: 44).isActive = true
            btn.heightAnchor.constraint(equalToConstant: 44).isActive = true
        }
        btn.addTarget(self, action: #selector(tapped), for: .touchUpInside)

        vc.view.addSubview(btn)
        NSLayoutConstraint.activate([
            btn.centerXAnchor.constraint(equalTo: vc.view.centerXAnchor),
            btn.bottomAnchor.constraint(equalTo: vc.view.safeAreaLayoutGuide.bottomAnchor,
                                       constant: isIPad ? -16 : -14)
        ])

        win.rootViewController = vc
        // NOTE: we intentionally do NOT make this window key, so the container's
        // text inputs (terminal) keep working. Visibility + a root VC connects it.
        self.window = win
    }

    @objc private func tapped() {
        SpringBoardController.shared.goHome()
    }
}
