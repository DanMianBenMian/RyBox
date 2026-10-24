import SwiftUI
import UIKit
import Combine

/// The floating log ball.
///
/// The user asked for a floating window that sits ON TOP of everything — so
/// the log stays reachable while a guest app is running (the guest covers the
/// whole screen, which is exactly when you need the log most).
///
/// Implementation notes that matter:
///   * It lives in its OWN `UIWindow` at `.alert + 200` level, so it floats
///     above both the container window AND any guest window (the guest is
///     installed at `.alert`).
///   * The window is created with `UIWindow(windowScene:)` — a window without
///     a scene is NOT shown on iOS 13+, which is exactly the bug that made
///     the Home key disappear after RyBox became scene-capable.
///   * The ball is a plain UIKit view (not SwiftUI) so the touch handling is
///     unambiguous: a drag moves the ball, a tap expands the log panel, and
///     every other touch passes straight through to the app underneath.
final class FloatingLogBall: NSObject {
    static let shared = FloatingLogBall()

    private var window: UIWindow?
    private var ball: UIView?
    private var ballIcon: UIImageView?
    private var errorDot: UIView?
    private var panel: UIView?
    private var logText: UILabel?
    private var panelVisible = false

    private var ballCenter: CGPoint = .zero
    private var dragStart: CGPoint = .zero
    private var ballStart: CGPoint = .zero

    /// Persisted so the ball keeps its place across launches.
    private let posKey = "rybox.floatBall.pos"

    private var cancellables = Set<AnyCancellable>()

    private override init() {
        super.init()
    }

    var isVisible: Bool { window != nil }

    // MARK: - Show / hide

    func show() {
        guard window == nil else { return }
        guard let scene = Self.currentScene() else {
            RyLog.shared.log("浮窗日志球无法开启：没有可用的 windowScene", .error, "ui")
            return
        }

        let win = UIWindow(windowScene: scene)
        win.windowLevel = .alert + 200
        win.isUserInteractionEnabled = true
        win.backgroundColor = .clear

        let root = PassThroughView()
        root.backgroundColor = .clear

        let vc = UIViewController()
        vc.view = root
        win.rootViewController = vc

        // --- the ball ---
        let ball = UIView()
        ball.backgroundColor = UIColor.secondarySystemBackground.withAlphaComponent(0.92)
        ball.layer.cornerRadius = 23
        ball.layer.borderWidth = 0.8
        ball.layer.borderColor = UIColor.white.withAlphaComponent(0.30).cgColor
        ball.layer.shadowColor = UIColor.black.cgColor
        ball.layer.shadowOpacity = 0.35
        ball.layer.shadowRadius = 8
        ball.layer.shadowOffset = CGSize(width: 0, height: 3)
        ball.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(ball)

        let icon = UIImageView(image: UIImage(systemName: "terminal.fill"))
        icon.tintColor = .label
        icon.contentMode = .scaleAspectFit
        icon.translatesAutoresizingMaskIntoConstraints = false
        ball.addSubview(icon)

        let dot = UIView()
        dot.backgroundColor = .systemRed
        dot.layer.cornerRadius = 4.5
        dot.translatesAutoresizingMaskIntoConstraints = false
        dot.isHidden = true
        ball.addSubview(dot)

        NSLayoutConstraint.activate([
            ball.widthAnchor.constraint(equalToConstant: 46),
            ball.heightAnchor.constraint(equalToConstant: 46),
            icon.centerXAnchor.constraint(equalTo: ball.centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: ball.centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 20),
            icon.heightAnchor.constraint(equalToConstant: 20),
            dot.widthAnchor.constraint(equalToConstant: 9),
            dot.heightAnchor.constraint(equalToConstant: 9),
            dot.trailingAnchor.constraint(equalTo: ball.trailingAnchor, constant: -1),
            dot.topAnchor.constraint(equalTo: ball.topAnchor, constant: 1)
        ])

        // --- the log panel ---
        let panel = UIView()
        panel.backgroundColor = UIColor.black.withAlphaComponent(0.82)
        panel.layer.cornerRadius = 14
        panel.layer.borderWidth = 0.6
        panel.layer.borderColor = UIColor.white.withAlphaComponent(0.16).cgColor
        panel.layer.shadowColor = UIColor.black.cgColor
        panel.layer.shadowOpacity = 0.4
        panel.layer.shadowRadius = 16
        panel.translatesAutoresizingMaskIntoConstraints = false
        panel.isHidden = true
        root.addSubview(panel)

        let text = UILabel()
        text.numberOfLines = 0
        text.font = .monospacedSystemFont(ofSize: 9.5, weight: .regular)
        text.textColor = UIColor.white.withAlphaComponent(0.9)
        text.translatesAutoresizingMaskIntoConstraints = false
        panel.addSubview(text)

        NSLayoutConstraint.activate([
            panel.widthAnchor.constraint(equalToConstant: 320),
            panel.heightAnchor.constraint(equalToConstant: 260),
            panel.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -12),
            panel.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -110),
            text.topAnchor.constraint(equalTo: panel.topAnchor, constant: 8),
            text.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 10),
            text.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -10),
            text.bottomAnchor.constraint(equalTo: panel.bottomAnchor, constant: -8)
        ])

        win.makeKeyAndVisible()
        window = win
        self.ball = ball
        self.ballIcon = icon
        self.errorDot = dot
        self.panel = panel
        self.logText = text

        // Restore the saved position (bottom-right by default).
        if let saved = UserDefaults.standard.object(forKey: posKey) as? [Double],
           saved.count == 2 {
            ballCenter = CGPoint(x: saved[0], y: saved[1])
        } else {
            let b = UIScreen.main.bounds
            ballCenter = CGPoint(x: b.maxX - 50, y: b.maxY - 140)
        }
        applyBallPosition()

        // Gestures: a tap toggles the panel, a drag moves the ball.
        let tap = UITapGestureRecognizer(target: self, action: #selector(onTap))
        ball.addGestureRecognizer(tap)
        let pan = UIPanGestureRecognizer(target: self, action: #selector(onPan(_:)))
        ball.addGestureRecognizer(pan)

        // Live-update the panel + the error dot.
        RyLog.shared.$entries
            .receive(on: DispatchQueue.main)
            .sink { [weak self] entries in
                self?.refresh(entries: entries)
            }
            .store(in: &cancellables)

        RyLog.shared.log("浮窗日志球已开启", .info, "ui")
    }

    func hide() {
        cancellables.removeAll()
        window?.isHidden = true
        window?.rootViewController = nil
        window = nil
        ball = nil
        ballIcon = nil
        errorDot = nil
        panel = nil
        logText = nil
        panelVisible = false
        RyLog.shared.log("浮窗日志球已关闭", .info, "ui")
    }

    func toggle() {
        isVisible ? hide() : show()
    }

    // MARK: - Gestures

    @objc private func onTap() {
        panelVisible.toggle()
        UIView.animate(withDuration: 0.22) {
            self.panel?.alpha = self.panelVisible ? 1 : 0
            self.panel?.isHidden = !self.panelVisible
        }
        if panelVisible { refresh(entries: RyLog.shared.entries) }
    }

    @objc private func onPan(_ g: UIPanGestureRecognizer) {
        guard let ball = ball else { return }
        switch g.state {
        case .began:
            dragStart = g.location(in: ball.superview)
            ballStart = ballCenter
        case .changed:
            let now = g.location(in: ball.superview)
            var next = CGPoint(x: ballStart.x + (now.x - dragStart.x),
                               y: ballStart.y + (now.y - dragStart.y))
            // Keep the ball on screen.
            let b = UIScreen.main.bounds
            next.x = max(30, min(b.maxX - 30, next.x))
            next.y = max(80, min(b.maxY - 40, next.y))
            ballCenter = next
            applyBallPosition()
        case .ended, .cancelled:
            UserDefaults.standard.set([Double(ballCenter.x), Double(ballCenter.y)], forKey: posKey)
        default:
            break
        }
    }

    private func applyBallPosition() {
        ball?.center = ballCenter
    }

    // MARK: - Live content

    private func refresh(entries: [RyLog.Entry]) {
        errorDot?.isHidden = !entries.contains { $0.level == .error }
        guard panelVisible, let text = logText else { return }
        let tail = entries.suffix(40).map { e in
            "[\(e.level.symbol)] \(e.tag) · \(e.message)"
        }.joined(separator: "\n")
        text.text = tail.isEmpty ? "（暂无日志）" : tail
    }

    private static func currentScene() -> UIWindowScene? {
        for s in UIApplication.shared.connectedScenes {
            if let ws = s as? UIWindowScene, ws.screen == UIScreen.main { return ws }
        }
        return UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first
    }
}
