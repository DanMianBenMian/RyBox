import SwiftUI
import UIKit
import Combine

/// The floating log ball.
///
/// The user asked for a floating window that sits ON TOP of everything — so
/// the log stays reachable while a guest app is running (the guest covers the
/// whole screen, which is exactly when you need the log most).
///
/// ## Why this is two TINY windows and not one full-screen one
///
/// The first implementation used a single full-screen window with a
/// `PassThroughView` root and called `makeKeyAndVisible()`. That froze the
/// entire desktop: the user's words were "他的交互区域把所有控件盖住了，像卡死".
/// Two separate things went wrong at once:
///
///   1. `makeKeyAndVisible()` STOLE the key window from the SpringBoard. A
///      non-key window still receives touches (UIKit walks visible windows by
///      `windowLevel`), but once the SpringBoard stopped being key, its
///      SwiftUI gesture plumbing stopped delivering — drag, long-press menu and
///      paging all went dead at the same time, which is exactly the report.
///   2. A full-screen hit surface depends on `hitTest` returning nil for every
///      point outside the ball. That is fragile: one non-nil answer anywhere
///      and the whole screen is swallowed.
///
/// So each control now lives in a window that is EXACTLY the size of that
/// control, and NEITHER window is made key. There is no surface left over that
/// could possibly intercept a touch, and the SpringBoard keeps its key window
/// (and therefore its gestures) untouched.
final class FloatingLogBall: NSObject {
    static let shared = FloatingLogBall()

    private static let ballSize = CGSize(width: 46, height: 46)
    private static let panelSize = CGSize(width: 320, height: 260)

    private var ballWindow: UIWindow?
    private var panelWindow: UIWindow?

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

    var isVisible: Bool { ballWindow != nil }

    // MARK: - Show / hide

    func show() {
        guard ballWindow == nil else { return }
        guard let scene = Self.currentScene() else {
            RyLog.shared.log("浮窗日志球无法开启：没有可用的 windowScene", level: .error, tag: "ui")
            return
        }

        // Restore the saved position (bottom-right by default) BEFORE building
        // the windows, because the window frames come from it.
        if let saved = UserDefaults.standard.object(forKey: posKey) as? [Double],
           saved.count == 2 {
            ballCenter = CGPoint(x: saved[0], y: saved[1])
        } else {
            let b = UIScreen.main.bounds
            ballCenter = CGPoint(x: b.maxX - 50, y: b.maxY - 140)
        }

        // ---- the ball, in its own 46×46 window -----------------------------
        let bw = UIWindow(frame: Self.ballFrame(ballCenter))
        bw.windowScene = scene
        bw.windowLevel = .alert + 200
        bw.backgroundColor = .clear
        // NOTE: `isHidden = false`, NOT `makeKeyAndVisible()`. See the header.
        bw.isHidden = false

        let ball = UIView()
        ball.backgroundColor = UIColor.secondarySystemBackground.withAlphaComponent(0.92)
        ball.layer.cornerRadius = 23
        ball.layer.borderWidth = 0.8
        ball.layer.borderColor = UIColor.white.withAlphaComponent(0.30).cgColor
        ball.layer.shadowColor = UIColor.black.cgColor
        ball.layer.shadowOpacity = 0.35
        ball.layer.shadowRadius = 8
        ball.layer.shadowOffset = CGSize(width: 0, height: 3)
        ball.frame = bw.bounds
        ball.autoresizingMask = [.flexibleWidth, .flexibleHeight]

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
            icon.centerXAnchor.constraint(equalTo: ball.centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: ball.centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 20),
            icon.heightAnchor.constraint(equalToConstant: 20),
            dot.widthAnchor.constraint(equalToConstant: 9),
            dot.heightAnchor.constraint(equalToConstant: 9),
            dot.trailingAnchor.constraint(equalTo: ball.trailingAnchor, constant: -1),
            dot.topAnchor.constraint(equalTo: ball.topAnchor, constant: 1)
        ])

        let bvc = UIViewController()
        bvc.view = UIView(frame: bw.bounds)
        bvc.view?.backgroundColor = .clear
        bvc.view?.addSubview(ball)
        bw.rootViewController = bvc
        ballWindow = bw

        // ---- the log panel, in its own 320×260 window ----------------------
        let pw = UIWindow(frame: Self.panelFrame(ballCenter))
        pw.windowScene = scene
        pw.windowLevel = .alert + 200
        pw.backgroundColor = .clear
        pw.isHidden = true          // only shown while expanded

        let panel = UIView()
        panel.backgroundColor = UIColor.black.withAlphaComponent(0.82)
        panel.layer.cornerRadius = 14
        panel.layer.borderWidth = 0.6
        panel.layer.borderColor = UIColor.white.withAlphaComponent(0.16).cgColor
        panel.layer.shadowColor = UIColor.black.cgColor
        panel.layer.shadowOpacity = 0.4
        panel.layer.shadowRadius = 16
        panel.frame = pw.bounds
        panel.autoresizingMask = [.flexibleWidth, .flexibleHeight]

        let text = UILabel()
        text.numberOfLines = 0
        text.font = .monospacedSystemFont(ofSize: 9.5, weight: .regular)
        text.textColor = UIColor.white.withAlphaComponent(0.9)
        text.translatesAutoresizingMaskIntoConstraints = false
        panel.addSubview(text)
        NSLayoutConstraint.activate([
            text.topAnchor.constraint(equalTo: panel.topAnchor, constant: 8),
            text.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 10),
            text.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -10),
            text.bottomAnchor.constraint(equalTo: panel.bottomAnchor, constant: -8)
        ])

        let pvc = UIViewController()
        pvc.view = UIView(frame: pw.bounds)
        pvc.view?.backgroundColor = .clear
        pvc.view?.addSubview(panel)
        pw.rootViewController = pvc
        panelWindow = pw

        self.ball = ball
        self.ballIcon = icon
        self.errorDot = dot
        self.panel = panel
        self.logText = text
        self.panelVisible = false

        // Gestures: a tap toggles the panel, a drag moves the ball. Both live
        // on the ball itself, inside the ball's own window, so they can never
        // be confused with a desktop gesture.
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

        RyLog.shared.log("浮窗日志球已开启", level: .info, tag: "ui")
    }

    func hide() {
        cancellables.removeAll()
        ballWindow?.isHidden = true
        ballWindow?.rootViewController = nil
        ballWindow = nil
        panelWindow?.isHidden = true
        panelWindow?.rootViewController = nil
        panelWindow = nil
        ball = nil
        ballIcon = nil
        errorDot = nil
        panel = nil
        logText = nil
        panelVisible = false
        RyLog.shared.log("浮窗日志球已关闭", level: .info, tag: "ui")
    }

    func toggle() {
        isVisible ? hide() : show()
    }

    /// `GuestWindowHost.dismissGuest()` hides EVERY window except the container
    /// one, which would take the ball down with the guest. Bring it back.
    func reshow() {
        guard ballWindow != nil else { return }
        ballWindow?.isHidden = false
        panelWindow?.isHidden = panelVisible
    }

    // MARK: - Frames

    private static func ballFrame(_ center: CGPoint) -> CGRect {
        CGRect(x: center.x - ballSize.width / 2,
               y: center.y - ballSize.height / 2,
               width: ballSize.width, height: ballSize.height)
    }

    /// The panel sits just above the ball, clamped on screen.
    private static func panelFrame(_ center: CGPoint) -> CGRect {
        let b = UIScreen.main.bounds
        var x = center.x - panelSize.width + ballSize.width / 2 + 8
        var y = center.y - panelSize.height - 30
        x = max(12, min(b.maxX - panelSize.width - 12, x))
        y = max(60, min(b.maxY - panelSize.height - 12, y))
        return CGRect(x: x, y: y, width: panelSize.width, height: panelSize.height)
    }

    private func applyFrames() {
        ballWindow?.frame = Self.ballFrame(ballCenter)
        panelWindow?.frame = Self.panelFrame(ballCenter)
    }

    // MARK: - Gestures

    @objc private func onTap() {
        panelVisible.toggle()
        panelWindow?.isHidden = !panelVisible
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
            // Keep the ball on screen (and clear of the status bar).
            let b = UIScreen.main.bounds
            next.x = max(30, min(b.maxX - 30, next.x))
            next.y = max(80, min(b.maxY - 40, next.y))
            ballCenter = next
            applyFrames()
        case .ended, .cancelled:
            UserDefaults.standard.set([Double(ballCenter.x), Double(ballCenter.y)], forKey: posKey)
        default:
            break
        }
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
