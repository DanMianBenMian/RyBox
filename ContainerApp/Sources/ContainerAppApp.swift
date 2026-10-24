import UIKit
import SwiftUI

/// UIKit application delegate for RyBox's CONTAINER mode.
///
/// RyBox is scene-capable (see `UIApplicationSceneManifest` in Info.plist) so it
/// owns a real `UIWindowScene`. The on-screen window is created by
/// `RyBoxSceneDelegate` (the modern, correct place). This app delegate only does
/// the non-visual boot setup, plus a SAFETY fallback: if for any reason the scene
/// delegate never produced a window, we build one here so the user never sees a
/// black screen. `GuestWindowHost` hides/restores the window via
/// `RyBoxAppDelegate.containerWindow` when a guest UI takes over the screen.
final class RyBoxAppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    /// The single on-screen container window. Set by `RyBoxSceneDelegate` (normal
    /// path) or by the fallback below. Exposed so GuestWindowHost can
    /// hide/restore it when a guest UI takes over the screen.
    static var containerWindow: UIWindow?

    /// The host's UIWindowScene. Every window RyBox creates must be bound to a
    /// scene on iOS 13+ or it is never rendered — that is why the floating
    /// "主屏" button used to disappear the moment the guest took over.
    static var hostScene: UIWindowScene?

    /// True once a window exists (scene path or fallback). Guards the fallback so
    /// we never end up with two windows.
    private static var hasWindow: Bool { containerWindow != nil }

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        VirtualRoot.shared.ensure()
        // Install the filesystem-redirect layer and point it at the virtual root.
        // Hooks are GATED (disabled until a guest is active), so RyBox's own file
        // operations are never affected at launch — only a guest's absolute path
        // opens get routed into the jbroot.
        ry_fs_install_hooks()
        ry_fs_set_root(VirtualRoot.shared.rootURL.path)
        // Populate the virtual root with the bundled minimal jbroot (dpkg/apt +
        // standard /usr /var layout). Non-blocking and idempotent; if the asset
        // is missing it logs and continues (Sileo still installs, tools absent).
        JbRoot.shared.bootstrap()
        Task { await RuntimeEnvironment.shared.detect() }
        // Live log: the container's own start-up trace, so the 日志 app (and the
        // floating ball) show the real boot sequence.
        RyLog.shared.log("RyBox 启动 · bundle=\(Bundle.main.bundleIdentifier ?? "?")", level: .info, tag: "boot")
        // NOTE: Sileo is NO LONGER installed here. It now runs from the boot
        // gate / ContentView once a certificate is configured, so it gets
        // signed with the user's identity instead of staying unsigned forever.
        //
        // The window itself is created by RyBoxSceneDelegate.scene(_:willConnect
        // ToSession:). If that never fires (should not happen with the scene
        // manifest present), fall back to building the window here after a short
        // delay so the shell is never stuck on a black screen.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
            guard !Self.hasWindow else { return }
            self?.buildFallbackWindow()
        }
        return true
    }

    /// Build the container window the legacy way. Only reached if the scene
    /// delegate failed to run; idempotent via `containerWindow`.
    fileprivate func buildFallbackWindow() {
        guard Self.containerWindow == nil else { return }
        installContainerWindow()
    }

    /// Shared window construction used by both the scene delegate and the
    /// fallback. Keeps the two paths identical so the shell looks and behaves the
    /// same regardless of which one ran. When a scene is supplied the window is
    /// created with `UIWindow(windowScene:)` (the correct iOS 13+ initializer);
    /// the fallback uses the legacy `initWithFrame:`.
    fileprivate func installContainerWindow(to scene: UIWindowScene? = nil) {
        let content = ContentView().environmentObject(RuntimeEnvironment.shared)
        let vc = UIHostingController(rootView: content)
        let win: UIWindow
        if let scene = scene {
            win = UIWindow(windowScene: scene)
        } else {
            win = UIWindow(frame: UIScreen.main.bounds)
            // Bind the fallback window to a scene too, otherwise it never draws.
            if let s = GuestWindowHost.hostWindowScene() {
                win.windowScene = s
            }
        }
        win.rootViewController = vc
        win.makeKeyAndVisible()
        self.window = win
        Self.containerWindow = win
        if let scene = scene { Self.hostScene = scene }
        RyLog.shared.log("容器窗口已创建 (scene=\(scene != nil ? "yes" : "fallback"))", level: .info, tag: "boot")
    }
}

/// Scene delegate: the modern home for the container window. RyBox declares a
/// single `UIWindowSceneSessionRoleApplication` scene (see Info.plist), so this is
/// where the SpringBoard shell's window is created. Keeping RyBox scene-capable is
/// what lets in-process GUI guests attach their own window to a real scene and run
/// their scene lifecycle inside RyBox's process.
final class RyBoxSceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(_ scene: UIScene,
               willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        RyBoxAppDelegate.hostScene = windowScene
        // Reuse the exact same construction as the app-delegate fallback so both
        // paths render an identical shell — but bind the window to THIS scene via
        // UIWindow(windowScene:), the correct iOS 13+ initializer.
        (UIApplication.shared.delegate as? RyBoxAppDelegate)?.installContainerWindow(to: windowScene)
        self.window = RyBoxAppDelegate.containerWindow
        RyLog.shared.log("scene 已连接 · connectedScenes=\(UIApplication.shared.connectedScenes.count)", level: .info, tag: "ui")
    }

    func sceneDidDisconnect(_ scene: UIScene) {
        RyLog.shared.log("scene 断开连接", level: .warn, tag: "ui")
    }
}
