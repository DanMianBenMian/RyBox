import UIKit
import SwiftUI

/// UIKit application delegate for RyBox's CONTAINER mode.
/// (Guest mode is handled directly in main.swift via UIApplicationMain.)
final class RyBoxAppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    /// Exposed so GuestWindowHost can hide/restore the container window when a
    /// guest UI takes over the screen.
    static var containerWindow: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        VirtualRoot.shared.ensure()
        Task { await RuntimeEnvironment.shared.detect() }

        let content = ContentView().environmentObject(RuntimeEnvironment.shared)
        let vc = UIHostingController(rootView: content)
        let win = UIWindow(frame: UIScreen.main.bounds)
        win.rootViewController = vc
        win.makeKeyAndVisible()
        self.window = win
        Self.containerWindow = win
        return true
    }
}
