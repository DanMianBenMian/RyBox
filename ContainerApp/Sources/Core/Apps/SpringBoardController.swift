import Foundation
import UIKit

/// Coordinates the RyBox shell: the SpringBoard home screen, launching guests,
/// and the virtual Home button "go home" action.
///
/// "Home" means: eject any in-process guest window (process stays alive) and ask
/// the home screen to dismiss any presented panel — always returning to the
/// SpringBoard. This is the unified "弹出 App" entry (see GuestChromeWindow).
final class SpringBoardController: ObservableObject {
    static let shared = SpringBoardController()

    /// Posted when the virtual Home button is tapped, so the home screen can
    /// dismiss any presented built-in tool panel.
    static let goHomeNotification = Notification.Name("rybox.goHome")

    /// "注销 SpringBoard" — spinner, re-read themes, re-place icons, lock screen.
    static let respringNotification = Notification.Name("rybox.respring")

    /// "注销资源库" — rescan /Library/Themes and drop the image caches.
    static let reloadLibraryNotification = Notification.Name("rybox.reloadLibrary")

    /// Gesture-driven shell panels (Control Center / App Switcher / Notification
    /// Center). Driven by local @State in SpringBoardView, but the names are
    /// declared here so any subsystem (e.g. a hardware-button shim) can trigger
    /// them too.
    static let appSwitcherNotification = Notification.Name("rybox.appSwitcher")
    static let controlCenterNotification = Notification.Name("rybox.controlCenter")
    static let notificationCenterNotification = Notification.Name("rybox.notificationCenter")

    /// Most-recently-opened desktop item ids (front = newest). Backs the App
    /// Switcher and survives relaunch so the recents deck is stable.
    @Published private(set) var recents: [String] = []
    private let recentsKey = "rybox.recents"

    private init() {
        recents = UserDefaults.standard.stringArray(forKey: recentsKey) ?? []
    }

    /// Record an app open at the front of the recents deck (dedup + cap).
    func recordOpen(_ id: String) {
        var next = recents.filter { $0 != id }
        next.insert(id, at: 0)
        if next.count > 16 { next = Array(next.prefix(16)) }
        recents = next
        UserDefaults.standard.set(recents, forKey: recentsKey)
    }

    /// Drop an item from the recents deck (App Switcher "swipe up to quit").
    func removeRecent(_ id: String) {
        recents.removeAll { $0 == id }
        UserDefaults.standard.set(recents, forKey: recentsKey)
    }

    /// Return to the SpringBoard. Container process is never terminated.
    func goHome() {
        GuestRuntime.eject()  // tear down the in-process guest window, if any
        NotificationCenter.default.post(name: Self.goHomeNotification, object: nil)
    }

    /// 注销 SpringBoard. The container process is never terminated — the shell
    /// is rebuilt in place, exactly what a jailbreak respring does to
    /// SpringBoard (which is also why themes need it).
    func respring() {
        goHome()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
            NotificationCenter.default.post(name: Self.respringNotification, object: nil)
        }
    }

    /// 注销资源库: rescan themes + drop cached artwork.
    func reloadLibrary() {
        NotificationCenter.default.post(name: Self.reloadLibraryNotification, object: nil)
    }
}
