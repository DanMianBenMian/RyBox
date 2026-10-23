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

    private init() {}

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
