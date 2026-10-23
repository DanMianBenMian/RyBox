import Foundation
import UIKit

/// Coordinates the RyBox shell: the SpringBoard home screen, launching guests,
/// and the virtual Home button "go home" action.
///
/// "Home" means: eject any in-process guest window (process stays alive) and ask
/// the home screen to dismiss any presented panel — always returning to the
/// SpringBoard. This is the unified "弹出 App" entry (see HomeButtonWindow).
final class SpringBoardController: ObservableObject {
    static let shared = SpringBoardController()

    /// Posted when the virtual Home button is tapped, so the home screen can
    /// dismiss any presented built-in tool panel.
    static let goHomeNotification = Notification.Name("rybox.goHome")

    private init() {}

    /// Return to the SpringBoard. Container process is never terminated.
    func goHome() {
        GuestRuntime.eject()  // tear down the in-process guest window, if any
        NotificationCenter.default.post(name: Self.goHomeNotification, object: nil)
    }
}
