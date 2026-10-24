import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var env: RuntimeEnvironment
    @State private var bootDone = BootGate.isCompleted
    /// Drives the one-time boot log shown right after entering the system
    /// (and on every cold relaunch into an already-completed container).
    @State private var startupDone = false

    var body: some View {
        ZStack {
            if !bootDone {
                BootGateView { enterSystem() }
                    .transition(.opacity)
            } else if !startupDone {
                StartupLogView { startupDone = true }
                    .transition(.opacity)
            } else {
                SpringBoardView()
                    .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.3), value: bootDone)
        .animation(.easeInOut(duration: 0.3), value: startupDone)
        // Sileo must only be installed once a certificate exists, otherwise it
        // would be registered unsigned and never re-signed afterwards.
        .onAppear {
            if bootDone && startupDone { PreinstalledStore.shared.bootstrapIfNeeded() }
        }
    }

    /// Gate passed: a signing identity is configured AND a firmware has been
    /// imported. Now the real work starts — show the boot log, then install the
    /// preinstalled Sileo (unzip -> sign -> register on the desktop) and show
    /// the SpringBoard.
    private func enterSystem() {
        bootDone = true
        startupDone = false
        PreinstalledStore.shared.bootstrapIfNeeded()
    }
}
