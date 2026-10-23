import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var env: RuntimeEnvironment
    @State private var bootDone = BootGate.isCompleted

    var body: some View {
        ZStack {
            if bootDone {
                SpringBoardView()
                    .transition(.opacity)
            } else {
                BootGateView { enterSystem() }
                    .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.3), value: bootDone)
        // Sileo must only be installed once a certificate exists, otherwise it
        // would be registered unsigned and never re-signed afterwards.
        .onAppear { if bootDone { PreinstalledStore.shared.bootstrapIfNeeded() } }
        // NOTE: no HomeButtonWindow.install() here. An always-on overlay window
        // at cold start used to swallow every touch in the container (pickers,
        // sheets, the desktop itself). The Home key is now a liquid-glass pill
        // inside this window; the overlay exists only during guest runtime.
    }

    /// Gate passed: a signing identity is configured AND a firmware has been
    /// imported. Now the real work starts — install the preinstalled Sileo
    /// (unzip -> sign -> register on the desktop) and show the SpringBoard.
    private func enterSystem() {
        bootDone = true
        PreinstalledStore.shared.bootstrapIfNeeded()
    }
}
