import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var env: RuntimeEnvironment

    var body: some View {
        SpringBoardView()
        // NOTE: no HomeButtonWindow.install() here. An always-on overlay window
        // at cold start used to swallow every touch in the container (pickers,
        // sheets, the desktop itself). The Home key is now a liquid-glass pill
        // inside this window; the overlay exists only during guest runtime.
    }
}
