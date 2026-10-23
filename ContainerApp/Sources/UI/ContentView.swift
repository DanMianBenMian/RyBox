import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var env: RuntimeEnvironment

    var body: some View {
        SpringBoardView()
            .onAppear { HomeButtonWindow.shared.install() }
    }
}
