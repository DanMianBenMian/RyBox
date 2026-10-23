import SwiftUI
import UIKit
import Combine

/// Lock screen shown on cold start and after every respring — the same
/// behaviour as a real device, which is what makes "注销 SpringBoard" feel right.
struct LockScreenView: View {
    var onUnlock: () -> Void

    @State private var now = Date()
    @State private var dragOffset: CGFloat = 0
    @ObservedObject private var theme = ThemeEngine.shared

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f
    }()

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "zh_CN")
        f.dateFormat = "M月d日 EEEE"
        return f
    }()

    var body: some View {
        ZStack {
            wallpaper
                .ignoresSafeArea()

            VStack(spacing: 0) {
                StatusBarView()
                    .padding(.top, 8)

                VStack(spacing: 2) {
                    Text(Self.dateFormatter.string(from: now))
                        .font(.system(size: 18, weight: .medium))
                    Text(Self.timeFormatter.string(from: now))
                        .font(.system(size: 78, weight: .medium, design: .rounded))
                        .monospacedDigit()
                }
                .foregroundStyle(.white)
                .shadow(color: .black.opacity(0.35), radius: 8, y: 2)
                .padding(.top, 30)

                Spacer()

                VStack(spacing: 10) {
                    Image(systemName: "lock.open.fill")
                        .font(.system(size: 20))
                    Text("上滑解锁")
                        .font(.system(size: 14, weight: .medium))
                }
                .foregroundStyle(.white.opacity(0.9))
                .padding(.bottom, 26)
            }
        }
        .contentShape(Rectangle())
        .offset(y: dragOffset)
        .gesture(
            DragGesture()
                .onChanged { v in
                    // Only upward drags move the lock screen, and it resists.
                    let upward = min(0, v.translation.height)
                    dragOffset = max(-220, upward * 0.55)
                }
                .onEnded { v in
                    if dragOffset < -80 {
                        withAnimation(.spring(response: 0.42, dampingFraction: 0.86)) {
                            dragOffset = -UIScreen.main.bounds.height
                        }
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.28) { onUnlock() }
                    } else {
                        withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) { dragOffset = 0 }
                    }
                }
        )
        .onReceive(Timer.publish(every: 15, on: .main, in: .common).autoconnect()) { now = $0 }
    }

    @ViewBuilder
    private var wallpaper: some View {
        if let img = theme.wallpaper(.lock) {
            Image(uiImage: img)
                .resizable()
                .scaledToFill()
                .ignoresSafeArea()
        } else {
            LinearGradient(colors: [Color(red: 0.08, green: 0.13, blue: 0.36),
                                    Color(red: 0.20, green: 0.33, blue: 0.70)],
                           startPoint: .topLeading, endPoint: .bottomTrailing)
        }
    }
}

/// Black screen with a spinner — the transition a real respring plays.
struct RespringView: View {
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            ProgressView()
                .controlSize(.large)
                .tint(.white)
        }
    }
}
