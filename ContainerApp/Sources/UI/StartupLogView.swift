import SwiftUI

/// Boot log shown right after the user enters the system (and on every cold
/// relaunch into a completed container). Black background, white monospaced text,
/// in the same family as the deploy log so the two "system coming up" screens
/// feel like one boot sequence. When the lines finish it calls `onFinished` and
/// the SpringBoard takes over.
struct StartupLogView: View {
    var onFinished: () -> Void

    @State private var lines: [String] = []
    @State private var done = false

    private static let allLines: [String] = [
        "[rybox] SpringBoard 启动中…",
        "[rybox] 挂载虚拟根 /  (Documents/root)",
        "[rybox] 载入主题引擎 → /Library/Themes",
        "[rybox] 注册内置应用：设置 / 文件 / 终端 / 导入",
        "[rybox] 还原桌面布局与 Dock",
        "[rybox] 初始化微内核进程管理器",
        "[rybox] 安装预置包（Sileo）…",
        "[rybox] 应用签名身份（p12 + mobileprovision）",
        "[rybox] 启动完成，欢迎使用 RyBox"
    ]

    var body: some View {
        Color.black.ignoresSafeArea()
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "shippingbox.fill").foregroundStyle(.white)
                Text("RyBox")
                    .font(.system(size: 15, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.white)
                Spacer()
                Text(done ? "完成" : "启动中")
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.8))
            }
            .padding(.horizontal, 18)
            .padding(.top, 18)

            Divider().background(Color.white.opacity(0.25))
                .padding(.vertical, 10)

            ScrollViewReader { proxy in
                ScrollView(.vertical, showsIndicators: false) {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(Array(lines.enumerated()), id: \.offset) { i, line in
                            Text(line)
                                .font(.system(size: 12.5, design: .monospaced))
                                .foregroundStyle(.white.opacity(0.9))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(i)
                        }
                    }
                    .padding(.horizontal, 18)
                }
                .onChange(of: lines.count) { _ in
                    withAnimation { proxy.scrollTo(max(0, lines.count - 1), anchor: .bottom) }
                }
            }
            Spacer(minLength: 0)
        }
        .task { runSequence() }
    }

    private func runSequence() {
        guard lines.isEmpty else { return }
        Task {
            for (i, line) in Self.allLines.enumerated() {
                try? await Task.sleep(nanoseconds: 220_000_000)
                lines.append(line)
                if i == Self.allLines.count - 1 {
                    try? await Task.sleep(nanoseconds: 450_000_000)
                    done = true
                    try? await Task.sleep(nanoseconds: 250_000_000)
                    onFinished()
                }
            }
        }
    }
}
