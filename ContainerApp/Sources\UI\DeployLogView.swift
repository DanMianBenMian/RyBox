import SwiftUI

/// Full-screen deploy log shown while the firmware is being unpacked into the
/// virtual root. Black background, white monospaced text — the look the user
/// asked for ("运行部署时跑黑底白字日志").
struct DeployLogView: View {
    @ObservedObject private var fw = FirmwareImporter.shared
    @State private var scroll = 0

    private static let fmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    var body: some View {
        Color.black.ignoresSafeArea()
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "shippingbox.fill").foregroundStyle(.white)
                Text("正在部署系统环境")
                    .font(.system(size: 15, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.white)
                Spacer()
                Text("\(Int(fw.progress * 100))%")
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
                        ForEach(Array(fw.log.enumerated()), id: \.offset) { i, line in
                            Text(line)
                                .font(.system(size: 12.5, design: .monospaced))
                                .foregroundStyle(color(for: line))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(i)
                        }
                    }
                    .padding(.horizontal, 18)
                }
                .onChange(of: fw.log.count) { _ in
                    withAnimation { proxy.scrollTo(max(0, fw.log.count - 1), anchor: .bottom) }
                }
                .onAppear { proxy.scrollTo(max(0, fw.log.count - 1), anchor: .bottom) }
            }
            Spacer(minLength: 0)
        }
    }

    private func color(for line: String) -> Color {
        if line.hasPrefix("✓") || line.hasPrefix("✅") { return Color(red: 0.35, green: 0.85, blue: 0.45) }
        if line.hasPrefix("✗") || line.hasPrefix("⚠") { return Color(red: 1.0, green: 0.75, blue: 0.30) }
        if line.hasPrefix("›") || line.hasPrefix("•") || line.hasPrefix("◦") { return .white.opacity(0.85) }
        return .white
    }
}
