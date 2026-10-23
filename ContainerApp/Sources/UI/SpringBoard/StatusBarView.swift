import SwiftUI
import Combine

/// Fake status bar drawn INSIDE the container.
///
/// A sandboxed app cannot read the real carrier/battery state (and certainly
/// cannot replace the system status bar), so this is a look-alike: real clock,
/// plausible glyphs. It exists because theming packages ship `UIImages` for the
/// status bar and a home screen without one looks wrong.
struct StatusBarView: View {
    var bright: Bool = true

    @State private var now = Date()

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f
    }()

    var body: some View {
        HStack(alignment: .center) {
            Text(Self.timeFormatter.string(from: now))
                .font(.system(size: 14, weight: .semibold))
                .monospacedDigit()

            Spacer()

            HStack(spacing: 5) {
                Image(systemName: "cellularbars")
                    .font(.system(size: 12, weight: .semibold))
                Image(systemName: "wifi")
                    .font(.system(size: 12, weight: .semibold))
                battery
            }
        }
        .foregroundStyle(bright ? .white : .primary)
        .padding(.horizontal, 22)
        .frame(height: 20)
        .contentShape(Rectangle())
        .onReceive(Timer.publish(every: 10, on: .main, in: .common).autoconnect()) { now = $0 }
    }

    private var battery: some View {
        HStack(spacing: 2) {
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 2.5, style: .continuous)
                    .strokeBorder((bright ? Color.white : Color.primary).opacity(0.5), lineWidth: 1)
                    .frame(width: 24, height: 12)
                RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                    .fill(bright ? Color.white : Color.primary)
                    .frame(width: 15, height: 8)
                    .padding(.leading, 2)
            }
            Capsule()
                .fill((bright ? Color.white : Color.primary).opacity(0.45))
                .frame(width: 2, height: 5)
        }
    }
}
