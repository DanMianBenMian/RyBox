import SwiftUI
import UIKit
import Combine

/// RyBox's live log, shown as a full-screen app on the desktop.
///
/// The user asked for exactly this: an app you can open to watch what the
/// container is doing in REAL TIME (import → sign → patch → dlopen → scene
/// drive), plus a floating ball that keeps the log reachable from ANY screen,
/// including while a guest app is running on top of the shell.
///
/// The same view powers both surfaces: the desktop app shows the whole log,
/// the floating ball shows a compact live tail that expands on tap.
struct LogConsoleView: View {
    /// Compact mode = the floating-ball panel (fewer rows, no toolbar chrome).
    var compact: Bool = false
    /// Called when the user asks to close the surface (the ball closes itself).
    var onClose: (() -> Void)? = nil

    @ObservedObject private var log = RyLog.shared
    @State private var query = ""
    @State private var follow = true
    @State private var showLevels = false

    private var rows: [RyLog.Entry] {
        let base = log.search(query)
        return compact ? Array(base.prefix(40)) : base
    }

    private var dateFmt: DateFormatter {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            if !compact { filterBar }
            list
        }
        .background(Color.black)
        .preferredColorScheme(.dark)
    }

    // MARK: Header

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "terminal.fill")
                .foregroundStyle(.green)
            Text(compact ? "实时日志" : "RyBox 实时日志")
                .font(.system(size: 15, weight: .semibold, design: .monospaced))
                .foregroundStyle(.white)
            Spacer()
            if !compact {
                Text("\(log.entries.count) 行")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.55))
            }
            if follow {
                Image(systemName: "arrow.down.circle.fill")
                    .font(.system(size: 13))
                    .foregroundStyle(.green.opacity(0.85))
            }
            if let onClose {
                Button(action: onClose) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 15))
                        .foregroundStyle(.white.opacity(0.7))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(Color.white.opacity(0.06))
    }

    private var filterBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 12))
                    .foregroundStyle(.white.opacity(0.6))
                TextField("搜索日志", text: $query)
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(.white)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(.white.opacity(0.08), in: Capsule())

            Menu {
                ForEach(RyLog.Level.allCases, id: \.self) { lvl in
                    Button {
                        log.minimumLevel = lvl
                    } label: {
                        if log.minimumLevel == lvl {
                            Label(lvl.rawValue, systemImage: "checkmark")
                        } else {
                            Text(lvl.rawValue)
                        }
                    }
                }
            } label: {
                Image(systemName: "line.3.horizontal.decrease.circle")
                    .font(.system(size: 15))
                    .foregroundStyle(.white.opacity(0.8))
            }

            Button {
                follow.toggle()
            } label: {
                Image(systemName: follow ? "arrow.down.circle.fill" : "arrow.down.circle")
                    .font(.system(size: 15))
                    .foregroundStyle(follow ? .green : .white.opacity(0.6))
            }
            .buttonStyle(.plain)

            Button {
                UIPasteboard.general.string = log.plainText()
            } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 14))
                    .foregroundStyle(.white.opacity(0.8))
            }
            .buttonStyle(.plain)

            Button(role: .destructive) {
                log.clear()
            } label: {
                Image(systemName: "trash")
                    .font(.system(size: 14))
                    .foregroundStyle(.red.opacity(0.9))
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color.white.opacity(0.04))
    }

    // MARK: List

    private var list: some View {
        ScrollViewReader { proxy in
            ScrollView(.vertical, showsIndicators: false) {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(rows) { entry in
                        row(entry)
                            .id(entry.id)
                    }
                    if rows.isEmpty {
                        Text("（暂无日志）")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.4))
                            .padding(.top, 12)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 24)
            }
            .onChange(of: log.revision) { _ in
                guard follow else { return }
                if let last = rows.first {
                    withAnimation(.linear(duration: 0.12)) {
                        proxy.scrollTo(last.id, anchor: .top)
                    }
                }
            }
        }
    }

    private func row(_ e: RyLog.Entry) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(dateFmt.string(from: e.date))
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(.white.opacity(0.42))
                .frame(width: 74, alignment: .leading)
            Text(e.level.symbol)
                .font(.system(size: 10.5, weight: .bold, design: .monospaced))
                .foregroundStyle(color(for: e.level))
                .frame(width: 10, alignment: .leading)
            Text(e.tag)
                .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                .foregroundStyle(.cyan.opacity(0.85))
                .frame(width: 62, alignment: .leading)
            Text(e.message)
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(.white.opacity(0.92))
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 1.5)
    }

    private func color(for lvl: RyLog.Level) -> Color {
        switch lvl {
        case .debug: return .white.opacity(0.45)
        case .info: return .green.opacity(0.9)
        case .warn: return .orange
        case .error: return .red
        }
    }
}
