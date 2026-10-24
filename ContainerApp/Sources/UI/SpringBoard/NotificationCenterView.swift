import SwiftUI
import Combine

/// iOS-style Notification Center, recreated inside the RyBox shell.
///
/// Triggered by a downward swipe on the (fake) status bar. Combines three
/// things the real Notification Center does:
///   * a Spotlight-style search field that filters every desktop item,
///   * the notification list (seeded from app badges + a couple of system
///     notices, since a sandboxed container has no real push stream),
///   * a small widget stack (clock / battery / storage) at the bottom.
/// A tap on the dimming backdrop or a downward drag dismisses it.
struct NotificationCenterView: View {
    var onOpen: (DesktopItem) -> Void
    var onDismiss: () -> Void

    @State private var query = ""
    @State private var now = Date()
    @State private var dragY: CGFloat = 0

    @ObservedObject private var store = DesktopStore.shared

    private var results: [DesktopItem] {
        guard !query.isEmpty else { return [] }
        let q = query.lowercased()
        return store.allItems.filter {
            $0.name.lowercased().contains(q)
                || ($0.bundleIdentifier?.lowercased().contains(q) ?? false)
        }
    }

    private static let timeFmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm"; return f
    }()
    private static let dateFmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "M月d日 EEEE"; f.locale = Locale(identifier: "zh_CN"); return f
    }()

    var body: some View {
        ZStack(alignment: .top) {
            Color.black.opacity(0.001)
                .ignoresSafeArea()
                .onTapGesture { withAnimation(.easeOut(duration: 0.2)) { onDismiss() } }

            VStack(spacing: 0) {
                // Grabber + search field (the Spotlight pillar).
                Capsule()
                    .fill(.white.opacity(0.5))
                    .frame(width: 36, height: 5)
                    .padding(.top, 8)

                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("搜索", text: $query)
                        .textFieldStyle(.plain)
                        .submitLabel(.search)
                }
                .padding(10)
                .background(.thinMaterial, in: Capsule())
                .padding(.horizontal, 16)
                .padding(.top, 8)

                ScrollView(showsIndicators: false) {
                    VStack(spacing: 14) {
                        if !query.isEmpty {
                            searchResults
                        } else {
                            notifications
                        }
                        widgetStack
                    }
                    .padding(.top, 12)
                    .padding(.bottom, 40)
                }
            }
            .frame(maxWidth: .infinity)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 0, style: .continuous))
            .offset(y: dragY)
            .gesture(
                DragGesture()
                    .onChanged { dragY = max(0, $0.translation.height) }
                    .onEnded { if $0.translation.height > 60 { withAnimation(.easeOut(duration: 0.2)) { onDismiss() } } else { dragY = 0 } }
            )
        }
        .ignoresSafeArea()
        .onReceive(Timer.publish(every: 10, on: .main, in: .common).autoconnect()) { now = $0 }
    }

    // MARK: Spotlight results

    private var searchResults: some View {
        VStack(alignment: .leading, spacing: 6) {
            if results.isEmpty {
                Text("无搜索结果")
                    .font(.system(size: 14))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 18)
            } else {
                ForEach(results) { item in
                    Button {
                        withAnimation(.easeOut(duration: 0.18)) { onOpen(item) }
                    } label: {
                        HStack(spacing: 12) {
                            IconArtwork(item: item, size: 40, folderMembers: [])
                                .frame(width: 40, height: 40)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.name).font(.system(size: 15, weight: .medium))
                                if let bid = item.bundleIdentifier {
                                    Text(bid).font(.system(size: 11)).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                        }
                        .padding(.horizontal, 18)
                        .padding(.vertical, 8)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    // MARK: Notifications

    private var notifications: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("今天")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 18)

            let badges = store.badges.filter { $0.value > 0 }
            if badges.isEmpty {
                systemNotice(title: "RyBox", body: "一切正常。从状态栏向下滑动可回到这里。")
            } else {
                ForEach(badges.keys.sorted(), id: \.self) { id in
                    if let item = store.resolve(id: id) {
                        notificationCard(item: item, count: badges[id] ?? 0)
                    }
                }
            }
        }
    }

    private func systemNotice(title: String, body: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "app.fill")
                .font(.system(size: 22))
                .foregroundStyle(Color(red: 0.30, green: 0.72, blue: 0.45))
                .frame(width: 38, height: 38)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 14, weight: .semibold))
                Text(body).font(.system(size: 13)).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(14)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .padding(.horizontal, 14)
    }

    private func notificationCard(item: DesktopItem, count: Int) -> some View {
        HStack(alignment: .top, spacing: 12) {
            IconArtwork(item: item, size: 38, folderMembers: [])
                .frame(width: 38, height: 38)
            VStack(alignment: .leading, spacing: 3) {
                Text(item.name).font(.system(size: 14, weight: .semibold))
                Text("\(count) 条新内容").font(.system(size: 13)).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(14)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .padding(.horizontal, 14)
    }

    // MARK: Widgets

    private var widgetStack: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("小组件")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 18)

            HStack(alignment: .top, spacing: 12) {
                clockWidget
                VStack(spacing: 12) {
                    batteryWidget
                    storageWidget
                }
            }
            .padding(.horizontal, 14)
        }
    }

    private var clockWidget: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(Self.timeFmt.string(from: now))
                .font(.system(size: 30, weight: .thin)).monospacedDigit()
            Text(Self.dateFmt.string(from: now))
                .font(.system(size: 12)).foregroundStyle(.secondary)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private var batteryWidget: some View {
        HStack {
            Image(systemName: "battery.100")
                .font(.system(size: 22))
            Text("电量").font(.system(size: 13))
            Spacer()
            Text("100%").font(.system(size: 13, weight: .semibold))
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private var storageWidget: some View {
        HStack {
            Image(systemName: "internaldrive")
                .font(.system(size: 22))
            Text("存储").font(.system(size: 13))
            Spacer()
            Text("可用").font(.system(size: 13, weight: .semibold))
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
