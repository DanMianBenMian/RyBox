import SwiftUI

/// iOS-style App Switcher, recreated inside the RyBox shell.
///
/// Triggered by a long-press on the virtual Home key. Shows a horizontal deck of
/// "app cards" for everything in the recents list (most recent first) plus a
/// "主屏幕" card at the end. Tapping a card opens that app; swiping a card up
/// quits it (drops it from the recents deck). A tap on the dimming backdrop
/// dismisses the panel.
struct AppSwitcherView: View {
    var recents: [String]
    var onOpen: (DesktopItem) -> Void
    var onQuit: (String) -> Void
    var onDismiss: () -> Void

    @State private var dragID: String?
    @State private var dragY: CGFloat = 0

    private var items: [(id: String, item: DesktopItem)] {
        recents.compactMap { id in
            guard let it = DesktopStore.shared.resolve(id: id) else { return nil }
            return (id, it)
        }
    }

    private let cardW: CGFloat = min(UIScreen.main.bounds.width, 720) * 0.62
    private var cardH: CGFloat { cardW * 1.32 }

    var body: some View {
        ZStack {
            Color.black.opacity(0.001)
                .ignoresSafeArea()
                .onTapGesture { withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) { onDismiss() } }

            VStack(spacing: 0) {
                Spacer()
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 18) {
                        ForEach(items, id: \.id) { pair in
                            appCard(pair.id, pair.item)
                        }
                        homeCard
                    }
                    .padding(.horizontal, 28)
                }
                .frame(maxHeight: cardH + 40)
                Spacer()
            }
        }
        .ignoresSafeArea()
    }

    private func appCard(_ id: String, _ item: DesktopItem) -> some View {
        let isDragging = dragID == id
        return VStack(spacing: 0) {
            ZStack {
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .fill(item.tint.opacity(0.35))
                    .overlay(
                        RoundedRectangle(cornerRadius: 22, style: .continuous)
                            .strokeBorder(.white.opacity(0.25), lineWidth: 1)
                    )
                VStack(spacing: 14) {
                    IconArtwork(item: item, size: 76, folderMembers: [])
                        .frame(width: 76, height: 76)
                    Text(item.name)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(.white)
                        .lineLimit(1)
                }
            }
            .frame(width: cardW, height: cardH)
        }
        .scaleEffect(isDragging ? 1.0 : 1.0)
        .offset(y: isDragging ? dragY : 0)
        .opacity(isDragging && dragY < -40 ? 0.4 : 1.0)
        .shadow(color: .black.opacity(0.4), radius: 18, y: 8)
        .animation(.easeOut(duration: 0.18), value: dragY)
        .contentShape(Rectangle())
        .onTapGesture {
            withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) { onOpen(item) }
        }
        .gesture(
            DragGesture(minimumDistance: 8)
                .onChanged { v in
                    dragID = id
                    dragY = v.translation.height
                }
                .onEnded { v in
                    if v.translation.height < -80 {
                        withAnimation(.easeOut(duration: 0.22)) { onQuit(id) }
                    }
                    dragID = nil
                    dragY = 0
                }
        )
    }

    private var homeCard: some View {
        VStack(spacing: 0) {
            ZStack {
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        RoundedRectangle(cornerRadius: 22, style: .continuous)
                            .strokeBorder(.white.opacity(0.25), lineWidth: 1)
                    )
                VStack(spacing: 12) {
                    Image(systemName: "house.fill")
                        .font(.system(size: 46, weight: .regular))
                        .foregroundStyle(.white)
                    Text("主屏幕")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(.white)
                }
            }
            .frame(width: cardW, height: cardH)
        }
        .shadow(color: .black.opacity(0.4), radius: 18, y: 8)
        .onTapGesture {
            withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) { onDismiss() }
        }
    }
}
