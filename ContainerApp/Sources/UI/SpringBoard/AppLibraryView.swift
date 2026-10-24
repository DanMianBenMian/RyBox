import SwiftUI

/// App Library — the page after the last home screen page.
///
/// Everything installed lives here whether or not it is on a home screen page,
/// grouped into buckets with a search field on top, like iOS 14+.
struct AppLibraryView: View {
    @ObservedObject private var store = DesktopStore.shared
    @ObservedObject private var theme = ThemeEngine.shared

    var onOpen: (DesktopItem) -> Void
    var onSearchCommit: (String) -> Void = { _ in }

    @State private var query = ""
    @FocusState private var searchFocused: Bool

    private var buckets: [LibraryBucket] {
        store.libraryBuckets()
    }

    private var isSearching: Bool { !query.trimmingCharacters(in: .whitespaces).isEmpty }

    var body: some View {
        VStack(spacing: 0) {
            searchField
                .padding(.horizontal, 18)
                .padding(.top, 6)
                .padding(.bottom, 10)

            ScrollView(.vertical, showsIndicators: false) {
                VStack(alignment: .leading, spacing: 22) {
                    if isSearching {
                        searchResults
                    } else if buckets.isEmpty {
                        // A genuinely empty library must never look like a
                        // rendering failure — say so, and say what to do.
                        emptyState
                    } else {
                        ForEach(buckets) { bucket in
                            bucketSection(bucket)
                        }
                    }
                }
                .padding(.horizontal, 18)
                .padding(.bottom, 110)
            }
            .contentShape(Rectangle())
            // Tapping the background dismisses the keyboard, like iOS.
            .onTapGesture { searchFocused = false }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "square.grid.2x2")
                .font(.system(size: 34, weight: .light))
            Text("资源库是空的")
                .font(.system(size: 15, weight: .semibold))
            Text("导入的 App 会出现在这里，也会自动放到主屏。")
                .font(.system(size: 12.5))
                .multilineTextAlignment(.center)
        }
        .foregroundStyle(.white.opacity(0.62))
        .frame(maxWidth: .infinity)
        .padding(.top, 70)
    }

    // MARK: Search

    private var searchField: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 13, weight: .semibold))
            TextField("搜索", text: $query)
                .font(.system(size: 15))
                .focused($searchFocused)
                .submitLabel(.search)
                .onSubmit { onSearchCommit(query) }
            if !query.isEmpty {
                Button { query = "" } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 13))
                }
                .buttonStyle(.plain)
            }
        }
        .foregroundStyle(.white.opacity(0.92))
        .padding(.horizontal, 11)
        .padding(.vertical, 8)
        .background(.ultraThinMaterial, in: Capsule())
    }

    private var matches: [DesktopItem] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return store.allItems.filter {
            $0.name.lowercased().contains(q)
            || ($0.bundleIdentifier ?? "").lowercased().contains(q)
        }
    }

    private var searchResults: some View {
        Group {
            if matches.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 30))
                    Text("没有找到「\(query)」")
                        .font(.system(size: 14, weight: .medium))
                }
                .foregroundStyle(.white.opacity(0.6))
                .frame(maxWidth: .infinity)
                .padding(.top, 60)
            } else {
                iconGrid(matches, columns: 4)
            }
        }
    }

    // MARK: Buckets

    private func bucketSection(_ bucket: LibraryBucket) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: bucket.category.symbol)
                    .font(.system(size: 12, weight: .semibold))
                Text(bucket.category.title)
                    .font(.system(size: 14, weight: .semibold))
            }
            .foregroundStyle(.white.opacity(0.92))

            // Three-wide tiles: the first is a large "folder" that opens the
            // first app, the rest are plain icons — same as iOS.
            iconGrid(bucket.items, columns: 4)
        }
    }

    private func iconGrid(_ items: [DesktopItem], columns: Int) -> some View {
        let grid = Array(repeating: GridItem(.flexible(), spacing: 14), count: columns)
        return LazyVGrid(columns: grid, spacing: 18) {
            ForEach(items) { item in
                LibraryTile(item: item) { onOpen(item) }
            }
        }
    }
}

private struct LibraryTile: View {
    let item: DesktopItem
    var onTap: () -> Void

    @ObservedObject private var theme = ThemeEngine.shared

    var body: some View {
        let badge = DesktopStore.shared.badge(for: item.id)
        return Button(action: onTap) {
            VStack(spacing: 6) {
                ZStack(alignment: .topTrailing) {
                    IconArtwork(item: item, size: 58, cornerRadius: 13)
                    if badge > 0 {
                        BadgeView(count: badge)
                            .offset(x: 6, y: -6)
                    }
                }
                Text(item.name)
                    .font(.system(size: 11))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
            }
        }
        .buttonStyle(.plain)
    }
}

/// Icon artwork used by both the home screen and the library: themed image if a
/// theme provides one, otherwise the app's own PNG, otherwise the generated
/// squircle. Centralising this is what makes theme icons apply everywhere.
struct IconArtwork: View {
    let item: DesktopItem
    let size: CGFloat
    var cornerRadius: CGFloat?
    var folderMembers: [DesktopItem] = []

    @ObservedObject private var theme = ThemeEngine.shared

    private var radius: CGFloat { cornerRadius ?? size * 0.225 }

    var body: some View {
        Group {
            if let image = themedOrOwnImage {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(width: size, height: size)
                    .clipShape(RoundedRectangle(cornerRadius: radius, style: .continuous))
            } else if case .folder = item.kind {
                folderArtwork
            } else {
                generatedArtwork
            }
        }
        .frame(width: size, height: size)
        .shadow(color: .black.opacity(0.24), radius: 5, y: 3)
    }

    /// The real artwork for an item: theme icon first, then the app's own PNG.
    /// Exposed so the FOLDER THUMBNAIL can show the members' real icons — the
    /// folder preview used to fall back to flat colour squares with an SF Symbol
    /// even when the member app had a perfectly good icon.
    static func artworkImage(for item: DesktopItem,
                             theme: ThemeEngine = .shared) -> UIImage? {
        if let bid = item.bundleIdentifier, let themed = theme.icon(forBundleID: bid) {
            return themed
        }
        if case .folder(let f) = item.kind, let themed = theme.icon(forBundleID: f.id) {
            return themed
        }
        if case .guest(let app) = item.kind, let path = app.iconPath {
            return UIImage(contentsOfFile: path)
        }
        return nil
    }

    private var themedOrOwnImage: UIImage? {
        IconArtwork.artworkImage(for: item, theme: theme)
    }

    private var folderArtwork: some View {
        let previews = Array(folderMembers.prefix(4))
        return RoundedRectangle(cornerRadius: radius, style: .continuous)
            // A dark frosted plate: the folder name is drawn in white on top of
            // it, so the plate must stay dark or the text is unreadable.
            .fill(.ultraThinMaterial)
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .fill(Color.black.opacity(0.34))
            )
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .strokeBorder(.white.opacity(0.25), lineWidth: 0.5)
            )
            .overlay(
                VStack(spacing: size * 0.045) {
                    ForEach(0..<2, id: \.self) { row in
                        HStack(spacing: size * 0.045) {
                            ForEach(0..<2, id: \.self) { col in
                                let idx = row * 2 + col
                                memberThumb(idx, previews: previews)
                            }
                        }
                    }
                }
            )
    }

    /// One member thumbnail inside the folder: the member's REAL icon when it
    /// has one (theme icon or the app's own PNG), otherwise the tinted
    /// placeholder square.
    @ViewBuilder
    private func memberThumb(_ idx: Int, previews: [DesktopItem]) -> some View {
        let member = previews.indices.contains(idx) ? previews[idx] : nil
        let real = member.flatMap { IconArtwork.artworkImage(for: $0, theme: theme) }
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.08, style: .continuous)
                .fill(member?.tint ?? Color.white.opacity(0.18))
                .frame(width: size * 0.32, height: size * 0.32)
            if let real = real {
                // The member's own icon, clipped to the squircle shape.
                Image(uiImage: real)
                    .resizable()
                    .scaledToFill()
                    .frame(width: size * 0.32, height: size * 0.32)
                    .clipShape(RoundedRectangle(cornerRadius: size * 0.08, style: .continuous))
            } else if let member = member {
                Image(systemName: member.symbol)
                    .font(.system(size: size * 0.13))
                    .foregroundStyle(.white)
            }
        }
    }

    private var generatedArtwork: some View {
        RoundedRectangle(cornerRadius: radius, style: .continuous)
            .fill(LinearGradient(colors: [item.tint.opacity(0.92), item.tint],
                                 startPoint: .topLeading, endPoint: .bottomTrailing))
            .overlay(
                Image(systemName: item.symbol)
                    .font(.system(size: size * 0.44, weight: .medium))
                    .foregroundStyle(.white)
            )
    }
}

/// Red notification badge.
struct BadgeView: View {
    let count: Int

    var body: some View {
        ZStack {
            Capsule().fill(Color(red: 0.94, green: 0.24, blue: 0.28))
            Text(count > 99 ? "99+" : "\(count)")
                .font(.system(size: 11, weight: .bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 5)
        }
        .frame(height: 18)
        .fixedSize(horizontal: true, vertical: false)
        .shadow(color: .black.opacity(0.3), radius: 3, y: 1)
    }
}
