import SwiftUI

/// One entry in the virtual rooted filesystem.
struct FSEntry: Identifiable, Hashable, Codable {
    var id: String { path }
    let name: String
    let path: String          // virtual absolute path, e.g. "/bin"
    let isDirectory: Bool
    let size: Int64
    let modified: Date?
}

/// Browses the virtual rooted filesystem ("/") with real directory navigation
/// (NavigationStack push/pop), directory-first ordering, and a text preview
/// sheet for small files.
///
/// Presented inside FullScreenAppView's NavigationStack — do NOT wrap this in
/// another NavigationStack (nested stacks double the nav bar).
struct FilesystemView: View {
    var body: some View {
        FileBrowserView(path: "/")
    }
}

struct FileBrowserView: View {
    let path: String
    @State private var entries: [FSEntry] = []
    @State private var preview: FSEntry?

    private let keys: Set<URLResourceKey> = [
        .isDirectoryKey, .fileSizeKey, .contentModificationDateKey, .isSymbolicLinkKey
    ]

    var body: some View {
        List {
            ForEach(entries) { e in
                if e.isDirectory {
                    NavigationLink(value: e) { row(e) }
                } else {
                    Button { preview = e } label: { row(e) }
                        .buttonStyle(.plain)
                }
            }
        }
        .navigationDestination(for: FSEntry.self) { e in
            FileBrowserView(path: e.path)
        }
        .navigationTitle(path == "/" ? "文件" : (path as NSString).lastPathComponent)
        .navigationBarTitleDisplayMode(.inline)
        .overlay {
            if entries.isEmpty {
                ContentUnavailableView("空目录",
                                       systemImage: "folder",
                                       description: Text("这个目录里还没有内容"))
            }
        }
        .onAppear { reload() }
        .sheet(item: $preview) { e in
            FilePreviewSheet(entry: e)
        }
    }

    private func row(_ e: FSEntry) -> some View {
        HStack(spacing: 12) {
            Image(systemName: e.isDirectory ? "folder.fill" : "doc")
                .foregroundStyle(e.isDirectory ? Color.blue : Color.secondary)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(e.name)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                if !e.isDirectory {
                    Text("\(ByteCountFormatter.string(fromByteCount: e.size, countStyle: .file))")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            if e.isDirectory {
                Image(systemName: "chevron.right")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 2)
    }

    private func reload() {
        let url = VirtualRoot.shared.url(for: path)
        let items = (try? FileManager.default.contentsOfDirectory(
            at: url, includingPropertiesForKeys: Array(keys))) ?? []
        entries = items.compactMap { u in
            let r = try? u.resourceValues(forKeys: keys)
            let vpath = path == "/" ? "/\(u.lastPathComponent)" : "\(path)/\(u.lastPathComponent)"
            return FSEntry(name: u.lastPathComponent,
                           path: vpath,
                           isDirectory: r?.isDirectory ?? false,
                           size: Int64(r?.fileSize ?? 0),
                           modified: r?.contentModificationDate)
        }
        .sorted { a, b in
            if a.isDirectory != b.isDirectory { return a.isDirectory }
            return a.name.localizedStandardCompare(b.name) == .orderedAscending
        }
    }
}

/// Text preview sheet for small files (<= 256 KB).
struct FilePreviewSheet: View {
    let entry: FSEntry
    @Environment(\.dismiss) private var dismiss
    @State private var text: String = "读取中…"

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(text)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .textSelection(.enabled)
            }
            .navigationTitle(entry.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("完成") { dismiss() }
                }
            }
        }
        .onAppear(perform: load)
    }

    private func load() {
        let url = VirtualRoot.shared.url(for: entry.path)
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            text = "无法读取文件。"; return
        }
        if data.count > 256 * 1024 {
            text = "文件过大（\(ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file))），仅预览 <= 256 KB 的文本。"
            return
        }
        if let s = String(data: data, encoding: .utf8) {
            text = s
        } else {
            text = "二进制文件（\(ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file))）"
        }
    }
}
