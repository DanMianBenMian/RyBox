import SwiftUI

/// Browses the virtual rooted filesystem ("/").
struct FilesystemView: View {
    @State private var items: [String] = []
    @State private var path = "/"

    var body: some View {
        NavigationView {
            List(items, id: \.self) { name in
                Text(name).font(.system(.callout, design: .monospaced))
            }
            .navigationTitle("文件 \(path)")
            .onAppear { reload() }
        }
    }

    private func reload() {
        let url = VirtualRoot.shared.url(for: path)
        items = (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
    }
}
