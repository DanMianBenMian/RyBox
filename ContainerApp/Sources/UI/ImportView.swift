import SwiftUI
import UniformTypeIdentifiers

/// The "导入 App" entry point inside the environment.
///
/// Picker note: we accept `.item` (any file) instead of a custom
/// UTType(filenameExtension: "ipa") — the dynamic type makes the Files picker
/// show .ipa files as NON-selectable on some iOS builds (tap does nothing).
/// We validate the extension + zip magic ourselves after selection.
struct ImportView: View {
    @State private var showPicker = false
    @State private var status: String = "尚未导入"
    @State private var busy = false

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "square.and.arrow.down.on.square")
                .font(.system(size: 52))
                .foregroundColor(.accentColor)
            Text("导入 App")
                .font(.title2.bold())
            Text("从「文件」App 选择 .ipa，容器会解包、用你的分发证书现场签名，并注册到桌面。GUI App 走独立签名安装（LiveContainer 模型），CLI 工具在微内核内运行。")
                .font(.footnote)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button {
                showPicker = true
            } label: {
                if busy { ProgressView().padding(.horizontal) }
                else { Text("选择 IPA 导入").bold() }
            }
            .buttonStyle(.borderedProminent)
            .disabled(busy)

            if let last = AppImporter.shared.lastImported {
                Label("已导入：\(last.name)", systemImage: "checkmark.circle.fill")
                    .foregroundColor(.green)
            }

            Text(status)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            Spacer()
        }
        .padding()
        .navigationTitle("导入")
        .fileImporter(isPresented: $showPicker,
                      allowedContentTypes: [.item]) { result in
            switch result {
            case .success(let url):
                let ok = url.startAccessingSecurityScopedResource()
                defer { if ok { url.stopAccessingSecurityScopedResource() } }

                guard url.pathExtension.lowercased() == "ipa" else {
                    status = "请选择 .ipa 文件（当前：\(url.lastPathComponent)）"
                    return
                }
                // zip magic check — an IPA must be a zip archive.
                if let fh = try? FileHandle(forReadingFrom: url),
                   let magic = try? fh.read(upToCount: 2), magic != Data("PK".utf8) {
                    status = "文件不是有效的 IPA（缺少 zip 头）"
                    return
                }

                busy = true
                status = "导入中…"
                DispatchQueue.global(qos: .userInitiated).async {
                    let r = AppImporter.shared.importApp(from: url)
                    DispatchQueue.main.async {
                        busy = false
                        switch r {
                        case .success(let app):
                            status = "成功：\(app.name)（\(app.isGUI ? "GUI" : "CLI")），已添加到桌面"
                        case .failure(let e):
                            status = "失败：\(e.localizedDescription)"
                        }
                    }
                }
            case .failure(let e):
                status = "选择失败：\(e.localizedDescription)"
            }
        }
    }
}
