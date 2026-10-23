import SwiftUI
import UniformTypeIdentifiers

/// The "导入 App" entry point inside the environment.
///
/// Picker note: we present a UIKit UIDocumentPickerViewController directly
/// (DocPicker) with `.item` content types — the SwiftUI `.fileImporter`
/// modifier opened the picker but never delivered selections on iPadOS 27
/// beta, and a custom UTType(filenameExtension: "ipa") filter made .ipa files
/// non-selectable in the Files app. We validate the extension + zip magic
/// ourselves after selection.
struct ImportView: View {
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
                pick()
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
    }

    private func pick() {
        status = "正在打开文件选择器…"
        DocPicker.present { result in
            switch result {
            case .success(let url):
                status = "已选择：\(url.lastPathComponent)"
                handlePicked(url)
            case .failure(let e):
                status = "选择失败：\(e.localizedDescription)"
            }
        }
    }

    private func handlePicked(_ url: URL) {
        guard url.pathExtension.lowercased() == "ipa" else {
            status = "请选择 .ipa 文件（当前：\(url.lastPathComponent)）"
            return
        }
        // asCopy gives a local tmp URL — copy to a stable path before importing.
        let dst = FileManager.default.temporaryDirectory
            .appendingPathComponent("import-\(UUID().uuidString).ipa")
        do {
            let data = try Data(contentsOf: url)
            if data.count < 4 || data.prefix(2) != Data("PK".utf8) {
                status = "文件不是有效的 IPA（缺少 zip 头）"
                return
            }
            try data.write(to: dst)
        } catch {
            status = "读取文件失败：\(error.localizedDescription)"
            return
        }

        busy = true
        status = "导入中…"
        DispatchQueue.global(qos: .userInitiated).async {
            let r = AppImporter.shared.importApp(from: dst)
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
    }
}
