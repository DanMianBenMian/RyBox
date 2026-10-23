import SwiftUI

/// dpkg-like package manager (minimal). Lists installed guest apps/packages.
struct PackageManagerView: View {
    @State private var apps: [ImportedApp] = []
    @State private var log = "包管理器就绪。"

    var body: some View {
        NavigationView {
            VStack {
                List(apps) { app in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(app.name).bold()
                            Text(app.bundleIdentifier).font(.caption).foregroundColor(.secondary)
                        }
                        Spacer()
                        Button("卸载") { uninstall(app) }.buttonStyle(.bordered)
                    }
                }
                Text(log).font(.caption).foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(8)
            }
            .navigationTitle("包管理")
            .onAppear { apps = AppImporter.shared.importedApps }
        }
    }

    private func uninstall(_ app: ImportedApp) {
        try? FileManager.default.removeItem(atPath: app.containerPath)
        log = "已卸载：\(app.name)"
        apps = AppImporter.shared.importedApps
    }
}
