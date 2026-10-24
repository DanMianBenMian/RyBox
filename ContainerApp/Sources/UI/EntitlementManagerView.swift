import SwiftUI

/// 特殊权限分配 — the "特殊权限分配" half of the entitlement policy.
///
/// When a guest IPA is imported, its ORIGINAL entitlements are recorded and the
/// privileged ones (`platform-application`, `com.apple.private.*`,
/// `task_for_pid-allow`, …) are MARKED as taken over by RyBox: they are stripped
/// from the guest's re-signed binary (an in-process guest gets its runtime
/// entitlements from the HOST process anyway) and re-granted here, one switch
/// per key, per app.
///
/// A switch that is OFF withholds the key: the guest's
/// `SecTaskCopyValueForEntitlement` query then answers "not entitled", which is
/// how the user allocates special permissions instead of the signature
/// pretending to carry them.
struct EntitlementManagerView: View {
    @ObservedObject private var policy = EntitlementPolicy.shared
    @ObservedObject private var importer = AppImporter.shared

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Label("签名里不放特殊权限", systemImage: "signature")
                        .font(.subheadline.weight(.medium))
                    Text("RyBox 里的 App 以 in-process 方式运行（dlopen 进宿主进程），运行时的权限查询由 RyBox 自己回答——所以签名时特殊权限会被剥掉，改由这里按 App 分配。关掉某个开关，该 App 查询这个权限时会得到「未授权」。")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, 4)
            }

            if appIDs.isEmpty {
                Section {
                    Text("还没有导入任何 App。导入后，这里会列出它原本声明的特殊权限。")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }

            ForEach(appIDs, id: \.self) { bid in
                appSection(bundleID: bid)
            }
        }
        .navigationTitle("特殊权限分配")
        .navigationBarTitleDisplayMode(.inline)
    }

    /// Every app whose original entitlements we recorded, sorted by display name.
    private var appIDs: [String] {
        policy.original.keys.sorted { a, b in
            name(for: a).localizedCaseInsensitiveCompare(name(for: b)) == .orderedAscending
        }
    }

    @ViewBuilder
    private func appSection(bundleID: String) -> some View {
        let keys = policy.takenOverKeys(bundleID: bundleID)
        Section {
            if keys.isEmpty {
                Text("未声明特殊权限")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            } else {
                ForEach(keys, id: \.self) { key in
                    Toggle(isOn: Binding(
                        get: { policy.isGranted(bundleID: bundleID, key: key) },
                        set: { policy.setGrant(bundleID: bundleID, key: key, allowed: $0) }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(key)
                                .font(.system(.footnote, design: .monospaced))
                                .lineLimit(2)
                                .fixedSize(horizontal: false, vertical: true)
                            if let value = policy.original[bundleID]?[key] {
                                Text(EntitlementPolicy.plistString(value))
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                    .lineLimit(1)
                            }
                        }
                    }
                }
                Button {
                    policy.grantAll(bundleID: bundleID)
                } label: {
                    Label("全部开启", systemImage: "checkmark.circle")
                }
            }
        } header: {
            HStack {
                Text(name(for: bundleID))
                Spacer()
                if !keys.isEmpty {
                    let on = keys.filter { policy.isGranted(bundleID: bundleID, key: $0) }.count
                    Text("\(on)/\(keys.count) 已分配")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        } footer: {
            Text(bundleID)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }

    private func name(for bundleID: String) -> String {
        importer.importedApps.first { $0.bundleIdentifier == bundleID }?.name ?? bundleID
    }
}
