import SwiftUI

/// Sileo — launcher/installer stub for the REAL Sileo, which is preinstalled
/// inside RyBox's app bundle as `Preinstalled/Sileo.ipa` (official Sileo 2.5.1,
/// bundle id org.coolstar.SileoStore, repacked from the upstream .deb).
///
/// This view does NOT re-implement a package manager: it shows the honest
/// install status of the bundled IPA and launches the real Sileo in-process
/// (LiveContainer model) once installed. Install failures (e.g. no signing
/// certificate configured yet) are surfaced verbatim.
struct SileoView: View {
    @ObservedObject private var importer = AppImporter.shared
    @ObservedObject private var certs = CertificateStore.shared
    @ObservedObject private var preinstalled = PreinstalledStore.shared

    private var sileoApp: ImportedApp? {
        importer.importedApps.first { $0.bundleIdentifier == PreinstalledStore.sileoBundleID }
    }

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(LinearGradient(colors: [Color(red: 0.95, green: 0.30, blue: 0.47),
                                              Color(red: 0.85, green: 0.14, blue: 0.34)],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
                .frame(width: 92, height: 92)
                .overlay(
                    Image(systemName: "shippingbox.fill")
                        .font(.system(size: 40))
                        .foregroundStyle(.white)
                )
                .shadow(color: .black.opacity(0.25), radius: 10, y: 4)

            Text("Sileo")
                .font(.title2.bold())
            Text("Sileo 2.5.1 · org.coolstar.SileoStore")
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(.secondary)

            Group {
                switch preinstalled.state {
                case .idle:
                    Text("Sileo 已随 RyBox 内置，点击安装到桌面。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    Button("安装 Sileo") { preinstalled.installSileo() }
                        .buttonStyle(.borderedProminent)

                case .installing:
                    ProgressView()
                    Text(preinstalled.message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)

                case .installed:
                    Text("已安装。Sileo 将以 LiveContainer 模式在 RyBox 进程内运行，启动后用悬浮「主屏」键返回。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                    Button("启动 Sileo") { launch() }
                        .buttonStyle(.borderedProminent)

                case .failed:
                    Label(preinstalled.message, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                    Button("重试安装") { preinstalled.installSileo() }
                        .buttonStyle(.borderedProminent)
                }
            }
            .padding(.horizontal, 28)

            if !certs.isConfigured {
                Label("尚未配置签名证书：安装会停在签名步骤。请先到「设置」导入 p12 + 描述文件，然后回来重试。",
                      systemImage: "key")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Spacer()
        }
        .padding()
        .onAppear { preinstalled.bootstrapIfNeeded() }
    }

    private func launch() {
        guard let app = sileoApp else { return }
        GuestRuntime.launchInProcess(app)
    }
}
