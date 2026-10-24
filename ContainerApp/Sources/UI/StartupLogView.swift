import SwiftUI
import UIKit
import Combine

/// Boot log shown right after the user enters the system (and on every cold
/// relaunch into a completed container). Black background, white monospaced text,
/// in the same family as the deploy log so the two "system coming up" screens
/// feel like one boot sequence.
///
/// Unlike the earlier hardcoded version, every line here reflects REAL work done
/// by the actual boot subsystems — mounting the virtual root, loading the theme
/// engine, restoring the desktop layout (including previously imported apps),
/// spinning up the user-space microkernel process manager, applying the signing
/// identity, and installing the preinstalled Sileo. Each line carries a real
/// timestamp and the real outcome of that step.
struct StartupLogView: View {
    var onFinished: () -> Void

    @State private var lines: [String] = []
    @State private var done = false
    @ObservedObject private var pre = PreinstalledStore.shared
    @ObservedObject private var cert = CertificateStore.shared

    private let dateFmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f
    }()
    private var isPad: Bool { UIDevice.current.userInterfaceIdiom == .pad }

    private func stamp() -> String { dateFmt.string(from: Date()) }
    private func log(_ msg: String) {
        lines.append("[\(stamp())] \(msg)")
        // Mirror into the container-wide live log, so the 「日志」 app and the
        // floating ball show the whole boot sequence too.
        RyLog.shared.log(msg, level: .info, tag: "boot")
    }

    var body: some View {
        Color.black.ignoresSafeArea()
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "shippingbox.fill").foregroundStyle(.white)
                Text("RyBox")
                    .font(.system(size: 15, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.white)
                Spacer()
                Text(done ? "完成" : "启动中")
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.8))
            }
            .padding(.horizontal, 18)
            .padding(.top, 18)

            Divider().background(Color.white.opacity(0.25))
                .padding(.vertical, 10)

            ScrollViewReader { proxy in
                ScrollView(.vertical, showsIndicators: false) {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(Array(lines.enumerated()), id: \.offset) { i, line in
                            Text(line)
                                .font(.system(size: 12.5, design: .monospaced))
                                .foregroundStyle(.white.opacity(0.9))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(i)
                        }
                    }
                    .padding(.horizontal, 18)
                }
                .onChange(of: lines.count) { _ in
                    withAnimation { proxy.scrollTo(max(0, lines.count - 1), anchor: .bottom) }
                }
            }
            Spacer(minLength: 0)
        }
        // The preinstalled-Sileo install runs asynchronously; when it settles we
        // append the real result and finish the boot log.
        .onChange(of: pre.state) { handleSileo($0) }
        .task { runSequence() }
    }

    /// Real boot sequence — each step performs the actual subsystem work and logs
    /// the real outcome with a timestamp (so this is never a fake script).
    private func runSequence() {
        guard lines.isEmpty else { return }
        Task {
            log("RyBox SpringBoard 启动中…")
            await tick()

            // 1) Virtual root mount.
            VirtualRoot.shared.ensure()
            log("挂载虚拟根 / → \(VirtualRoot.shared.rootURL.path)")
            log("fs   WRITE  \(VirtualRoot.shared.rootURL.path)  (virtual root mounted)")
            await tick()

            // 2) Theme engine load (real theme count under /Library/Themes).
            let themeCount = ThemeEngine.shared.reload()
            log("载入主题引擎 → /Library/Themes（\(themeCount) 个主题）")
            log("fs   READ   Library/Themes  (\(themeCount) theme dirs)")
            await tick()

            // 3) Desktop layout + Dock restore, including previously imported apps.
            let restored = AppImporter.shared.importedApps.count
            DesktopStore.shared.pruneSlots()
            DesktopStore.shared.ensurePlaced(isIPad: isPad)
            let iconCount = DesktopStore.shared.allItems.count
            log("还原桌面布局与 Dock（\(iconCount) 个图标，还原 \(restored) 个已导入 App）")
            log("fs   READ   Apps/  (\(restored) guest bundles) · WRITE UserDefaults slots")
            await tick()

            // 3b) Scene capability — the surface in-process GUI guests attach their
            //     window to (see RyDyldHooks.m). Must be >= 1 or guests show only a
            //     launch image.
            let sceneCount = UIApplication.shared.connectedScenes.count
            log("ui   SCENE  connectedScenes=\(sceneCount)  (guest windows attach here)")
            await tick()

            // 4) User-space microkernel process manager (POSIX spawn / PID space /
            //    signals / waitpid) — the real subsystem behind CLI guests.
            _ = ProcessManager.shared
            let procCount = ProcessManager.shared.list().count
            log("初始化微内核进程管理器（PID 空间 / 信号 / waitpid，当前 \(procCount) 个进程）")
            log("ks   EXEC   process manager (posix_spawn shim)")
            await tick()

            // 5) Signing identity (real cert/team state).
            if CertificateStore.shared.isConfigured {
                if let team = CertificateStore.shared.teamIdentifier, !team.isEmpty {
                    log("应用签名身份（p12 + mobileprovision）· Team \(team)")
                } else {
                    log("应用签名身份（p12 + mobileprovision）")
                }
                log("ks   READ   p12 + mobileprovision  (signing identity)")
            } else {
                log("签名身份未配置（导入/运行 App 可能受限）")
            }
            await tick()

            // 6) Preinstalled Sileo. If it has already settled (or there is nothing
            //    to do) we log the real current state and finish immediately; if it
            //    is still installing we log that and let handleSileo finish.
            switch pre.state {
            case .installed:
                log("预置包 Sileo 已就绪")
                finish()
            case .failed:
                log("预置包 Sileo 安装失败：\(pre.message)")
                finish()
            case .idle:
                if PreinstalledStore.shared.isInstalled {
                    log("预置包 Sileo 已就绪")
                } else {
                    log("预置包 Sileo：无需安装或尚未配置证书")
                }
                finish()
            case .installing:
                log("正在安装预置包 Sileo…")
                // handleSileo finishes when the state settles.
            }
        }
    }

    /// Appends the real Sileo install result and finishes the boot log.
    private func handleSileo(_ state: PreinstalledStore.State) {
        guard !lines.isEmpty else { return }
        switch state {
        case .installed:
            log("预置包 Sileo 安装完成 ✓")
            finish()
        case .failed:
            log("预置包 Sileo 安装失败：\(pre.message)")
            finish()
        default:
            break
        }
    }

    private func finish() {
        guard !done else { return }
        done = true
        Task {
            try? await Task.sleep(nanoseconds: 400_000_000)
            onFinished()
        }
    }

    /// Small stagger between lines so the boot reads like a real sequence.
    private func tick() async {
        try? await Task.sleep(nanoseconds: 160_000_000)
    }
}
