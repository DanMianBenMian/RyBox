import Foundation

/// Installs apps bundled INSIDE the RyBox .app (`Preinstalled/*.ipa`) on first
/// launch. Sileo ships this way — the REAL Sileo (official 2.5.1 IPA repacked
/// from the upstream .deb), not a re-implementation.
///
/// Installation goes through the exact same pipeline as a manual import
/// (unzip → classify → sign with the user's cert → register on the desktop),
/// so its status is always honest: if the signing step can't run yet, the
/// Sileo launcher stub says so instead of pretending.
final class PreinstalledStore: ObservableObject {
    static let shared = PreinstalledStore()

    /// Bundle id of the real Sileo (org.coolstar.SileoStore, v2.5.1).
    static let sileoBundleID = "org.coolstar.SileoStore"
    static let sileoIPAName = "Sileo.ipa"

    enum State {
        case idle, installing, installed, failed
    }

    @Published var state: State = .idle
    @Published var message: String = ""

    private var bootstrapped = false

    private init() {}

    var isInstalled: Bool {
        AppImporter.shared.importedApps.contains { $0.bundleIdentifier == Self.sileoBundleID }
    }

    private var bundledIPA: URL? {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Preinstalled/\(Self.sileoIPAName)")
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    /// Called on launch / view appear. Idempotent: installs once, and
    /// auto-retries a previous failure (e.g. the user just configured a cert
    /// in Settings and came back).
    func bootstrapIfNeeded() {
        if isInstalled {
            state = .installed
            return
        }
        if state == .failed {
            installSileo()
            return
        }
        guard !bootstrapped else { return }
        bootstrapped = true
        installSileo()
    }

    /// (Re)attempt the preinstalled Sileo install.
    func installSileo() {
        guard !isInstalled else {
            state = .installed
            return
        }
        guard state != .installing else { return }   // no double imports
        guard let ipa = bundledIPA else {
            state = .failed
            message = "未找到内置 Sileo.ipa（RyBox.app/Preinstalled/）"
            return
        }
        state = .installing
        message = "正在安装 Sileo…"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = AppImporter.shared.importApp(from: ipa)
            DispatchQueue.main.async {
                switch result {
                case .success:
                    self.state = .installed
                    self.message = "Sileo 已安装"
                case .failure(let e):
                    self.state = .failed
                    self.message = "安装失败：\(e.localizedDescription)"
                }
            }
        }
    }
}
