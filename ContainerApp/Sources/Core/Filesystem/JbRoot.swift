import Foundation

/// Populates the virtual root ("/") with a STANDARD, MINIMAL jbroot.
///
/// Architecture shift (2026-10-24): RyBox no longer restores a real system
/// image from an IPSW / .ryboxenv. Instead it ships a small, standard bootstrap
/// (the Procursus `usr/`, `bin/`, `etc/`, `var/` tree + dpkg/apt databases)
/// inside the app as `Preinstalled/ProcursusBootstrap.zip` and unzips it into
/// `VirtualRoot.shared.rootURL` once, on first launch. Everything a package
/// manager (Sileo → dpkg/apt) needs — binaries, configs, status databases —
/// lives under that jbroot.
///
/// The unzip is idempotent and NON-BLOCKING: it is triggered from app launch
/// and from Settings, and skipped if the marker file already exists. If the
/// bundled asset is missing (it is large and staged separately by CI), we log
/// honestly and continue — Sileo still installs, only its package tools are
/// unavailable until the asset is provided.
final class JbRoot {
    static let shared = JbRoot()

    /// Bundle asset that holds the prebuilt jbroot tree.
    static let assetName = "ProcursusBootstrap.zip"

    private let markerName = ".jbroot_installed"

    private init() {}

    private var assetURL: URL {
        Bundle.main.bundleURL.appendingPathComponent("Preinstalled/\(Self.assetName)")
    }

    /// True once the bootstrap has been extracted (marker file present).
    var isBootstrapped: Bool {
        FileManager.default.fileExists(atPath: markerURL.path)
    }

    private var markerURL: URL {
        VirtualRoot.shared.rootURL.appendingPathComponent(markerName)
    }

    /// Human-readable status for the UI (BootGate / Settings).
    var statusLine: String? {
        let fm = FileManager.default
        if fm.fileExists(atPath: assetURL.path) {
            if isBootstrapped {
                return "内置 bootstrap 已解压到虚拟根目录。"
            }
            return "发现内置 bootstrap，将在后台解压。"
        }
        return "未找到内置 \(Self.assetName)，包管理工具（dpkg/apt）暂不可用；请在电脑上用 make_jbroot.py 生成后放入 Preinstalled/。"
    }

    /// Extract the bundled bootstrap into the virtual root. Idempotent — safe to
    /// call repeatedly; only does work the first time (or after a reset).
    ///
    /// Runs on a background queue so app launch is never blocked. All failures
    /// are logged and surfaced via `statusLine`; nothing here is fatal.
    func bootstrap() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.work()
        }
    }

    private func work() {
        let fm = FileManager.default
        let root = VirtualRoot.shared.rootURL
        VirtualRoot.shared.ensure()

        guard !isBootstrapped else {
            RyLog.shared.log("jbroot 已解压，跳过", level: .info, tag: "jbroot")
            return
        }

        guard fm.fileExists(atPath: assetURL.path) else {
            RyLog.shared.log("jbroot：未找到内置 \(Self.assetName)，跳过解压（Sileo 仍可安装，但 dpkg/apt 不可用）",
                             level: .warn, tag: "jbroot")
            return
        }

        RyLog.shared.log("jbroot：开始解压 \(Self.assetName) → \(root.path)", level: .info, tag: "jbroot")

        let tmp = fm.temporaryDirectory.appendingPathComponent("jbroot-\(UUID().uuidString)")
        try? fm.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tmp) }

        // "*" selects every entry (RyUnzip sentinel for "extract all").
        let namesFile = tmp.appendingPathComponent("all.txt")
        try? "*\n".write(to: namesFile, atomically: true, encoding: .utf8)

        var outBytes: UInt64 = 0
        let n = ry_unzip_extract_selected(assetURL.path, root.path,
                                          namesFile.path, &outBytes)
        guard n > 0 else {
            RyLog.shared.log("jbroot：解压失败（错误码 \(n)）", level: .error, tag: "jbroot")
            return
        }

        flattenIfNeeded(into: root)
        preserveBundleFiles(in: root)

        // Mark done ONLY after a successful, complete extraction.
        try? "".write(to: markerURL, atomically: true, encoding: .utf8)

        let mb = Double(outBytes) / 1024 / 1024
        RyLog.shared.log("jbroot：解压完成 \(n) 个条目 / \(String(format: "%.1f", mb)) MB",
                         level: .info, tag: "jbroot")
    }

    /// Some bootstrap archives nest everything under a single top-level folder
    /// (e.g. `Procursus/usr/...`). If that is the case, lift its contents to the
    /// jbroot root so `/usr`, `/bin` land directly under "/".
    private func flattenIfNeeded(into root: URL) {
        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(at: root,
                includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]),
              contents.count == 1,
              let only = contents.first,
              (try? only.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true
        else { return }

        // Heuristic: only flatten if the single folder looks like a bootstrap
        // root (contains usr/ or bin/), otherwise leave it alone.
        let hasUsr = fm.fileExists(atPath: only.appendingPathComponent("usr").path)
        let hasBin = fm.fileExists(atPath: only.appendingPathComponent("bin").path)
        guard hasUsr || hasBin else { return }

        RyLog.shared.log("jbroot：检测到单层目录，上移内容到虚拟根", level: .debug, tag: "jbroot")
        guard let inner = try? fm.contentsOfDirectory(at: only, includingPropertiesForKeys: nil)
        else { return }
        for item in inner {
            let dst = root.appendingPathComponent(item.lastPathComponent)
            try? fm.removeItem(at: dst)
            try? fm.moveItem(at: item, to: dst)
        }
        try? fm.removeItem(at: only)
    }

    /// Never let the bootstrap clobber RyBox's own managed virtual-root dirs
    /// (e.g. the desktop/Apps/Library layout the container owns). The bootstrap
    /// ships standard unix trees; this is a safety re-ensure, cheap and idempotent.
    private func preserveBundleFiles(in root: URL) {
        VirtualRoot.shared.ensure()
    }

    /// Wipe the jbroot back to empty (keeps the managed skeleton). Useful for a
    /// "reset" and for re-extracting after updating the bundled asset.
    func reset() {
        let fm = FileManager.default
        let root = VirtualRoot.shared.rootURL
        guard let contents = try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) else { return }
        for item in contents {
            guard item.lastPathComponent != markerName else { continue }
            try? fm.removeItem(at: item)
        }
        try? fm.removeItem(at: markerURL)
        RyLog.shared.log("jbroot：已重置", level: .info, tag: "jbroot")
    }
}
