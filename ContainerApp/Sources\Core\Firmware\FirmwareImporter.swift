import Foundation

/// What one firmware import actually produced.
struct FirmwareReport: Codable, Equatable {
    var source: String            // picked file name
    var kind: String              // "ryboxenv" | "ipsw"
    var version: String?          // e.g. "27.0"
    var build: String?            // e.g. "24A5370h"
    var deviceClass: String?      // e.g. "j271ap"
    var entries: Int              // entries in the archive
    var installedFiles: Int
    var installedBytes: Int64
    /// AEA-encrypted volumes we could NOT decode on device (modern IPSWs keep
    /// the whole system volume here: needs a WKMS key + APFS decode).
    var aeaVolumes: [String]
    var notes: [String]
    var completedAt: Date
}

/// RyBox firmware ingestion — "完整还原系统环境".
///
/// The firmware NEVER travels inside the IPA (that would make it gigabytes).
/// Instead the user imports it once, in the boot flow, from the Files app. Two
/// inputs are supported:
///
///  1. `.ryboxenv` — a system-environment PACKAGE produced on a computer, where
///     AEA / DMG / APFS have already been decoded. It is a plain zip holding
///     `ryboxenv.json` plus a `rootfs/` tree; RyBox unzips it straight into the
///     virtual root, so `/usr`, `/bin`, `/System`, `/Applications` become REAL
///     content. This is the complete path.
///
///  2. `.ipsw` — the raw Apple archive. RyBox reads its ZIP64 index in place
///     (no 10 GB copy!) and extracts everything that is not AEA-encrypted:
///     BuildManifest, kernelcache, trustcaches, mtree, SystemVersion. The main
///     system volume is AEA-encrypted, so we list those volumes and say so
///     honestly rather than pretending we decoded them.
final class FirmwareImporter: ObservableObject {
    static let shared = FirmwareImporter()

    private enum Key {
        static let report = "rybox.firmware.report"
    }

    enum Phase: Equatable {
        case idle, scanning, extracting, ready, partial, failed
        var label: String {
            switch self {
            case .idle: return "未导入"
            case .scanning: return "扫描中"
            case .extracting: return "还原中"
            case .ready: return "已还原"
            case .partial: return "部分还原"
            case .failed: return "失败"
            }
        }
    }

    @Published var phase: Phase = .idle
    @Published var progress: Double = 0
    @Published var message = "尚未导入固件"
    @Published var report: FirmwareReport?
    /// Stream of human-readable deploy steps, shown on the black-background
    /// deploy log screen while the firmware is being unpacked.
    @Published var log: [String] = []

    private var working = false

    private init() {
        if let r = Self.loadReport() {
            report = r
            phase = r.aeaVolumes.isEmpty ? .ready : .partial
            message = Self.summary(r)
        }
    }

    /// A firmware import satisfies the boot gate (`.partial` counts: the user
    /// really did import a firmware, we just could not decode its AEA volume).
    var isSatisfied: Bool { phase == .ready || phase == .partial }

    static func summary(_ r: FirmwareReport) -> String {
        let mb = Double(r.installedBytes) / 1024 / 1024
        var s = "\(r.source)：\(r.installedFiles) 个文件 / \(String(format: "%.1f", mb)) MB"
        if !r.aeaVolumes.isEmpty {
            s += "（\(r.aeaVolumes.count) 个 AEA 加密卷需电脑端预处理）"
        }
        return s
    }

    // MARK: - Public API

    /// Import a firmware file. `url` may be a security-scoped picker URL
    /// (asCopy: false) — access is started/stopped around the read.
    func ingest(_ url: URL) {
        guard !working else { return }
        working = true
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        DispatchQueue.main.async {
            self.log.removeAll()
            self.appendLog("ryboxenv deploy — \(url.lastPathComponent)")
            self.phase = .scanning
            self.progress = 0.03
            self.message = "正在扫描固件索引…"
            self.appendLog("› 扫描固件索引…")
        }

        DispatchQueue.global(qos: .userInitiated).async {
            self.work(url)
            self.working = false
        }
    }

    func reset() {
        report = nil
        phase = .idle
        progress = 0
        message = "尚未导入固件"
        UserDefaults.standard.removeObject(forKey: Key.report)
    }

    // MARK: - Worker

    private func work(_ url: URL) {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory.appendingPathComponent("fw-\(UUID().uuidString)")
        try? fm.createDirectory(at: tmp, withIntermediateDirectories: true)

        let listURL = tmp.appendingPathComponent("index.tsv")
        let count = ry_unzip_enumerate(url.path, listURL.path)
        guard count > 0 else {
            fail("无法读取固件索引（错误码 \(count)）。文件可能是损坏的 zip，或不是 IPSW/.ryboxenv。")
            return
        }
        guard let text = try? String(contentsOf: listURL, encoding: .utf8) else {
            fail("无法解析固件索引")
            return
        }

        var entries: [(String, UInt64)] = []
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard parts.count >= 2, let usize = UInt64(parts[1]) else { continue }
            entries.append((String(parts[0]), usize))
        }

        let names = Set(entries.map { $0.0 })
        let isEnv = names.contains("ryboxenv.json")
        let isIPSW = names.contains("BuildManifest.plist") || names.contains("Restore.plist")
        guard isEnv || isIPSW else {
            fail("这个文件既不是 .ryboxenv 系统环境包，也不是 IPSW（未找到 ryboxenv.json / BuildManifest.plist）")
            return
        }

        let aea = entries.filter { $0.0.hasSuffix(".aea") }.map { ($0.0 as NSString).lastPathComponent }

        let kind = isEnv ? "ryboxenv 系统环境包" : "IPSW 原厂固件"
        appendLog("› 识别为 \(kind)（\(entries.count) 个条目）")
        if isEnv {
            appendLog("› 解包 rootfs → 虚拟根…")
        } else {
            appendLog("› 提取未加密条目（manifest / kernelcache / trustcache）…")
        }
        post(phase: .extracting, progress: 0.12, message: "正在还原系统环境…")

        var outBytes: UInt64 = 0
        var installed = 0

        if isEnv {
            // Complete package: extract every entry, then move rootfs/* into
            // the virtual root.
            let unpack = tmp.appendingPathComponent("unpacked")
            let namesFile = tmp.appendingPathComponent("all.txt")
            try? "*\n".write(to: namesFile, atomically: true, encoding: .utf8)
            let n = ry_unzip_extract_selected(url.path, unpack.path, namesFile.path, &outBytes)
            guard n > 0 else {
                fail("解包失败（错误码 \(n)）")
                return
            }
            installed = Self.mergeRootfs(from: unpack, into: VirtualRoot.shared.rootURL)
        } else {
            // Raw IPSW: only the small, non-AEA artifacts are worth pulling out
            // on device (a 7.5 GB AEA volume cannot be decoded here anyway).
            let wanted = entries.filter { Self.isWantedIPSWEntry($0.0, size: $0.1) }.map { $0.0 }
            let namesFile = tmp.appendingPathComponent("want.txt")
            try? wanted.joined(separator: "\n").write(to: namesFile, atomically: true, encoding: .utf8)
            let unpack = tmp.appendingPathComponent("unpacked")
            let n = ry_unzip_extract_selected(url.path, unpack.path, namesFile.path, &outBytes)
            guard n > 0 else {
                fail("固件条目提取失败（错误码 \(n)）")
                return
            }
            installed = Self.installIPSWArchive(from: unpack, into: VirtualRoot.shared.rootURL)
        }

        // Metadata (best effort).
        let meta = Self.readMetadata(isEnv ? tmp.appendingPathComponent("unpacked/ryboxenv.json") : nil,
                                     ipswDir: tmp.appendingPathComponent("unpacked"))
        var notes: [String] = []
        if !aea.isEmpty {
            notes.append("本 IPSW 的 \(aea.count) 个卷使用 AEA 加密，设备端无法解密；请在电脑上用 make_ryboxenv.py 生成 .ryboxenv 后重新导入，即可获得完整 /usr /System 目录树。")
        }
        if !isEnv {
            notes.append("已从 IPSW 提取 manifest / kernelcache / trustcache，存放在虚拟根的 /System/Firmware/ 下，可在「文件」中查看。")
        }

        let rep = FirmwareReport(source: (url.lastPathComponent as NSString).lastPathComponent,
                                 kind: isEnv ? "ryboxenv" : "ipsw",
                                 version: meta.version,
                                 build: meta.build,
                                 deviceClass: meta.device,
                                 entries: entries.count,
                                 installedFiles: installed,
                                 installedBytes: Int64(outBytes),
                                 aeaVolumes: aea,
                                 notes: notes,
                                 completedAt: Date())
        Self.saveReport(rep)
        let mb = Double(outBytes) / 1024 / 1024
        appendLog("✓ 已还原 \(installed) 个文件 / \(String(format: "%.1f", mb)) MB")
        if !aea.isEmpty { appendLog("⚠ \(aea.count) 个 AEA 加密卷需在电脑端预处理") }
        appendLog(aea.isEmpty ? "✓ 系统环境完整还原" : "◦ 部分还原（其余卷需 .ryboxenv）")
        DispatchQueue.main.async {
            self.report = rep
            self.phase = aea.isEmpty ? .ready : .partial
            self.progress = 1
            self.message = Self.summary(rep)
        }
        try? fm.removeItem(at: tmp)
        // The picker hands us a COPY inside our own container (asCopy: true).
        // Once the tree is extracted that copy is dead weight — a .ryboxenv can
        // be hundreds of MB — so drop it. Never touch anything outside tmp.
        let tmpRoot = fm.temporaryDirectory.path
        if url.path.hasPrefix(tmpRoot) { try? fm.removeItem(at: url) }
    }

    // MARK: - Helpers

    /// Non-AEA artifacts of an IPSW that are actually useful on device.
    private static func isWantedIPSWEntry(_ name: String, size: UInt64) -> Bool {
        if name.hasSuffix(".aea") || name.hasSuffix(".dmg") { return false }  // huge + undecodable
        if name.hasSuffix("/") { return false }
        let lower = name.lowercased()
        if lower.hasSuffix(".plist") { return true }
        if lower.contains("kernelcache") { return true }
        if lower.hasSuffix(".trustcache") || lower.hasSuffix(".mtree") { return true }
        if lower.hasSuffix(".root_hash") { return true }
        if lower.hasSuffix(".im4p") && size < 8 * 1024 * 1024 { return true }
        return false
    }

    /// Move `<unpacked>/rootfs/*` into the virtual root (merging into
    /// existing dirs). Returns the number of files installed.
    private static func mergeRootfs(from unpack: URL, into root: URL) -> Int {
        let fm = FileManager.default
        let src = unpack.appendingPathComponent("rootfs")
        let base = fm.fileExists(atPath: src.path) ? src : unpack
        var n = 0
        guard let en = fm.enumerator(at: base, includingPropertiesForKeys: [.isRegularFileKey],
                                     options: [.skipsHiddenFiles]) else { return 0 }
        while let obj = en.nextObject() as? URL {
            let vals = try? obj.resourceValues(forKeys: [.isRegularFileKey])
            guard vals?.isRegularFile == true else { continue }
            let rel = obj.path.replacingOccurrences(of: base.path, with: "")
            let dst = root.appendingPathComponent(rel)
            try? fm.createDirectory(at: dst.deletingLastPathComponent(),
                                    withIntermediateDirectories: true)
            try? fm.removeItem(at: dst)
            if (try? fm.moveItem(at: obj, to: dst)) != nil { n += 1 }
        }
        return n
    }

    /// Park the extracted IPSW artifacts under the virtual root so the Files
    /// app (and the Terminal) can see the real firmware metadata.
    private static func installIPSWArchive(from unpack: URL, into root: URL) -> Int {
        let fm = FileManager.default
        let dest = root.appendingPathComponent("System/Firmware")
        try? fm.createDirectory(at: dest, withIntermediateDirectories: true)
        var n = 0
        guard let en = fm.enumerator(at: unpack, includingPropertiesForKeys: [.isRegularFileKey],
                                     options: []) else { return 0 }
        while let obj = en.nextObject() as? URL {
            let vals = try? obj.resourceValues(forKeys: [.isRegularFileKey])
            guard vals?.isRegularFile == true else { continue }
            let rel = obj.path.replacingOccurrences(of: unpack.path + "/", with: "")
            let dst = dest.appendingPathComponent(rel)
            try? fm.createDirectory(at: dst.deletingLastPathComponent(),
                                    withIntermediateDirectories: true)
            try? fm.removeItem(at: dst)
            if (try? fm.moveItem(at: obj, to: dst)) != nil { n += 1 }
        }
        return n
    }

    private static func readMetadata(_ envJSON: URL?, ipswDir: URL) -> (version: String?, build: String?, device: String?) {
        // .ryboxenv ships an explicit manifest.
        if let u = envJSON, let data = try? Data(contentsOf: u),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return (obj["osVersion"] as? String,
                    obj["build"] as? String,
                    obj["deviceClass"] as? String)
        }
        // IPSW: SystemVersion.plist / Restore.plist.
        for name in ["SystemVersion.plist", "Restore.plist"] {
            let u = ipswDir.appendingPathComponent(name)
            guard let data = try? Data(contentsOf: u),
                  let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                    as? [String: Any] else { continue }
            let v = plist["ProductVersion"] as? String
            let b = plist["ProductBuildVersion"] as? String
            let d = (plist["ProductName"] as? String)
            return (v, b, d)
        }
        return (nil, nil, nil)
    }

    private func post(phase: Phase, progress: Double, message: String) {
        DispatchQueue.main.async {
            self.phase = phase
            self.progress = progress
            self.message = message
        }
    }

    private func fail(_ msg: String) {
        appendLog("✗ \(msg)")
        DispatchQueue.main.async {
            self.phase = .failed
            self.progress = 0
            self.message = msg
        }
    }

    /// Append a line to the deploy log (main-thread safe).
    func appendLog(_ line: String) {
        DispatchQueue.main.async {
            self.log.append(line)
        }
    }

    // MARK: - Persistence

    private static func saveReport(_ r: FirmwareReport) {
        guard let data = try? JSONEncoder().encode(r) else { return }
        UserDefaults.standard.set(data, forKey: Key.report)
    }

    private static func loadReport() -> FirmwareReport? {
        guard let data = UserDefaults.standard.data(forKey: Key.report),
              let r = try? JSONDecoder().decode(FirmwareReport.self, from: data) else { return nil }
        return r
    }
}
