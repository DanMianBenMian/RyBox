import Foundation
import Network
import Darwin
import UIKit

/// Developer debug bridge.
///
/// When enabled in Settings, RyBox opens a TCP listener so a PC can connect and
/// drive the device WITHOUT rebuilding the IPA: push a recompiled guest binary or
/// an entitlements file, re-sign a guest, launch/eject it, stream RyLog, run
/// sandbox-shell commands, and inspect the virtual root. The listener binds to
/// `0.0.0.0` on the chosen port; the PC connects over the device's LAN address
/// (the Settings screen shows it).
///
/// Protocol (line-based, UTF-8, `\n` terminated):
///   help                       list commands
///   info                       device + app + imported-app inventory
///   log [query]                dump RyLog (optionally filtered by `query`)
///   ls <path>                  list a directory under the sandbox / virtual root
///   cat <path>                 read a file (capped at 256 KiB)
///   push <path> <size>\\n<bin> write `size` raw bytes to `path`, then reply
///   exec <shell>               run a sandboxed shell command, return stdout+stderr
///   resign <bundleID>          re-patch + re-sign a guest bundle (no rebuild)
///   launch <bundleID>          launch a guest in-process
///   eject                      tear down the current guest
///   quit                       close this connection
/// Every response is terminated by a line `<<EOF>>`. `push` switches the
/// connection into raw-binary mode for exactly `size` bytes, then returns to
/// line mode.
final class DevBridge {

    static let shared = DevBridge()

    private let devModeKey = "rybox.devmode"
    private let portKey = "rybox.devport"

    private var listener: NWListener?
    private let serviceQueue = DispatchQueue(label: "devbridge.listener")

    var isRunning: Bool { listener != nil }

    /// Begin/stop the listener according to the persisted dev-mode flag. Call
    /// from app launch and from the Settings toggle.
    func applyDevMode() {
        let on = UserDefaults.standard.bool(forKey: devModeKey)
        if on { start() } else { stop() }
    }

    func start() {
        guard listener == nil else { return }
        let port = UInt16(UserDefaults.standard.integer(forKey: portKey) > 0
                          ? UserDefaults.standard.integer(forKey: portKey)
                          : 2222)
        let params = NWParameters.tcp
        // Permissive accept; the sandbox still confines every command to the app
        // container + virtual root.
        do {
            let l = try NWListener(using: params, on: NWEndpoint.Port(integerLiteral: port))
            l.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    RyLog.shared.log("DevBridge 监听就绪 · 端口 \(port)", level: .info, tag: "dev")
                case .failed(let err):
                    RyLog.shared.log("DevBridge 监听失败：\(err)", level: .error, tag: "dev")
                default: break
                }
            }
            l.newConnectionHandler = { [weak self] conn in
                self?.handle(conn)
            }
            l.start(queue: serviceQueue)
            listener = l
            RyLog.shared.log("DevBridge 已启动（开发者调试）", level: .info, tag: "dev")
        } catch {
            RyLog.shared.log("DevBridge 启动异常：\(error)", level: .error, tag: "dev")
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        RyLog.shared.log("DevBridge 已停止", level: .info, tag: "dev")
    }

    // MARK: - Connection handling

    private func handle(_ conn: NWConnection) {
        conn.start(queue: serviceQueue)
        var buffer = Data()
        var pendingPush: (url: URL, remaining: Int, handle: FileHandle?)? = nil

        func safeBase() -> URL {
            // Allowed roots: the app sandbox Documents dir and the virtual root.
            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
            return docs
        }

        func resolve(_ path: String) -> URL? {
            let base = safeBase()
            let vroot = base.appendingPathComponent("root")
            let trimmed = path.trimmingCharacters(in: .whitespaces)
            let url: URL
            if trimmed.hasPrefix("/") {
                url = URL(fileURLWithPath: trimmed)
                // Only allow inside the home directory (sandbox would block
                // anyway, but be explicit).
                guard url.path.hasPrefix(NSHomeDirectory()) else { return nil }
            } else {
                // Relative: resolve under the virtual root first, else Documents.
                let underV = vroot.appendingPathComponent(trimmed)
                url = underV
            }
            return url
        }

        func send(_ text: String, on c: NWConnection) {
            var out = Data(text.utf8)
            out.append("\n<<EOF>>\n".data(using: .utf8)!)
            c.send(content: out, completion: .contentProcessed({ _ in }))
        }

        func processLine(_ raw: String, on c: NWConnection) {
            let parts = raw.split(separator: " ", maxSplits: 2).map(String.init)
            guard let cmd = parts.first?.lowercased() else { send("ERR empty\n", on: c); return }
            switch cmd {
            case "help":
                send(helpText(), on: c)
            case "info":
                send(infoText(), on: c)
            case "log":
                let q = parts.count > 1 ? parts[1] : ""
                let text = q.isEmpty ? RyLog.shared.plainText()
                                     : RyLog.shared.search(q).map { format($0) }.joined(separator: "\n")
                send(text.isEmpty ? "(空日志)" : text, on: c)
            case "ls":
                guard parts.count > 1, let u = resolve(parts[1]) else { send("ERR bad path\n", on: c); return }
                send(listDir(u), on: c)
            case "cat":
                guard parts.count > 1, let u = resolve(parts[1]) else { send("ERR bad path\n", on: c); return }
                send(readFile(u), on: c)
            case "push":
                // push <path> <size>
                guard parts.count == 3, let u = resolve(parts[1]),
                      let size = Int(parts[2]) else { send("ERR push <path> <size>\n", on: c); return }
                // Always arm a pending push and reply "OK push-ready" so the
                // client knows to stream the binary. (If the bytes were already
                // coalesced into this receive, feed them now and finalize; the
                // client only sends the file when it sees "push-ready".)
                let handle = openPush(u)
                let take = min(buffer.count, size)
                if take > 0 {
                    handle?.write(buffer.subdata(in: 0..<take))
                    buffer.removeSubrange(0..<take)
                }
                let remaining = size - take
                if remaining <= 0 {
                    try? handle?.close()
                    send("OK pushed \(u.path) \(size)B\n", on: c)
                } else {
                    pendingPush = (url: u, remaining: remaining, handle: handle)
                    send("OK push-ready \(size)\n", on: c)
                }
            case "exec":
                let shell = parts.count > 1 ? parts[1...].joined(separator: " ") : ""
                send(runShell(shell), on: c)
            case "resign":
                guard parts.count > 1 else { send("ERR resign <bundleID>\n", on: c); return }
                send(resign(parts[1]), on: c)
            case "launch":
                guard parts.count > 1 else { send("ERR launch <bundleID>\n", on: c); return }
                send(launch(parts[1]), on: c)
            case "eject":
                DispatchQueue.main.async { GuestRuntime.eject() }
                send("OK eject queued\n", on: c)
            case "quit":
                send("BYE\n", on: c)
                c.cancel()
            default:
                send("ERR unknown command: \(cmd)\n", on: c)
            }
        }

        func openPush(_ url: URL) -> FileHandle? {
            let fm = FileManager.default
            do {
                let dir = url.deletingLastPathComponent()
                try fm.createDirectory(at: dir, withIntermediateDirectories: true)
                if fm.fileExists(atPath: url.path) { try fm.removeItem(at: url) }
                try "".write(to: url, atomically: true, encoding: .utf8)
                return try FileHandle(forWritingTo: url)
            } catch {
                RyLog.shared.log("DevBridge push open failed: \(error)", level: .error, tag: "dev")
                return nil
            }
        }

        func pump() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, _ in
                guard let data = data, !data.isEmpty else {
                    // Connection closed.
                    if let p = pendingPush, let h = p.handle { try? h.close() }
                    conn.cancel()
                    return
                }
                if var p = pendingPush, p.remaining > 0 {
                    // Binary push in progress.
                    let take = min(data.count, p.remaining)
                    let chunk = data.subdata(in: 0..<take)
                    p.remaining -= take
                    if p.handle == nil { p.handle = openPush(p.url) }
                    if let h = p.handle { h.write(chunk) }
                    // Any bytes beyond `take` belong to the next command; keep
                    // them for the line parser.
                    if data.count > take {
                        buffer.append(data.subdata(in: take..<data.count))
                    }
                    pendingPush = p
                    if p.remaining <= 0 {
                        try? p.handle?.close()
                        pendingPush = nil
                        RyLog.shared.log("DevBridge push 完成 \(p.url.path)", level: .info, tag: "dev")
                        send("OK pushed \(p.url.path)\n", on: conn)
                    }
                    pump()
                    return
                }
                buffer.append(data)
                // Extract complete lines.
                while let nl = buffer.firstIndex(of: 0x0A) {
                    let line = buffer.subdata(in: 0..<nl)
                    buffer.removeSubrange(0...nl)   // drop line + newline
                    if let s = String(data: line, encoding: .utf8) {
                        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
                        if !trimmed.isEmpty { processLine(trimmed, on: conn) }
                    }
                }
                pump()
            }
        }
        pump()
    }

    // MARK: - Command implementations

    private func helpText() -> String {
        return [
            "RyBox DevBridge commands:",
            "  help                  this list",
            "  info                  device / app / imported apps",
            "  log [query]           dump RyLog (filtered by query)",
            "  ls <path>             list a dir (sandbox + virtual root)",
            "  cat <path>            read a file (<=256KiB)",
            "  push <path> <size>    send raw bytes (next <size> bytes)",
            "  exec <shell>          run a sandboxed shell command",
            "  resign <bundleID>     re-patch + re-sign a guest (no rebuild)",
            "  launch <bundleID>     launch a guest in-process",
            "  eject                 tear down current guest",
            "  quit                  close connection",
            "all responses end with <<EOF>>"
        ].joined(separator: "\n")
    }

    private func infoText() -> String {
        let dev = UIDevice.current
        var lines: [String] = []
        lines.append("device: \(dev.model) / \(dev.systemName) \(dev.systemVersion)")
        lines.append("app: \(Bundle.main.bundleIdentifier ?? "?") v\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] ?? "?")")
        lines.append("devmode: \(UserDefaults.standard.bool(forKey: devModeKey))")
        lines.append("localIP: \(localIP())")
        lines.append("imported apps:")
        for a in AppImporter.shared.importedApps {
            lines.append("  \(a.bundleIdentifier)  ->  \(a.executablePath)")
        }
        return lines.joined(separator: "\n")
    }

    private func format(_ e: RyLog.Entry) -> String {
        let df = DateFormatter(); df.dateFormat = "HH:mm:ss.SSS"
        return "[\(df.string(from: e.date))] [\(e.level.rawValue)] [\(e.tag)] \(e.message)"
    }

    private func listDir(_ url: URL) -> String {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(at: url, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else {
            return "ERR cannot list \(url.path)"
        }
        if items.isEmpty { return "(empty)" }
        return items.map { u in
            let isDir = (try? u.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true
            return isDir == true ? "\(u.lastPathComponent)/" : u.lastPathComponent
        }.joined(separator: "\n")
    }

    private func readFile(_ url: URL) -> String {
        let fm = FileManager.default
        guard let attr = try? fm.attributesOfItem(atPath: url.path),
              let size = attr[.size] as? UInt64 else { return "ERR cannot read \(url.path)" }
        guard size <= 256 * 1024 else { return "ERR too large (\(size)B > 256KiB)" }
        guard let data = try? Data(contentsOf: url) else { return "ERR read failed" }
        if let s = String(data: data, encoding: .utf8) { return s }
        return "ERR not utf8 (\(data.count)B binary)"
    }

    // iOS has no `Process`; spawn via posix_spawn exactly like ProcessManager.
    private func runShell(_ shell: String) -> String {
        guard !shell.isEmpty else { return "ERR empty command" }
        let path = "/bin/sh"
        let args: [String] = ["-c", shell]

        var pid: pid_t = 0
        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)

        var ioPipe: [Int32] = [0, 0]
        pipe(&ioPipe)
        // Redirect both stdout and stderr to the SAME pipe so a single drain
        // cannot deadlock waiting on a full sibling pipe (ProcessManager does
        // the same).
        posix_spawn_file_actions_adddup2(&fileActions, ioPipe[1], 1)
        posix_spawn_file_actions_adddup2(&fileActions, ioPipe[1], 2)
        posix_spawn_file_actions_addclose(&fileActions, ioPipe[0])
        posix_spawn_file_actions_addclose(&fileActions, ioPipe[1])

        var argsC: [UnsafeMutablePointer<CChar>?] =
            ([path] + args).map { $0.withCString(strdup) }
        argsC.append(nil)

        var envC: [UnsafeMutablePointer<CChar>?] = [ strdup("PATH=/usr/bin:/bin") ]
        envC.append(nil)

        let rc = posix_spawn(&pid, path, &fileActions, nil, &argsC, &envC)
        argsC.forEach { free($0) }
        envC.forEach { free($0) }
        posix_spawn_file_actions_destroy(&fileActions)

        guard rc == 0 else {
            return "ERR spawn errno=\(rc) (\(String(cString: strerror(rc))))"
        }

        close(ioPipe[1])
        let data = readAll(fd: ioPipe[0])
        close(ioPipe[0])

        var st: Int32 = 0
        waitpid(pid, &st, 0)
        // Mirror ProcessManager: report the raw wait status. WIFEXITED /
        // WEXITSTATUS are not reliably imported into Swift on iOS, so leave the
        // raw status for the caller to interpret.
        let exitCode = st

        var s = "exit=\(exitCode)\n"
        if let o = String(data: data, encoding: .utf8), !o.isEmpty { s += "--- output ---\n\(o)" }
        return s
    }

    private func readAll(fd: Int32) -> Data {
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        var n: ssize_t = 0
        repeat {
            n = read(fd, &buf, buf.count)
            if n > 0 { data.append(buf, count: Int(n)) }
        } while n > 0
        return data
    }

    private func resign(_ bid: String) -> String {
        guard let app = RyLaunchCoordinator.shared.app(bundleID: bid) else {
            return "ERR no such app: \(bid)"
        }
        let exe = app.executablePath
        let rc = RyPatchGuestExecutable(exe)
        guard rc == 0 else { return "ERR patch rc=\(rc)" }
        switch CodeSigner.shared.sign(bundleAt: URL(fileURLWithPath: exe).deletingLastPathComponent().path) {
        case .success:
            return "OK resigned \(bid)"
        case .failure(let err):
            return "ERR sign: \(err.localizedDescription)"
        }
    }

    private func launch(_ bid: String) -> String {
        guard let app = RyLaunchCoordinator.shared.app(bundleID: bid) else {
            return "ERR no such app: \(bid)"
        }
        DispatchQueue.main.async { GuestRuntime.launch(app) }
        return "OK launch queued \(bid)"
    }

    /// Best-effort LAN IPv4 of the device, for the Settings screen.
    ///
    /// The old version only matched a hard-coded allow-list (`en0` / `pdp_ip0`
    /// / `bridge0`); on any device whose active interface is named differently
    /// (USB Ethernet, a tethered/`en1` Wi-Fi, a personal-hotspot bridge, …) it
    /// fell through to `"unknown"` and the Settings screen showed `:2222`.
    /// We now take the first usable non-loopback IPv4 address, preferring Wi-Fi
    /// (`en0`) when present, then any `en*`, then cellular / bridge interfaces.
    func localIP() -> String {
        var ifaddrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrs) == 0, let first = ifaddrs else { return "unknown" }
        defer { freeifaddrs(ifaddrs) }

        var candidates: [String: String] = [:]   // interface name -> IPv4
        var p = first
        while true {
            if let addr = p.pointee.ifa_addr,
               addr.pointee.sa_family == UInt8(AF_INET) {
                let name = String(cString: p.pointee.ifa_name)
                // Skip loopback and the Apple wireless / tunnel virtuals.
                let skip = name == "lo0"
                    || name.hasPrefix("awdl")
                    || name.hasPrefix("llw")
                    || name.hasPrefix("utun")
                if !skip {
                    var sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    if let c = inet_ntop(AF_INET, &sin.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN)) {
                        let ip = String(cString: c)
                        if ip != "127.0.0.1" { candidates[name] = ip }
                    }
                }
            }
            if p.pointee.ifa_next == nil { break }
            p = p.pointee.ifa_next
        }

        // Preference order: Wi-Fi, then any wired/en*, then cellular, then bridge,
        // then whatever else we found.
        if let en0 = candidates["en0"] { return en0 }
        if let en = candidates.first(where: { $0.key.hasPrefix("en") })?.value { return en }
        if let pdp = candidates.first(where: { $0.key.hasPrefix("pdp") })?.value { return pdp }
        if let bridge = candidates.first(where: { $0.key.hasPrefix("bridge") })?.value { return bridge }
        return candidates.first?.value ?? "unknown"
    }
}
