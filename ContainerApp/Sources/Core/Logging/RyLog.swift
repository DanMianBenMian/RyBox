import Foundation
import Combine
import os

/// RyBox's live log bus.
///
/// Everything that happens inside the container — the guest loader, the
/// signer, the microkernel, the UI shell — pushes its lines here. The lines
/// show up in two places:
///   * the 「日志」 app on the desktop (full screen, searchable, live),
///   * the floating ball (a small always-on-top bubble that can be expanded
///     into the same log view from any screen, including while a guest app
///     is running).
///
/// The store keeps a bounded ring buffer so a long session cannot eat memory,
/// and mirrors every line into the unified system log so `Console.app` still
/// works as before.
public final class RyLog: ObservableObject {
    public static let shared = RyLog()

    public enum Level: String, CaseIterable, Comparable {
        case debug, info, warn, error

        public var rank: Int {
            switch self {
            case .debug: return 0
            case .info: return 1
            case .warn: return 2
            case .error: return 3
            }
        }
        public static func < (a: Level, b: Level) -> Bool { a.rank < b.rank }

        public var symbol: String {
            switch self {
            case .debug: return "·"
            case .info: return "i"
            case .warn: return "!"
            case .error: return "×"
            }
        }
    }

    public struct Entry: Identifiable {
        public let id = UUID()
        public let date: Date
        public let level: Level
        public let tag: String
        public let message: String
    }

    /// Newest first (the view renders top-down without reversing).
    @Published public private(set) var entries: [Entry] = []

    /// Bumped on every append so views can scroll to the end cheaply.
    @Published public private(set) var revision: UInt64 = 0

    /// Minimum level kept in the buffer / shown by default.
    @Published public var minimumLevel: Level = .debug

    /// Ring-buffer cap. 4000 lines ≈ a few hundred KB — plenty for a session.
    private let capacity = 4000
    private let lock = NSLock()
    private var buffer: [Entry] = []
    private var pending = 0

    private let osLog = OSLog(subsystem: "com.rybox.RyBox", category: "rybox")

    private init() {
        // Bridge the C/ObjC side (guest loader, signer) into the same bus so
        // the in-app log shows the REAL loader trace, not just Swift-side
        // cosmetics.
        //
        // The sink is a C function pointer, so it must be a plain top-level
        // function with no captures — a Swift closure cannot be converted
        // implicitly. `ryLogSink` is that trampoline.
        RyLogSetSink(ryLogSink)
    }

    // MARK: - Writing

    /// Log a line. Safe from any thread.
    ///
    /// The signature is `log(_ message:, level:, tag:)` — the level and tag are
    /// ALWAYS labelled. An unlabelled positional overload would make every
    /// call site ambiguous (`log("x", .info, "tag")` could match either).
    public func log(_ message: String, level: Level = .info, tag: String = "app") {
        append(message: message, level: level, tag: tag)
    }

    fileprivate func append(message: String, level: Level, tag: String) {
        let entry = Entry(date: Date(), level: level, tag: tag, message: message)

        lock.lock()
        buffer.append(entry)
        if buffer.count > capacity {
            buffer.removeFirst(buffer.count - capacity)
        }
        lock.unlock()

        // Mirror to the unified log (unchanged behaviour for Console.app).
        let type: OSLogType
        switch level {
        case .debug: type = .debug
        case .info: type = .info
        case .warn: type = .default
        case .error: type = .error
        }
        os_log("%{public}@ [%{public}@] %{public}@", log: osLog, type: type,
               level.rawValue, tag, message)

        publish()
    }

    /// Push the buffer to the UI. Coalesced: many appends in one runloop turn
    /// produce a single publish.
    private func publish() {
        lock.lock()
        pending += 1
        let shouldPublish = pending == 1
        lock.unlock()
        guard shouldPublish else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            self.pending = 0
            let snapshot = self.buffer
            self.lock.unlock()
            self.entries = snapshot
            self.revision &+= 1
        }
    }

    // MARK: - Reading / clearing

    /// Entries filtered by the current minimum level, newest first.
    public var visibleEntries: [Entry] {
        entries.filter { $0.level.rank >= minimumLevel.rank }
    }

    /// Free-text search across tag + message.
    public func search(_ query: String) -> [Entry] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        let base = visibleEntries
        guard !q.isEmpty else { return base }
        return base.filter {
            $0.message.lowercased().contains(q) || $0.tag.lowercased().contains(q)
        }
    }

    public func clear() {
        lock.lock()
        buffer.removeAll()
        lock.unlock()
        publish()
    }

    /// The whole log as plain text (for the share sheet / copy button).
    public func plainText() -> String {
        let fmt = DateFormatter()
        fmt.dateFormat = "HH:mm:ss.SSS"
        return entries.reversed().map { e in
            "[\(fmt.string(from: e.date))] [\(e.level.rawValue.uppercased())] [\(e.tag)] \(e.message)"
        }.joined(separator: "\n")
    }
}

/// C trampoline for the log sink (see `RyLog.init`).
///
/// It must be a top-level function with no captures so it can be converted to
/// a C function pointer. The `RyLogSetSink` typedef is
/// `void (*)(const char *, const char *, const char *)`.
private func ryLogSink(_ level: UnsafePointer<CChar>?,
                        _ tag: UnsafePointer<CChar>?,
                        _ message: UnsafePointer<CChar>?) {
    let lvl = level.flatMap { RyLog.Level(rawValue: String(cString: $0)) } ?? .info
    let t = tag.map { String(cString: $0) } ?? "c"
    let m = message.map { String(cString: $0) } ?? ""
    RyLog.shared.append(message: m, level: lvl, tag: t)
}
