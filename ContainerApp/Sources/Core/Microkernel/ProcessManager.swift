import Foundation
import Darwin

/// The microkernel's process subsystem.
/// iOS sandbox lets us posix_spawn our own signed binaries; we wrap it with our
/// own PID space, enumeration, signal and kill — constructing the missing
/// primitives instead of escaping to get them.
public final class ProcessManager: ObservableObject {
    public static let shared = ProcessManager()

    private var counter: UInt32 = 1
    private let lock = NSLock()

    @Published public private(set) var processes: [NKProcess] = []

    private func nextID() -> UInt32 {
        lock.lock()
        defer { lock.unlock() }
        let v = counter
        counter += 1
        return v
    }

    /// Spawn a guest binary as a managed process.
    /// - Note: the binary must already be signed (see Signing/CodeSigner).
    @discardableResult
    public func spawn(executable path: String,
                      arguments: [String] = [],
                      environment: [String: String] = [:],
                      workingDirectory: String? = nil,
                      captureOutput: Bool = true,
                      onOutput: ((String) -> Void)? = nil,
                      onExit: ((Int32) -> Void)? = nil) -> NKProcess? {
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }

        let proc = NKProcess(id: NKProcessID(value: nextID()),
                             name: (path as NSString).lastPathComponent,
                             executablePath: path,
                             arguments: arguments,
                             environment: environment)
        proc.onOutput = onOutput
        proc.onExit = onExit

        var pid: pid_t = 0
        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)

        var outPipe: [Int32] = [0, 0]
        if captureOutput {
            pipe(&outPipe)
            posix_spawn_file_actions_adddup2(&fileActions, outPipe[1], 1)
            posix_spawn_file_actions_adddup2(&fileActions, outPipe[1], 2)
            posix_spawn_file_actions_addclose(&fileActions, outPipe[0])
            posix_spawn_file_actions_addclose(&fileActions, outPipe[1])
        }

        var argsC: [UnsafeMutablePointer<CChar>?] =
            ([path] + arguments).map { $0.withCString(strdup) }
        argsC.append(nil)

        var envC: [UnsafeMutablePointer<CChar>?] = []
        var sawPath = false
        for (k, v) in environment {
            if k == "PATH" { sawPath = true }
            envC.append(strdup("\(k)=\(v)"))
        }
        // Only append a default PATH if the caller didn't supply one.
        if !sawPath { envC.append(strdup("PATH=/usr/bin:/bin")) }
        // iOS has no posix_spawn_file_actions_addchdir_np; approximate the child
        // working directory by exporting PWD (honored by most CLI tools).
        if let wd = workingDirectory, !wd.isEmpty { envC.append(strdup("PWD=\(wd)")) }
        envC.append(nil)

        let rc = posix_spawn(&pid, path, &fileActions, nil, &argsC, &envC)
        argsC.forEach { free($0) }
        envC.forEach { free($0) }
        posix_spawn_file_actions_destroy(&fileActions)

        guard rc == 0 else { return nil }

        proc.markRunning(pid: pid)

        if captureOutput {
            close(outPipe[1])
            let readFd = outPipe[0]
            DispatchQueue.global(qos: .background).async {
                guard let fp = fdopen(readFd, "r") else { close(readFd); return }
                var buf = [CChar](repeating: 0, count: 4096)
                while let line = fgets(&buf, Int32(buf.count), fp) {
                    let s = String(cString: line)
                    DispatchQueue.main.async { proc.appendOutput(s) }
                }
                fclose(fp)
                var st: Int32 = 0
                waitpid(pid, &st, 0)
                DispatchQueue.main.async { proc.markExited(status: st) }
            }
        }

        DispatchQueue.main.async { self.processes.append(proc) }
        return proc
    }

    public func kill(_ proc: NKProcess, signal: Int32 = SIGTERM) {
        if proc.pid > 0 {
            _ = Darwin.kill(proc.pid, signal)
        }
    }

    public func list() -> [NKProcess] { processes }
}
