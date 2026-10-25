import Foundation

/// Opaque, container-managed process identifier.
/// We "make our own PID space" — these are the only PIDs that exist inside the domain.
public struct NKProcessID: Hashable, Codable {
    public let value: UInt32
    public init(value: UInt32) { self.value = value }
}

/// A guest process managed by the in-sandbox microkernel.
/// Not a fake process — it is the only process abstraction that exists here.
public final class NKProcess: ObservableObject {
    public let id: NKProcessID
    public let name: String
    public let executablePath: String
    public let arguments: [String]
    public let environment: [String: String]

    public enum State { case spawning, running, exited, signaled }

    @Published public private(set) var pid: pid_t = 0
    @Published public private(set) var state: State = .spawning
    @Published public private(set) var exitStatus: Int32 = 0
    @Published public private(set) var output: String = ""

    internal init(id: NKProcessID, name: String, executablePath: String,
                  arguments: [String], environment: [String: String]) {
        self.id = id
        self.name = name
        self.executablePath = executablePath
        self.arguments = arguments
        self.environment = environment
    }

    internal func markRunning(pid: pid_t) {
        self.pid = pid
        self.state = .running
    }

    internal func markExited(status: Int32) {
        self.exitStatus = status
        self.state = .exited
        onExit?(status)
    }

    internal func appendOutput(_ s: String) {
        output += s
        onOutput?(s)
    }

    /// Live hooks the launcher can use to mirror the child's stdout/stderr
    /// into RyBox's own log. A guest that dies during startup says WHY on
    /// stderr (an AMFI refusal, a missing symbol, a bad profile) — without
    /// this the container would only see "the process went away".
    internal var onOutput: ((String) -> Void)?
    internal var onExit: ((Int32) -> Void)?
}
