import Foundation

/// A guest app registered inside the container.
public struct ImportedApp: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let bundleIdentifier: String
    public let executablePath: String
    /// true = standard iOS GUI app (installed as a separate signed app, model B);
    /// false = CLI tool / daemon run inside the microkernel.
    public let isGUI: Bool
    public let containerPath: String

    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}
