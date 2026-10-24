import SwiftUI

/// Minimal a-Shell-style terminal: runs guest binaries inside the microkernel.
struct TerminalView: View {
    @State private var input = ""
    @State private var lines: [String] = ["Container shell (jailed microkernel). Type a path or command."]

    var body: some View {
        VStack {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(lines.indices, id: \.self) { i in
                            Text(lines[i]).font(.system(.caption, design: .monospaced))
                                .foregroundColor(.primary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                }
                .onChange(of: lines.count) { _ in proxy.scrollTo(lines.count - 1, anchor: .bottom) }
            }
            HStack {
                TextField("command / path", text: $input)
                    .textFieldStyle(.roundedBorder)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                Button("运行") { run() }.buttonStyle(.bordered)
            }
            .padding(8)
        }
        .navigationTitle("终端")
    }

    private func run() {
        let cmd = input.trimmingCharacters(in: .whitespaces)
        guard !cmd.isEmpty else { return }
        lines.append("$ \(cmd)")
        input = ""
        // Resolve against the virtual root first, then PATH.
        let candidate = VirtualRoot.shared.realPath(of: cmd.hasPrefix("/") ? cmd : "/bin/\(cmd)")
        let path = FileManager.default.isExecutableFile(atPath: candidate) ? candidate : cmd
        if let proc = ProcessManager.shared.spawn(executable: path,
                                                 environment: ["HOME": VirtualRoot.shared.rootURL.path]) {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                for l in proc.output.split(separator: "\n") { lines.append(String(l)) }
            }
        } else {
            lines.append("cannot execute: \(path)")
        }
    }
}
