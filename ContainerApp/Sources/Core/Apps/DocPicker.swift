import UIKit
import UniformTypeIdentifiers

/// UIKit document picker, presented DIRECTLY from the app's top view controller.
///
/// Why not SwiftUI's `.fileImporter`: on this iPad (iPadOS 27 beta) the SwiftUI
/// modifier opens the picker but never delivers the selection — both the .ipa
/// picker and the .p12/.mobileprovision pickers silently failed across two
/// builds. The UIKit path is the battle-tested one.
///
/// Two modes matter here:
///  * `asCopy: true`  — the system hands us a LOCAL COPY inside our container
///    (no security scoping needed). Used for small files: p12, mobileprovision,
///    IPA.
///  * `asCopy: false` — a security-scoped URL to the ORIGINAL file. Mandatory
///    for firmware: a 10 GB IPSW must not be duplicated into our container.
enum DocPicker {

    enum PickerError: LocalizedError {
        case noHost
        case unreadable(String)
        public var errorDescription: String? {
            switch self {
            case noHost: return "找不到可用的视图控制器来打开文件选择器"
            case unreadable(let n): return "无法读取所选文件：\(n)"
            }
        }
    }

    /// Strong ref: UIDocumentPickerViewController holds its delegate WEAKLY.
    private static var retainedDelegate: PickerDelegate?

    /// Present the picker. `completion` runs on the main thread.
    /// - Parameter asCopy: true = import a copy (small files); false = open the
    ///   original in place (large files, e.g. firmware).
    static func present(asCopy: Bool = true,
                        completion: @escaping (Result<URL, Error>) -> Void) {
        DispatchQueue.main.async {
            guard let host = topViewController() else {
                completion(.failure(PickerError.noHost))
                return
            }
            let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.item],
                                                        asCopy: asCopy)
            picker.allowsMultipleSelection = false
            picker.shouldShowFileExtensions = true
            let delegate = PickerDelegate(asCopy: asCopy, completion: completion)
            retainedDelegate = delegate           // keep alive across presentation
            picker.delegate = delegate
            host.present(picker, animated: true)
        }
    }

    /// Walk every window of every scene, prefer the KEY one, and climb to the
    /// top-most presented controller. Guest-runtime chrome windows are skipped
    /// because their root controller is a bare pass-through VC.
    static func topViewController() -> UIViewController? {
        var windows: [UIWindow] = []
        for scene in UIApplication.shared.connectedScenes {
            guard let ws = scene as? UIWindowScene else { continue }
            windows.append(contentsOf: ws.windows)
        }
        let sorted = windows.sorted { a, b in
            if a.isKeyWindow != b.isKeyWindow { return a.isKeyWindow && !b.isKeyWindow }
            return a.windowLevel < b.windowLevel
        }
        for w in sorted {
            guard !w.isHidden, w.alpha > 0.01 else { continue }
            var vc = w.rootViewController
            while let presented = vc?.presentedViewController,
                  !(presented is UIDocumentPickerViewController) {
                vc = presented
            }
            if let vc = vc, vc.view.window != nil || vc === w.rootViewController {
                return vc
            }
        }
        return windows.first?.rootViewController
    }
}

/// UIDocumentPickerViewController delegate that forwards the picked URL.
private final class PickerDelegate: NSObject, UIDocumentPickerDelegate {
    let completion: (Result<URL, Error>) -> Void
    let asCopy: Bool

    init(asCopy: Bool, completion: @escaping (Result<URL, Error>) -> Void) {
        self.asCopy = asCopy
        self.completion = completion
    }

    // New (iOS 11+) API.
    func documentPicker(_ controller: UIDocumentPickerViewController,
                        didPickDocumentsAt urls: [URL]) {
        if let url = urls.first { deliver(url) }
        DocPicker.retainedDelegate = nil
    }

    // Legacy API — implemented as well: some betas call this one instead.
    func documentPicker(_ controller: UIDocumentPickerViewController,
                        didPickDocumentAt url: URL) {
        deliver(url)
        DocPicker.retainedDelegate = nil
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        DocPicker.retainedDelegate = nil
    }

    private func deliver(_ url: URL) {
        // Opening in place: grant ourselves access to the security-scoped URL.
        // Imported copies are already inside our container and need nothing.
        if !asCopy { _ = url.startAccessingSecurityScopedResource() }
        guard FileManager.default.isReadableFile(atPath: url.path) else {
            completion(.failure(DocPicker.PickerError.unreadable(url.lastPathComponent)))
            return
        }
        completion(.success(url))
    }
}
