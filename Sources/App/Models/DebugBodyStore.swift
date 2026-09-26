import Foundation

/// Opt-in debug store for the *actual* request body that triggered a block.
/// Main `ActivityStore` is safe (only redacted categories). This file contains
/// raw bodies, so it is OFF by default, written 0600, and truncated to 8k.
/// Enable only to diagnose false positives, then disable/clear.
final class DebugBodyStore {
    private let fileURL: URL
    private let queue = DispatchQueue(label: AppIdentity.queueLabel("debugstore"))
    static let enabledKey = AppIdentity.defaultsKey("debugLogRawBodies")

    init(directory: URL) {
        self.fileURL = directory.appendingPathComponent("debug-pii-bodies.jsonl")
    }

    var fileURLForDisplay: URL { fileURL }

    var isEnabled: Bool { UserDefaults.standard.bool(forKey: Self.enabledKey) }

    func setEnabled(_ enabled: Bool) {
        UserDefaults.standard.set(enabled, forKey: Self.enabledKey)
    }

    func log(host: String, providerName: String, categories: [String], body: Data?) {
        guard isEnabled, let body, let text = String(data: body, encoding: .utf8), !text.isEmpty else { return }
        let entry: [String: Any] = [
            "date": ISO8601DateFormatter().string(from: Date()),
            "host": host,
            "providerName": providerName,
            "categories": categories,
            "body": String(text.prefix(8000))
        ]
        queue.async { [fileURL] in
            guard let raw = try? JSONSerialization.data(withJSONObject: entry, options: [.sortedKeys]) else { return }
            var d = raw; d.append(UInt8(ascii: "\n"))
            if let h = try? FileHandle(forWritingTo: fileURL) {
                h.seekToEndOfFile(); h.write(d); try? h.close()
            } else {
                try? d.write(to: fileURL, options: .atomic)
            }
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        }
    }

    func clear() {
        queue.async { [fileURL] in try? FileManager.default.removeItem(at: fileURL) }
    }
}
