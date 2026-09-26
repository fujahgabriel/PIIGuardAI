import Foundation

/// Appends `TrafficEvent`s to a JSON-Lines file on disk so the Activity tab
/// survives app restarts. Events never contain raw PII (only rule names and
/// redacted previews), so persisting them carries the same privacy profile
/// as the in-memory list already had.
final class ActivityStore {
    private let fileURL: URL
    private let queue = DispatchQueue(label: AppIdentity.queueLabel("activitystore"))
    private let maxStoredEvents = 5000

    init(directory: URL) {
        self.fileURL = directory.appendingPathComponent("activity-log.jsonl")
    }

    var fileURLForDisplay: URL { fileURL }

    /// Newest-first.
    func loadAll() -> [TrafficEvent] {
        queue.sync {
            guard let data = try? Data(contentsOf: fileURL) else { return [] }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let events = data
                .split(separator: UInt8(ascii: "\n"))
                .compactMap { try? decoder.decode(TrafficEvent.self, from: Data($0)) }
            return events.reversed()
        }
    }

    func append(_ event: TrafficEvent) {
        queue.async { [fileURL, maxStoredEvents] in
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            guard var line = try? encoder.encode(event) else { return }
            line.append(UInt8(ascii: "\n"))

            if let handle = try? FileHandle(forWritingTo: fileURL) {
                handle.seekToEndOfFile()
                handle.write(line)
                try? handle.close()
            } else {
                try? line.write(to: fileURL, options: .atomic)
            }
            Self.trimIfNeeded(fileURL: fileURL, maxLines: maxStoredEvents)
        }
    }

    func clear() {
        queue.async { [fileURL] in
            try? FileManager.default.removeItem(at: fileURL)
        }
    }

    private static func trimIfNeeded(fileURL: URL, maxLines: Int) {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        let lines = data.split(separator: UInt8(ascii: "\n"), omittingEmptySubsequences: true)
        guard lines.count > maxLines + 500 else { return }

        var trimmed = Data()
        for line in lines.suffix(maxLines) {
            trimmed.append(line)
            trimmed.append(UInt8(ascii: "\n"))
        }
        try? trimmed.write(to: fileURL, options: .atomic)
    }
}
