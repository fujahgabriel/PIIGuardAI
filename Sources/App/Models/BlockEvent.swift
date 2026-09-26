import Foundation

/// A record of something the proxy observed. The raw PII value itself is
/// never stored here — only the rule names that fired and a short redacted
/// preview per match (e.g. "email address: jo***te"), so the event log
/// (including its on-disk copy) can't itself become a plaintext store of the
/// exact secrets it caught.
struct TrafficEvent: Identifiable, Hashable, Codable {
    enum Outcome: String, Hashable, Codable {
        case blocked
        case allowed
        case allowedUnscanned // body couldn't be parsed (e.g. chunked/compressed)
        case redacted // PII found, but auto-redact mode replaced it and forwarded the rest
    }

    let id: UUID
    let date: Date
    let host: String
    let providerName: String
    let outcome: Outcome
    /// Display-ready rule names that fired, e.g. "email address" or a
    /// custom rule's own label. Empty for `.allowed`/`.allowedUnscanned`.
    let matchedCategories: [String]
    /// "<category>: <redacted preview>" per match, e.g. "email address: jo***te".
    /// Absent on log entries written before this field existed.
    let detectionPreviews: [String]

    init(id: UUID = UUID(), date: Date, host: String, providerName: String, outcome: Outcome, matchedCategories: [String], detectionPreviews: [String] = []) {
        self.id = id
        self.date = date
        self.host = host
        self.providerName = providerName
        self.outcome = outcome
        self.matchedCategories = matchedCategories
        self.detectionPreviews = detectionPreviews
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        date = try container.decode(Date.self, forKey: .date)
        host = try container.decode(String.self, forKey: .host)
        providerName = try container.decode(String.self, forKey: .providerName)
        outcome = try container.decode(Outcome.self, forKey: .outcome)
        matchedCategories = try container.decode([String].self, forKey: .matchedCategories)
        detectionPreviews = try container.decodeIfPresent([String].self, forKey: .detectionPreviews) ?? []
    }

    var summary: String {
        switch outcome {
        case .blocked:
            let detail = detectionPreviews.isEmpty ? matchedCategories.joined(separator: ", ") : detectionPreviews.joined(separator: ", ")
            return "Blocked message to \(providerName): \(detail)"
        case .allowed:
            return "Allowed message to \(providerName)"
        case .allowedUnscanned:
            return "Allowed message to \(providerName) (could not scan body)"
        case .redacted:
            let detail = detectionPreviews.isEmpty ? matchedCategories.joined(separator: ", ") : detectionPreviews.joined(separator: ", ")
            return "Redacted and sent to \(providerName): \(detail)"
        }
    }
}
