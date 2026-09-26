import Foundation

/// A user-defined detection rule, supplementing the built-in PII categories.
/// Either a plain case-insensitive substring (e.g. a project codename, an
/// internal hostname, a person's name) or a regular expression for more
/// precise matching.
struct CustomRule: Identifiable, Hashable, Codable {
    let id: UUID
    var label: String
    var pattern: String
    var isRegex: Bool
    var isEnabled: Bool

    init(id: UUID = UUID(), label: String, pattern: String, isRegex: Bool, isEnabled: Bool = true) {
        self.id = id
        self.label = label
        self.pattern = pattern
        self.isRegex = isRegex
        self.isEnabled = isEnabled
    }
}
