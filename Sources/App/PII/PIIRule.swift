import Foundation

enum PIICategory: String, CaseIterable, Hashable, Codable {
    case email
    case phoneNumber
    case ssn
    case creditCard
    case awsKey
    case genericApiKey
    case ipv4Address
    case envSecret
    case envFile

    var displayName: String {
        switch self {
        case .email: return "email address"
        case .phoneNumber: return "phone number"
        case .ssn: return "Social Security number"
        case .creditCard: return "credit card number"
        case .awsKey: return "AWS access key"
        case .genericApiKey: return "API key / secret"
        case .ipv4Address: return "IP address"
        case .envSecret: return "environment secret (.env)"
        case .envFile: return ".env file contents"
        }
    }
}

/// A single PII hit. Built-in rules and user-defined custom rules both
/// produce these -- `categoryName` is already a display-ready label (a
/// `PIICategory`'s `displayName`, or a custom rule's own label), so
/// downstream code (notifications, the activity log) never needs to know
/// which kind of rule fired.
struct PIIMatch: Hashable {
    let categoryName: String
    /// A redacted preview safe to show in a notification, e.g. "j***@example.com".
    let redactedPreview: String
    /// Where the match sits in the scanned text (NSString/UTF-16 indexing,
    /// matching NSRegularExpression). Used only for in-place redaction --
    /// `NSRange(location: NSNotFound, length: 0)` for matches that aren't
    /// tied to a specific substring (e.g. the bulk ".env file" heuristic,
    /// which flags the *shape* of several lines, not one replaceable span).
    let range: NSRange
}
