import Foundation

/// Local, on-device regex-based PII scanner. Nothing here ever leaves the
/// Mac — detection runs entirely in-process against the request body the
/// proxy already decrypted.
struct PIIDetector {
    private static let emailRegex = try! NSRegularExpression(
        pattern: #"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#
    )
    private static let phoneRegex = try! NSRegularExpression(
        pattern: #"(?<!\d)(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"#
    )
    private static let ssnRegex = try! NSRegularExpression(
        pattern: #"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"#
    )
    private static let creditCardRegex = try! NSRegularExpression(
        // Tightened: require 16-19 digits with optional single sep, start 3/4/5/6, not inside longer run. Luhn still checked.
        pattern: #"(?<!\d)(?:3[47]\d[ -]?\d{6}[ -]?\d{5}|(?:4\d|5[1-5]|6\d)[ -]?(?:\d[ -]?){12,15})(?!\d)"#
    )
    private static let awsKeyRegex = try! NSRegularExpression(
        pattern: #"\bAKIA[0-9A-Z]{16}\b"#
    )
    private static let genericApiKeyRegex = try! NSRegularExpression(
        // Dash-separated (OpenAI-style sk-..., sk-proj-...), underscore/test-live-separated
        // (Stripe-style sk_test_..., sk_live_..., pk_test_..., pk_live_...), GitHub tokens,
        // and Slack tokens.
        pattern: #"\b(sk|pk|rk)-[A-Za-z0-9]{20,}\b|\b(sk|pk|rk)_(test|live)_[A-Za-z0-9]{6,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"#
    )
    private static let ipv4Regex = try! NSRegularExpression(
        pattern: #"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"#
    )
    /// A single `NAME=value` (or `NAME: value`) line whose variable name
    /// looks like a secret -- catches a stray `OPENAI_API_KEY=sk-...` even
    /// when it's just one line pasted into an otherwise ordinary message.
    private static let envSecretRegex = try! NSRegularExpression(
        pattern: #"(?im)^[ \t]*[A-Za-z_][A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AUTH)[A-Za-z0-9_]*[ \t]*[:=][ \t]*\S+"#
    )
    /// A plain `NAME=value` line, used only to spot a *bulk* .env-file paste
    /// (several such lines together) regardless of whether any individual
    /// name looks sensitive.
    private static let envLineRegex = try! NSRegularExpression(
        pattern: #"^[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*\S+$"#
    )

    var enabledCategories: Set<PIICategory> = Set(PIICategory.allCases)
    var customRules: [CustomRule] = []

    func scan(_ text: String) -> [PIIMatch] {
        var matches: [PIIMatch] = []
        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)

        func run(_ regex: NSRegularExpression, _ category: PIICategory, validate: ((String) -> Bool)? = nil) {
            guard enabledCategories.contains(category) else { return }
            regex.enumerateMatches(in: text, range: full) { result, _, _ in
                guard let result else { return }
                let matched = ns.substring(with: result.range)
                if let validate, !validate(matched) { return }
                matches.append(PIIMatch(categoryName: category.displayName, redactedPreview: Self.redact(matched), range: result.range))
            }
        }

        run(Self.emailRegex, .email)
        run(Self.phoneRegex, .phoneNumber)
        run(Self.ssnRegex, .ssn)
        run(Self.creditCardRegex, .creditCard) { candidate in
            Self.passesLuhn(candidate)
        }
        run(Self.awsKeyRegex, .awsKey)
        run(Self.genericApiKeyRegex, .genericApiKey)
        run(Self.ipv4Regex, .ipv4Address)
        run(Self.envSecretRegex, .envSecret)

        if let bulkEnvMatch = scanForBulkEnvFile(text) {
            matches.append(bulkEnvMatch)
        }

        for rule in customRules where rule.isEnabled {
            matches.append(contentsOf: runCustomRule(rule, text: text, ns: ns, full: full))
        }

        return matches
    }

    /// Replaces every redactable match (i.e. every match with a real range --
    /// see `PIIMatch.range`) with a `[REDACTED:<category>]` placeholder and
    /// returns the modified text, for "auto-redact and forward" mode instead
    /// of blocking outright. Matches are applied back-to-front so earlier
    /// ranges stay valid as later ones are replaced, and overlapping matches
    /// (e.g. a custom rule and a built-in rule catching the same substring)
    /// are only replaced once.
    func redactedText(in text: String, matches: [PIIMatch]) -> String {
        let redactable = matches
            .filter { $0.range.location != NSNotFound && $0.range.length > 0 }
            .sorted { $0.range.location > $1.range.location }
        guard !redactable.isEmpty else { return text }

        let mutable = NSMutableString(string: text)
        var handledRanges: [NSRange] = []
        for match in redactable {
            if handledRanges.contains(where: { NSIntersectionRange($0, match.range).length > 0 }) { continue }
            mutable.replaceCharacters(in: match.range, with: "[REDACTED:\(match.categoryName)]")
            handledRanges.append(match.range)
        }
        return mutable as String
    }

    /// Flags a message as an ".env file paste" when it contains several
    /// `NAME=value`-shaped lines together, even if no individual name
    /// contains an obviously sensitive word like "SECRET" or "TOKEN" --
    /// dumping a whole .env file is risky regardless of which keys it holds.
    /// Not tied to one replaceable span, so it can't be auto-redacted --
    /// only blocked.
    private func scanForBulkEnvFile(_ text: String) -> PIIMatch? {
        guard enabledCategories.contains(.envFile) else { return nil }
        var matchingLines = 0
        text.enumerateLines { line, _ in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return }
            let range = NSRange(trimmed.startIndex..., in: trimmed)
            if Self.envLineRegex.firstMatch(in: trimmed, range: range) != nil {
                matchingLines += 1
            }
        }
        guard matchingLines >= 3 else { return nil }
        return PIIMatch(
            categoryName: PIICategory.envFile.displayName,
            redactedPreview: "\(matchingLines) env-style lines",
            range: NSRange(location: NSNotFound, length: 0)
        )
    }

    private func runCustomRule(_ rule: CustomRule, text: String, ns: NSString, full: NSRange) -> [PIIMatch] {
        if rule.isRegex {
            guard let regex = try? NSRegularExpression(pattern: rule.pattern, options: [.caseInsensitive]) else { return [] }
            var found: [PIIMatch] = []
            regex.enumerateMatches(in: text, range: full) { result, _, _ in
                guard let result else { return }
                let matched = ns.substring(with: result.range)
                found.append(PIIMatch(categoryName: rule.label, redactedPreview: Self.redact(matched), range: result.range))
            }
            return found
        } else {
            guard !rule.pattern.isEmpty else { return [] }
            var found: [PIIMatch] = []
            var searchRange = full
            while searchRange.length > 0 {
                let foundRange = ns.range(of: rule.pattern, options: [.caseInsensitive], range: searchRange)
                if foundRange.location == NSNotFound { break }
                let matched = ns.substring(with: foundRange)
                found.append(PIIMatch(categoryName: rule.label, redactedPreview: Self.redact(matched), range: foundRange))
                let nextLocation = foundRange.location + foundRange.length
                searchRange = NSRange(location: nextLocation, length: full.length - nextLocation)
            }
            return found
        }
    }

    private static func redact(_ value: String) -> String {
        guard value.count > 4 else { return String(repeating: "*", count: value.count) }
        let prefix = value.prefix(2)
        let suffix = value.suffix(2)
        return "\(prefix)\(String(repeating: "*", count: max(value.count - 4, 1)))\(suffix)"
    }

    /// Luhn checksum, used to keep the credit-card regex from flagging every
    /// long run of digits (order numbers, phone numbers, timestamps, etc.).
    private static func passesLuhn(_ candidate: String) -> Bool {
        let digits = candidate.filter(\.isNumber).compactMap { $0.wholeNumberValue }
        guard digits.count >= 13 && digits.count <= 19 else { return false }
        var sum = 0
        for (index, digit) in digits.reversed().enumerated() {
            if index % 2 == 1 {
                let doubled = digit * 2
                sum += doubled > 9 ? doubled - 9 : doubled
            } else {
                sum += digit
            }
        }
        return sum % 10 == 0
    }
}
