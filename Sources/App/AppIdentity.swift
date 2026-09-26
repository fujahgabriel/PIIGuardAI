import Foundation

/// Single source of truth for every name/identifier this app uses --
/// UserDefaults keys, on-disk file names, DispatchQueue labels, the CA's
/// Common Name, and user-facing strings. Anything that used to be a
/// hardcoded "PIIGuard AI" / "PIIGuardAI" / "com.piiguard.app" literal
/// scattered across files should read from here instead, so a future rename
/// is a one-line change, not a grep-and-pray across a dozen files.
///
/// `bundleIdentifier` deliberately reads from `PIIGuardHelperConstants`
/// (shared with the privileged helper target) rather than duplicating the
/// string here -- that's the one place it's genuinely load-bearing (the
/// helper checks it against the calling process's code signature), so it's
/// the right source of truth to defer to.
enum AppIdentity {
    /// User-facing name, e.g. shown in the menu bar and notifications.
    static let displayName = "PIIGuard AI"
    /// No-space variant, used for UserDefaults key prefixes and the
    /// Application Support folder name.
    static let shortName = "PIIGuardAI"
    static let bundleIdentifier = PIIGuardHelperConstants.clientBundleIdentifier
    /// Prefix for on-disk file names this app writes (e.g. "\(filePrefix)-root-ca.cer").
    static let filePrefix = "piiguard"
    static let caCommonName = "\(displayName) Local MITM CA"

    static func defaultsKey(_ suffix: String) -> String { "\(shortName).\(suffix)" }
    static func queueLabel(_ suffix: String) -> String { "\(bundleIdentifier).\(suffix)" }
    static func fileName(_ suffix: String) -> String { "\(filePrefix)-\(suffix)" }
}
