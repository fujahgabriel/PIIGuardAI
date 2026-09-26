import Foundation

/// Shared between the main app and the privileged helper tool -- compiled
/// into both targets. Keep this file free of anything that isn't available
/// in a bare command-line tool target (no SwiftUI, no AppKit).
enum PIIGuardHelperConstants {
    static let machServiceName = "com.piiguard.app.helper"
    static let bundleIdentifier = "com.piiguard.app.helper"
    /// Bumped whenever the protocol or helper behavior changes; the app
    /// re-blesses the helper when the installed version doesn't match.
    static let version = "1"
    /// The main app's own identity, used by the helper to verify who's
    /// allowed to connect (defense in depth on top of SMAuthorizedClients,
    /// which only gates installation, not every subsequent XPC call).
    static let clientTeamID = "NBYH83Z3X8"
    static let clientBundleIdentifier = "com.piiguard.app"
}

@objc(PIIGuardHelperProtocol)
protocol PIIGuardHelperProtocol {
    /// Points `service` (a network service name, e.g. "Wi-Fi") at `urlString`
    /// as its PAC URL (if non-nil) and turns its auto-proxy state on/off.
    func setAutoProxy(service: String, urlString: String?, enabled: Bool, withReply reply: @escaping (Bool, String?) -> Void)
    /// `security add-trusted-cert -d -r trustRoot` for the cert at `path`.
    func trustCertificate(atPath path: String, withReply reply: @escaping (Bool, String?) -> Void)
    /// `security delete-certificate -c <commonName>` from the System keychain.
    func removeCertificate(commonName: String, withReply reply: @escaping (Bool, String?) -> Void)
    /// Lets the app detect a stale installed helper and re-bless a newer one.
    func getVersion(withReply reply: @escaping (String) -> Void)
}
