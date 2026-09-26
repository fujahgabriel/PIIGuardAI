import Foundation

/// Installs / removes the app's root CA certificate as a trusted root in the
/// current user's login keychain, via `security(1)`.
///
/// Deliberately targets the *login* keychain, not the System keychain:
/// `SecTrustSettingsSetTrustSettings` for the System/admin domain requires a
/// genuine interactive Authorization Services approval every time, even from
/// a process already running as root (confirmed empirically -- both the
/// privileged helper, a real root LaunchDaemon, and an `osascript`-elevated
/// shell fail identically with "authorization was denied since no user
/// interaction was possible" from a headless launch context). The login
/// keychain is owned outright by the current user, so trust changes there
/// need no elevation and no interactive prompt at all -- which also matches
/// this app's documented personal/single-Mac scope (browsers and CLI tools
/// both consult the login keychain as part of the default trust store).
enum TrustStoreInstaller {
    private static var loginKeychainPath: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Keychains/login.keychain-db").path
    }

    /// True only when the cert actually carries trust settings, not merely
    /// when a cert *item* with this name exists in the keychain (a cert can
    /// persist with its trust settings stripped out-of-band, which
    /// `find-certificate` alone can't distinguish from "genuinely trusted").
    /// `dump-trust-settings` (no `-d`, i.e. the user domain) lists a cert
    /// only once it actually carries trust settings, so a substring match on
    /// its output is a reliable, if blunt, signal.
    static func isInstalled(commonName: String = CertificateAuthority.commonName) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["dump-trust-settings"]
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = Pipe()
        do {
            try process.run()
            let data = outPipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0, let output = String(data: data, encoding: .utf8) else { return false }
            return output.contains(commonName)
        } catch {
            return false
        }
    }

    /// Adding an already-trusted cert again still triggers a fresh Touch
    /// ID/password prompt (`security`'s own "Certificate Trust Settings"
    /// confirmation), so this only actually runs `add-trusted-cert` the
    /// first time -- callers can invoke this unconditionally on every
    /// protection start without re-prompting.
    static func install(certificateAt certificateURL: URL) throws {
        guard !isInstalled() else { return }
        try run(["add-trusted-cert", "-r", "trustRoot", "-k", loginKeychainPath, certificateURL.path])
    }

    static func remove(commonName: String = CertificateAuthority.commonName) throws {
        try run(["delete-certificate", "-c", commonName, loginKeychainPath])
    }

    private static func run(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = arguments
        let errorPipe = Pipe()
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let message = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw PrivilegedRunnerError.scriptFailed(message?.isEmpty == false ? message! : "security exited with status \(process.terminationStatus)")
        }
    }
}
