import Foundation
import Security

/// Runs as root (installed as a LaunchDaemon via `SMJobBless`). Everything
/// here executes with root privileges the instant a call comes in over XPC
/// -- no further authorization needed, which is the entire point: the user
/// authorizes installing *this* once, and it handles every future proxy
/// on/off and certificate-trust change without prompting again.
final class HelperService: NSObject, PIIGuardHelperProtocol, NSXPCListenerDelegate {
    private let listener: NSXPCListener

    override init() {
        listener = NSXPCListener(machServiceName: PIIGuardHelperConstants.machServiceName)
        super.init()
        listener.delegate = self
    }

    func run() {
        listener.resume()
        RunLoop.current.run()
    }

    // MARK: - NSXPCListenerDelegate

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        guard Self.isAuthorizedClient(pid: newConnection.processIdentifier) else { return false }
        newConnection.exportedInterface = NSXPCInterface(with: PIIGuardHelperProtocol.self)
        newConnection.exportedObject = self
        newConnection.resume()
        return true
    }

    /// Defense in depth: `SMAuthorizedClients` in Info.plist only gates who
    /// is allowed to *install* this helper. Anything that can reach the Mach
    /// service by name could otherwise open a connection, so every
    /// connection is independently checked against the same code-signing
    /// requirement (real Team ID + bundle identifier), not just at bless time.
    private static func isAuthorizedClient(pid: pid_t) -> Bool {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else {
            return false
        }
        let requirementString = "anchor apple generic and certificate leaf[subject.OU] = \"\(PIIGuardHelperConstants.clientTeamID)\" and identifier \"\(PIIGuardHelperConstants.clientBundleIdentifier)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementString as CFString, [], &requirement) == errSecSuccess, let requirement else {
            return false
        }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    // MARK: - PIIGuardHelperProtocol

    func setAutoProxy(service: String, urlString: String?, enabled: Bool, withReply reply: @escaping (Bool, String?) -> Void) {
        var commands: [[String]] = []
        if let urlString {
            commands.append(["/usr/sbin/networksetup", "-setautoproxyurl", service, urlString])
        }
        commands.append(["/usr/sbin/networksetup", "-setautoproxystate", service, enabled ? "on" : "off"])
        runSequentially(commands, reply: reply)
    }

    func trustCertificate(atPath path: String, withReply reply: @escaping (Bool, String?) -> Void) {
        runSequentially([[
            "/usr/bin/security", "add-trusted-cert", "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain", path,
        ]], reply: reply)
    }

    func removeCertificate(commonName: String, withReply reply: @escaping (Bool, String?) -> Void) {
        runSequentially([[
            "/usr/bin/security", "delete-certificate", "-c", commonName,
            "/Library/Keychains/System.keychain",
        ]], reply: reply)
    }

    func getVersion(withReply reply: @escaping (String) -> Void) {
        reply(PIIGuardHelperConstants.version)
    }

    // MARK: - Process execution

    /// Runs each argv array as its own process (no shell involved, so no
    /// quoting/injection concerns even though every caller is already
    /// verified by code signature).
    private func runSequentially(_ commandsArgv: [[String]], reply: @escaping (Bool, String?) -> Void) {
        for argv in commandsArgv {
            guard let executable = argv.first else { continue }
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = Array(argv.dropFirst())
            let errPipe = Pipe()
            process.standardError = errPipe
            do {
                try process.run()
                process.waitUntilExit()
                if process.terminationStatus != 0 {
                    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
                    let message = String(data: errData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                    reply(false, message?.isEmpty == false ? message : "\(executable) exited with status \(process.terminationStatus)")
                    return
                }
            } catch {
                reply(false, error.localizedDescription)
                return
            }
        }
        reply(true, nil)
    }
}

let service = HelperService()
service.run()
