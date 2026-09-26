import Foundation
import ServiceManagement
import Security

enum HelperClientError: Error {
    case blessFailed(String)
    case connectionFailed
    case helperError(String)
}

extension HelperClientError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .blessFailed(let message): return "Could not install the privileged helper: \(message)"
        case .connectionFailed: return "Could not reach the privileged helper."
        case .helperError(let message): return message
        }
    }
}

/// Talks to the privileged helper tool (see `Sources/PIIGuardHelper`) over
/// XPC, installing ("blessing") it once via `SMJobBless` if it's missing or
/// out of date. That one install is the *only* admin-password prompt --
/// every proxy-toggle and CA-trust operation after that runs through the
/// already-root helper with no further authorization needed.
final class HelperClient {
    private var connection: NSXPCConnection?

    /// Installs the helper if it isn't already present at the current
    /// version. Prompts for admin authorization only in that case.
    func ensureInstalled() throws {
        if let installedVersion = try? currentHelperVersion(), installedVersion == PIIGuardHelperConstants.version {
            return
        }
        try bless()
    }

    private func bless() throws {
        var authRef: AuthorizationRef?
        let status = AuthorizationCreate(nil, nil, [], &authRef)
        guard status == errAuthorizationSuccess, let authRef else {
            throw HelperClientError.blessFailed("Could not create an authorization reference (\(status)).")
        }
        defer { AuthorizationFree(authRef, []) }

        let rightName = kSMRightBlessPrivilegedHelper
        var authItem = AuthorizationItem(name: (rightName as NSString).utf8String!, valueLength: 0, value: nil, flags: 0)
        let status2: OSStatus = withUnsafeMutablePointer(to: &authItem) { itemPtr -> OSStatus in
            var rights = AuthorizationRights(count: 1, items: itemPtr)
            return AuthorizationCopyRights(authRef, &rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], nil)
        }
        guard status2 == errAuthorizationSuccess else {
            if status2 == errAuthorizationCanceled {
                throw HelperClientError.blessFailed("cancelled")
            }
            throw HelperClientError.blessFailed("Authorization was not granted (\(status2)).")
        }

        var cfError: Unmanaged<CFError>?
        let success = SMJobBless(kSMDomainSystemLaunchd, PIIGuardHelperConstants.bundleIdentifier as CFString, authRef, &cfError)
        guard success else {
            let message = cfError.map { ($0.takeRetainedValue() as Error).localizedDescription } ?? "unknown error"
            throw HelperClientError.blessFailed(message)
        }
        // Old connection (if any) points at the now-replaced helper process.
        connection?.invalidate()
        connection = nil
    }

    private func currentHelperVersion() throws -> String {
        try withConnection { proxy, resolve in
            proxy.getVersion { version in resolve(.success(version)) }
        }
    }

    // MARK: - Operations

    func setAutoProxy(service: String, urlString: String?, enabled: Bool) throws {
        try withConnection { proxy, resolve in
            proxy.setAutoProxy(service: service, urlString: urlString, enabled: enabled) { success, error in
                resolve(success ? .success(()) : .failure(HelperClientError.helperError(error ?? "unknown error")))
            }
        }
    }

    func trustCertificate(atPath path: String) throws {
        try withConnection { proxy, resolve in
            proxy.trustCertificate(atPath: path) { success, error in
                resolve(success ? .success(()) : .failure(HelperClientError.helperError(error ?? "unknown error")))
            }
        }
    }

    func removeCertificate(commonName: String) throws {
        try withConnection { proxy, resolve in
            proxy.removeCertificate(commonName: commonName) { success, error in
                resolve(success ? .success(()) : .failure(HelperClientError.helperError(error ?? "unknown error")))
            }
        }
    }

    // MARK: - XPC plumbing

    private func makeConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: PIIGuardHelperConstants.machServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: PIIGuardHelperProtocol.self)
        connection.invalidationHandler = { [weak self] in self?.connection = nil }
        connection.resume()
        return connection
    }

    /// Bridges one XPC call's completion handler to a blocking wait -- fine
    /// here because every caller already runs off the main thread (see
    /// `AppState`'s `Task.detached` blocks).
    private func withConnection<T>(_ body: @escaping (PIIGuardHelperProtocol, @escaping (Result<T, Error>) -> Void) -> Void) throws -> T {
        let connection = self.connection ?? makeConnection()
        self.connection = connection

        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<T, Error> = .failure(HelperClientError.connectionFailed)
        var replied = false

        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            guard !replied else { return }
            replied = true
            result = .failure(error)
            semaphore.signal()
        } as? PIIGuardHelperProtocol

        guard let proxy else { throw HelperClientError.connectionFailed }

        body(proxy) { r in
            guard !replied else { return }
            replied = true
            result = r
            semaphore.signal()
        }

        _ = semaphore.wait(timeout: .now() + 15)
        return try result.get()
    }
}
