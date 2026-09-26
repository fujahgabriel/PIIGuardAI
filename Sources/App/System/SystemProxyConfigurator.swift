import Foundation

/// Points the Mac's network services at a PAC (Proxy Auto-Config) script
/// that sends only known LLM provider domains through the local MITM proxy
/// -- everything else resolves "DIRECT" and never touches this app at all.
enum SystemProxyConfigurator {
    private static let touchedServicesKey = AppIdentity.defaultsKey("proxyConfiguredServices")

    static func pacFileURL(appSupportDirectory: URL) -> URL {
        appSupportDirectory.appendingPathComponent(AppIdentity.fileName("proxy.pac"))
    }

    static func pacScript(proxyPort: UInt16, providers: [ProviderDomain]) -> String {
        let hostList = providers.filter(\.isEnabled).map { "\"\($0.host)\"" }.joined(separator: ", ")
        return """
        function FindProxyForURL(url, host) {
            var protectedHosts = [\(hostList)];
            for (var i = 0; i < protectedHosts.length; i++) {
                if (host == protectedHosts[i] || dnsDomainIs(host, "." + protectedHosts[i])) {
                    return "PROXY 127.0.0.1:\(proxyPort)";
                }
            }
            return "DIRECT";
        }
        """
    }

    /// Writes the PAC script to disk too, purely for reference/debugging --
    /// the *active* config points at `PACFileServer`'s HTTP URL (see below),
    /// not this file, because Chromium-based browsers (Chrome, Arc, Edge)
    /// refuse to fetch PAC scripts from `file://` URLs.
    static func writePACFile(to url: URL, proxyPort: UInt16, providers: [ProviderDomain]) throws {
        try pacScript(proxyPort: proxyPort, providers: providers).write(to: url, atomically: true, encoding: .utf8)
    }

    /// Builds (but does not run) the privileged commands needed to turn the
    /// proxy on, so callers can merge them with other privileged commands
    /// (e.g. trusting the root CA) into a single admin-password prompt.
    static func buildEnableCommands(pacServerURL: URL) throws -> [String] {
        let services = try activeNetworkServices()
        guard !services.isEmpty else { return [] }
        UserDefaults.standard.set(services, forKey: touchedServicesKey)

        var commands: [String] = []
        for service in services {
            commands.append("networksetup -setautoproxyurl \"\(service)\" \"\(pacServerURL.absoluteString)\"")
            commands.append("networksetup -setautoproxystate \"\(service)\" on")
        }
        return commands
    }

    static func buildDisableCommands() -> [String] {
        let services = UserDefaults.standard.stringArray(forKey: touchedServicesKey) ?? []
        guard !services.isEmpty else { return [] }
        UserDefaults.standard.removeObject(forKey: touchedServicesKey)
        return services.map { "networksetup -setautoproxystate \"\($0)\" off" }
    }

    // MARK: - Helper-client path (typed calls, no shell strings)

    /// The network services currently on, so the caller can point each one
    /// at the PAC server via `HelperClient` and remember which it touched.
    static func servicesToEnable() throws -> [String] {
        let services = try activeNetworkServices()
        UserDefaults.standard.set(services, forKey: touchedServicesKey)
        return services
    }

    static func touchedServices() -> [String] {
        UserDefaults.standard.stringArray(forKey: touchedServicesKey) ?? []
    }

    static func clearTouchedServices() {
        UserDefaults.standard.removeObject(forKey: touchedServicesKey)
    }

    private static func activeNetworkServices() throws -> [String] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = ["-listallnetworkservices"]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

        return output
            .components(separatedBy: "\n")
            .dropFirst() // "An asterisk (*) denotes that a network service is disabled."
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("*") }
    }
}
