import Foundation

/// Manages CLI coverage for the local MITM proxy. PAC is only honored by
/// CFNetwork/WebKit; `node`/`python`/`curl` CLIs need HTTP_PROXY + CA bundle.
/// This helper auto-installs a sourceable env file and shell integration so
/// the menubar toggle is enough — no manual `source` step.
enum CLIProxyEnv {
    static func envFileURL(appSupportDirectory: URL) -> URL {
        appSupportDirectory.appendingPathComponent(AppIdentity.fileName("env.sh"))
    }

    static func pemURL(for caCertificateURL: URL) -> URL {
        caCertificateURL.deletingPathExtension().appendingPathExtension("pem")
    }

    /// Ensures a PEM file exists alongside the DER .cer (curl/node need PEM). Best-effort.
    @discardableResult
    static func ensurePEM(for caCertificateURL: URL) -> URL {
        let pem = pemURL(for: caCertificateURL)
        if FileManager.default.fileExists(atPath: pem.path) { return pem }
        if let der = try? Data(contentsOf: caCertificateURL) {
            // DER -> PEM base64 with 64-char lines
            let b64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            let pemBody = "-----BEGIN CERTIFICATE-----\n\(b64)\n-----END CERTIFICATE-----\n"
            try? pemBody.write(to: pem, atomically: true, encoding: .utf8)
            try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pem.path)
        }
        return FileManager.default.fileExists(atPath: pem.path) ? pem : caCertificateURL
    }

    /// Writes enabled env file (proxy ON). Sourced by shell rc.
    @discardableResult
    static func writeEnvFile(appSupportDirectory: URL, proxyPort: UInt16, caCertificateURL: URL) throws -> URL {
        let dir = appSupportDirectory
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = envFileURL(appSupportDirectory: dir)
        let proxy = "http://127.0.0.1:\(proxyPort)"
        let caPEM = ensurePEM(for: caCertificateURL).path
        let content = """
        # \(AppIdentity.displayName) — auto-generated. Do not edit. Managed by the \(AppIdentity.displayName) menu bar app.
        # When protection is ON, CLI traffic (claude code, codex, curl, python) routes via 127.0.0.1:\(proxyPort).
        export HTTP_PROXY="\(proxy)"
        export HTTPS_PROXY="\(proxy)"
        export http_proxy="\(proxy)"
        export https_proxy="\(proxy)"
        export NO_PROXY="localhost,127.0.0.1"
        export no_proxy="localhost,127.0.0.1"
        export NODE_EXTRA_CA_CERTS="\(caPEM)"
        export REQUESTS_CA_BUNDLE="\(caPEM)"
        export CURL_CA_BUNDLE="\(caPEM)"
        export SSL_CERT_FILE="\(caPEM)"
        # Avoid Claude Code 3m first-byte timeout when via local proxy (buffers streaming)
        export CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS="120000"

        """
        try content.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        return url
    }

    /// Writes a disabled file that unsets the vars so new shells don't break when protection is OFF.
    @discardableResult
    static func writeDisabledEnvFile(appSupportDirectory: URL) throws -> URL {
        let dir = appSupportDirectory
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = envFileURL(appSupportDirectory: dir)
        let content = """
        # \(AppIdentity.displayName) — protection is OFF. This file unsets the proxy so CLIs go DIRECT.
        unset HTTP_PROXY; unset HTTPS_PROXY; unset http_proxy; unset https_proxy
        # Keep CA bundle if you still want it, but unset to be clean:
        # unset NODE_EXTRA_CA_CERTS; unset REQUESTS_CA_BUNDLE; unset CURL_CA_BUNDLE; unset SSL_CERT_FILE

        """
        try content.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        return url
    }

    static func removeEnvFile(appSupportDirectory: URL) {
        let url = envFileURL(appSupportDirectory: appSupportDirectory)
        try? FileManager.default.removeItem(at: url)
    }

    static func shellSnippet(appSupportDirectory: URL) -> String {
        let path = envFileURL(appSupportDirectory: appSupportDirectory).path
        let quoted = path.replacingOccurrences(of: "\"", with: "\\\"")
        // Guard so missing file doesn't spam new shells
        return "[ -f \"\(quoted)\" ] && source \"\(quoted)\"  # \(AppIdentity.displayName) CLI proxy (auto)"
    }

    // MARK: - Shell rc auto-install

    private static var rcFileURLs: [URL] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return [
            home.appendingPathComponent(".zshrc"),
            home.appendingPathComponent(".zshenv"),
            home.appendingPathComponent(".bashrc"),
            home.appendingPathComponent(".bash_profile"),
            home.appendingPathComponent(".config/fish/config.fish"),
        ]
    }

    /// Idempotently ensures every existing rc sources the env file. Creates .zshrc if none exist.
    @discardableResult
    static func ensureShellIntegration(appSupportDirectory: URL) -> [URL] {
        let snippet = shellSnippet(appSupportDirectory: appSupportDirectory)
        let marker = envFileURL(appSupportDirectory: appSupportDirectory).path
        var touched: [URL] = []
        let fm = FileManager.default
        let existingRCs = rcFileURLs.filter { fm.fileExists(atPath: $0.path) }
        let targets: [URL] = existingRCs.isEmpty ? [fm.homeDirectoryForCurrentUser.appendingPathComponent(".zshrc")] : existingRCs

        for target in targets {
            do {
                let existing = (try? String(contentsOf: target, encoding: .utf8)) ?? ""
                if existing.contains(marker) { continue }
                // Fish uses different syntax
                let line: String
                if target.path.contains("fish") {
                    line = "\n# Added by \(AppIdentity.displayName) — route CLI AI traffic through local PII proxy\nif test -f \"\(envFileURL(appSupportDirectory: appSupportDirectory).path)\"; source \"\(envFileURL(appSupportDirectory: appSupportDirectory).path)\"; end\n"
                } else {
                    line = "\n# Added by \(AppIdentity.displayName) — route CLI AI traffic through local PII proxy\n\(snippet)\n"
                }
                // Ensure parent dir exists (for fish)
                try fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
                if fm.fileExists(atPath: target.path) {
                    let handle = try FileHandle(forWritingTo: target)
                    handle.seekToEndOfFile()
                    handle.write(line.data(using: .utf8)!)
                    try handle.close()
                } else {
                    try line.write(to: target, atomically: true, encoding: .utf8)
                }
                touched.append(target)
            } catch { continue }
        }
        return touched
    }

    /// Removes the auto-added source line from all rc files. Called on "Remove certificate & reset".
    static func removeShellIntegration(appSupportDirectory: URL) {
        let marker = envFileURL(appSupportDirectory: appSupportDirectory).path
        for url in rcFileURLs {
            guard let content = try? String(contentsOf: url, encoding: .utf8), content.contains(marker) else { continue }
            let filtered = content
                .components(separatedBy: "\n")
                .filter { !$0.contains(marker) && !$0.contains("Added by \(AppIdentity.displayName)") }
                .joined(separator: "\n")
            try? filtered.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    // MARK: - launchctl (GUI apps + new Terminal windows)

    /// Sets HTTP_PROXY etc. for the user's launchd session so GUI apps (VS Code, Cursor)
    /// and *new* Terminal windows pick it up without a shell rc change. Best-effort.
    static func setLaunchctlEnv(proxyPort: UInt16, caCertificateURL: URL) {
        let proxy = "http://127.0.0.1:\(proxyPort)"
        let caPEM = ensurePEM(for: caCertificateURL).path
        let pairs: [(String, String)] = [
            ("HTTP_PROXY", proxy), ("HTTPS_PROXY", proxy),
            ("http_proxy", proxy), ("https_proxy", proxy),
            ("NODE_EXTRA_CA_CERTS", caPEM),
        ]
        for (k, v) in pairs {
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            p.arguments = ["setenv", k, v]; try? p.run(); p.waitUntilExit()
        }
    }

    static func unsetLaunchctlEnv() {
        for k in ["HTTP_PROXY","HTTPS_PROXY","http_proxy","https_proxy","NODE_EXTRA_CA_CERTS"] {
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            p.arguments = ["unsetenv", k]; try? p.run(); p.waitUntilExit()
        }
    }

    static func shellExportPreview(proxyPort: UInt16, caCertificateURL: URL) -> String {
        let proxy = "http://127.0.0.1:\(proxyPort)"
        return "export HTTP_PROXY=\"\(proxy)\" HTTPS_PROXY=\"\(proxy)\" NODE_EXTRA_CA_CERTS=\"\(caCertificateURL.path)\""
    }
}
