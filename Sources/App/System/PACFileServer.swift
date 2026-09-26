import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Serves the PAC (Proxy Auto-Config) script over plain local HTTP instead
/// of a `file://` URL.
///
/// `networksetup -setautoproxyurl` happily accepts a `file://` URL and
/// `scutil --proxy` will faithfully report it as configured, but Chromium
/// (Chrome, Arc, Edge, Brave, ...) deliberately refuses to fetch PAC scripts
/// from `file://` URLs as a security hardening measure -- it silently falls
/// back to no proxy at all, with no visible error anywhere. Serving the same
/// script over `http://127.0.0.1:<port>/proxy.pac` works identically for
/// every browser, including Safari.
final class PACFileServer {
    let port: UInt16
    private let lock = NSLock()
    private var content = Data()
    private var listenerFD: Int32?
    private var isRunning = false
    private let queue = DispatchQueue(label: "com.piiguard.app.pacserver")

    init(port: UInt16) {
        self.port = port
    }

    func updateContent(_ data: Data) {
        lock.lock(); content = data; lock.unlock()
    }

    func start() throws {
        guard !isRunning else { return }
        let fd = try POSIXSocket.makeLoopbackListener(port: port)
        listenerFD = fd
        isRunning = true
        queue.async { [weak self] in self?.acceptLoop(fd) }
    }

    func stop() {
        isRunning = false
        if let fd = listenerFD {
            shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
        }
        listenerFD = nil
    }

    private func acceptLoop(_ fd: Int32) {
        while isRunning {
            guard let clientFD = try? POSIXSocket.accept(fd) else { continue }
            DispatchQueue.global(qos: .utility).async { [weak self] in self?.respond(clientFD) }
        }
    }

    private func respond(_ clientFD: Int32) {
        defer { Darwin.close(clientFD) }
        _ = try? POSIXSocket.readSome(clientFD, maxLength: 4096)

        lock.lock(); let body = content; lock.unlock()
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var data = head.data(using: .utf8)!
        data.append(body)
        try? POSIXSocket.writeAll(clientFD, data)
    }
}
