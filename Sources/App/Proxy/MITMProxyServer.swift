import Foundation
#if canImport(Darwin)
import Darwin
#endif

protocol MITMProxyServerDelegate: AnyObject {
    func proxyServer(_ server: MITMProxyServer, didRecord event: TrafficEvent)
}

/// A local forward proxy that terminates TLS for connections tunneled to it
/// (via CONNECT, as configured by the PAC file / system proxy settings),
/// scans request bodies for PII, and either blocks or forwards them to the
/// real provider.
///
/// Design notes / known limitations:
///  - Only requests with a `Content-Length` body or a decodable
///    `Transfer-Encoding: chunked` body are scanned. Anything else (e.g. a
///    compressed body) is allowed through and reported as "unscanned".
///  - Every forwarded request opens a fresh upstream connection with
///    `Connection: close`, trading a little latency for a proxy that never
///    has to guess where a keep-alive response ends.
final class MITMProxyServer {
    let port: UInt16
    private let identityStore: IdentityStore

    private let stateLock = NSLock()
    private var detector: PIIDetector
    private var providers: [ProviderDomain]
    private var blockingEnabled: Bool
    private var autoRedactEnabled: Bool = false
    var debugBodyLogger: ((String, String, [String], Data?) -> Void)?

    weak var delegate: MITMProxyServerDelegate?

    private var listenerFD: Int32?
    private let acceptQueue = DispatchQueue(label: AppIdentity.queueLabel("proxy.accept"))
    private var isRunning = false

    init(port: UInt16, identityStore: IdentityStore, detector: PIIDetector, providers: [ProviderDomain], blockingEnabled: Bool = true) {
        self.port = port
        self.identityStore = identityStore
        self.detector = detector
        self.providers = providers
        self.blockingEnabled = blockingEnabled
    }

    func updateProviders(_ providers: [ProviderDomain]) {
        stateLock.lock(); self.providers = providers; stateLock.unlock()
    }

    func updateDetector(_ detector: PIIDetector) {
        stateLock.lock(); self.detector = detector; stateLock.unlock()
    }

    func setBlockingEnabled(_ enabled: Bool) {
        stateLock.lock(); self.blockingEnabled = enabled; stateLock.unlock()
    }

    /// When enabled, a message with PII gets the offending substrings
    /// replaced with `[REDACTED:<category>]` and is still forwarded, instead
    /// of being blocked outright. Falls back to blocking for matches that
    /// aren't tied to a specific replaceable span (e.g. the bulk ".env file"
    /// heuristic), since there's nothing sensible to redact there.
    func setAutoRedactEnabled(_ enabled: Bool) {
        stateLock.lock(); self.autoRedactEnabled = enabled; stateLock.unlock()
    }

    func start() throws {
        guard !isRunning else { return }
        Self.raiseFileDescriptorLimit()
        let fd = try POSIXSocket.makeLoopbackListener(port: port)
        listenerFD = fd
        isRunning = true
        acceptQueue.async { [weak self] in self?.acceptLoop(fd) }
    }

    /// The default per-process fd limit inherited from launchd (256 on this
    /// Mac) is nowhere near enough: every proxied request holds 2 fds
    /// (client + upstream socket) for its whole lifetime, and a single real
    /// page load easily has 100+ requests in flight at once (chatgpt.com's
    /// web app fires 450+ requests on load). Past the limit, new connections
    /// fail immediately (EMFILE) rather than queueing -- indistinguishable
    /// from the page randomly failing some requests. Raise it once at
    /// startup, capped at the process's actual hard ceiling.
    private static func raiseFileDescriptorLimit(target: UInt64 = 10240) {
        var limit = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limit) == 0 else { return }
        let newLimit = min(target, limit.rlim_max)
        guard newLimit > limit.rlim_cur else { return }
        limit.rlim_cur = newLimit
        setrlimit(RLIMIT_NOFILE, &limit)
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
            guard let clientFD = try? POSIXSocket.accept(fd) else {
                continue
            }
            // A dedicated Thread, not DispatchQueue.global(): handleConnection
            // blocks synchronously for the connection's entire lifetime,
            // including long-lived SSE relays held open for minutes (see
            // relay()'s comment). GCD's global concurrent queue has a finite
            // worker-thread pool not meant for indefinitely-blocking work --
            // enough simultaneous SSE/long-poll connections (an ordinary
            // chatgpt.com/claude.ai page load generates many) saturate it and
            // every subsequent connection queues forever, which is
            // indistinguishable from the page just hanging.
            let thread = Thread { [weak self] in
                self?.handleConnection(clientFD)
            }
            thread.stackSize = 256 * 1024
            thread.start()
        }
    }

    // MARK: - Per-connection handling

    private func handleConnection(_ clientFD: Int32) {
        var buffer = Data()
        var parsed: (head: HTTPRequestHead, bodyOffset: Int)?
        while parsed == nil {
            guard let chunk = try? POSIXSocket.readSome(clientFD, maxLength: 4096), !chunk.isEmpty else {
                Darwin.close(clientFD); return
            }
            buffer.append(chunk)
            parsed = HTTPParser.parseHead([UInt8](buffer))
            if buffer.count > 65536 { Darwin.close(clientFD); return }
        }
        guard let head = parsed?.head, head.method.uppercased() == "CONNECT",
              let target = HTTPParser.parseConnectTarget(head.target) else {
            Darwin.close(clientFD); return
        }

        let established = "HTTP/1.1 200 Connection Established\r\n\r\n".data(using: .utf8)!
        guard (try? POSIXSocket.writeAll(clientFD, established)) != nil else {
            Darwin.close(clientFD); return
        }

        let host = target.host
        guard let identity = try? identityStore.identity(forHost: host) else {
            Darwin.close(clientFD); return
        }
        guard let clientTLS = try? TLSSocket(fd: clientFD, role: .server(identity: identity)) else {
            Darwin.close(clientFD); return
        }
        do {
            try clientTLS.handshake()
        } catch {
            clientTLS.close()
            return
        }
        defer { clientTLS.close() }

        stateLock.lock()
        let matchedProvider = providers.first(where: { $0.isEnabled && $0.matches(host) })
        let providerName = matchedProvider?.providerName ?? host
        let isProviderHost = matchedProvider != nil
        stateLock.unlock()

        while serveOneExchange(host: host, providerName: providerName, isProviderHost: isProviderHost, port: target.port, clientTLS: clientTLS) {}
    }

    /// Reads one request, scans it, forwards or blocks it, relays the
    /// response, and returns whether the client tunnel should stay open for
    /// another request.
    private func serveOneExchange(host: String, providerName: String, isProviderHost: Bool, port: UInt16, clientTLS: TLSSocket) -> Bool {
        guard let (head, body) = try? readFullClientRequest(clientTLS) else {
            return false
        }

        // Only scan LLM provider traffic. When via HTTP_PROXY (CLI env) everything
        // hits the proxy, but scanning datadog/downloads/mcp-proxy creates false
        // positives like "credit card" on trace IDs.
        if !isProviderHost {
            return forward(head: head, body: body, host: host, providerName: providerName, port: port, clientTLS: clientTLS, notifyOutcome: .allowed)
        }

        stateLock.lock()
        let currentDetector = detector
        let currentlyBlocking = blockingEnabled
        let currentlyAutoRedacting = autoRedactEnabled
        let logger = debugBodyLogger
        stateLock.unlock()

        var matches: [PIIMatch] = []
        var scanned = true
        var bodyText: String?
        if let body, let text = String(data: body, encoding: .utf8) {
            bodyText = text
            matches = currentDetector.scan(text)
        } else if head.contentLength.map({ $0 > 0 }) == true || head.isChunked {
            scanned = false
        }

        var effectiveBody = body

        if !matches.isEmpty {
            let categories = Array(Set(matches.map(\.categoryName))).sorted()
            // "<category>: <redacted preview>" per match, e.g. "email address: jo***te" --
            // never the raw matched text (see TrafficEvent's doc comment).
            let detectionPreviews = matches
                .sorted { $0.categoryName < $1.categoryName }
                .map { "\($0.categoryName): \($0.redactedPreview)" }
            // Opt-in raw body log for false-positive diagnosis (0600, truncated)
            logger?(host, providerName, categories, body)

            let allRedactable = matches.allSatisfy { $0.range.location != NSNotFound && $0.range.length > 0 }
            if currentlyAutoRedacting, allRedactable, let bodyText {
                effectiveBody = Data(currentDetector.redactedText(in: bodyText, matches: matches).utf8)
                notify(host: host, providerName: providerName, outcome: .redacted, categories: categories, detectionPreviews: detectionPreviews)
                return forward(head: head, body: effectiveBody, host: host, providerName: providerName, port: port, clientTLS: clientTLS)
            } else if currentlyBlocking {
                try? clientTLS.write(Self.blockedResponse(categories: categories))
                notify(host: host, providerName: providerName, outcome: .blocked, categories: categories, detectionPreviews: detectionPreviews)
                return false
            }
        }

        return forward(head: head, body: effectiveBody, host: host, providerName: providerName, port: port, clientTLS: clientTLS, notifyOutcome: scanned ? .allowed : .allowedUnscanned)
    }

    /// Connects upstream, sends `body`, relays the response back, and
    /// returns whether the client tunnel should stay open for another
    /// request. `notifyOutcome` is skipped when the caller already recorded
    /// its own event (the redact path logs `.redacted` before calling this).
    private func forward(head: HTTPRequestHead, body: Data?, host: String, providerName: String, port: UInt16, clientTLS: TLSSocket, notifyOutcome: TrafficEvent.Outcome? = nil) -> Bool {
        let forwardRequest = Self.buildForwardedRequest(head: head, body: body)

        guard let upstreamFD = try? POSIXSocket.connect(host: host, port: port) else {
            try? clientTLS.write(Self.upstreamErrorResponse())
            return false
        }
        guard let upstreamTLS = try? TLSSocket(fd: upstreamFD, role: .client(sniHostname: host)) else {
            Darwin.close(upstreamFD)
            try? clientTLS.write(Self.upstreamErrorResponse())
            return false
        }
        do {
            try upstreamTLS.handshake()
        } catch {
            upstreamTLS.close()
            try? clientTLS.write(Self.upstreamErrorResponse())
            return false
        }
        defer { upstreamTLS.close() }

        guard (try? upstreamTLS.write(forwardRequest)) != nil else { return false }

        if let notifyOutcome {
            notify(host: host, providerName: providerName, outcome: notifyOutcome, categories: [])
        }

        relay(from: upstreamTLS, to: clientTLS)
        return head.headers["connection"]?.lowercased() != "close"
    }

    private func relay(from source: TLSSocket, to destination: TLSSocket) {
        // Use small reads to avoid buffering the SSE stream (Claude Code 3m timeout)
        while true {
            guard let chunk = try? source.read(maxLength: 8192), !chunk.isEmpty else { break }
            guard (try? destination.write(chunk)) != nil else { break }
        }
    }

    private func notify(host: String, providerName: String, outcome: TrafficEvent.Outcome, categories: [String], detectionPreviews: [String] = []) {
        let event = TrafficEvent(date: Date(), host: host, providerName: providerName, outcome: outcome, matchedCategories: categories, detectionPreviews: detectionPreviews)
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.delegate?.proxyServer(self, didRecord: event)
        }
    }

    // MARK: - Request reading

    private func readFullClientRequest(_ tls: TLSSocket) throws -> (HTTPRequestHead, Data?)? {
        var buffer = Data()
        var headInfo: (head: HTTPRequestHead, bodyOffset: Int)?
        while headInfo == nil {
            let chunk = try tls.read(maxLength: 8192)
            if chunk.isEmpty { return nil }
            buffer.append(chunk)
            headInfo = HTTPParser.parseHead([UInt8](buffer))
            if buffer.count > 1_000_000 { return nil }
        }
        guard let (head, bodyOffset) = headInfo else { return nil }

        if let contentLength = head.contentLength, contentLength > 0 {
            while buffer.count < bodyOffset + contentLength {
                let chunk = try tls.read(maxLength: 32768)
                if chunk.isEmpty { break }
                buffer.append(chunk)
            }
            guard buffer.count >= bodyOffset + contentLength else { return (head, nil) }
            let body = buffer.subdata(in: bodyOffset..<(bodyOffset + contentLength))
            return (head, body)
        } else if head.isChunked {
            let seed = buffer.subdata(in: bodyOffset..<buffer.count)
            let body = try readChunkedBody(tls, seed: seed)
            return (head, body)
        } else {
            return (head, nil)
        }
    }

    private func readChunkedBody(_ tls: TLSSocket, seed: Data) throws -> Data {
        var leftover = seed
        var decoded = Data()

        func fill(_ minimum: Int) throws {
            while leftover.count < minimum {
                let chunk = try tls.read(maxLength: 8192)
                if chunk.isEmpty { return }
                leftover.append(chunk)
            }
        }

        func readLine() throws -> String? {
            while true {
                if let range = leftover.range(of: Data([0x0D, 0x0A])) {
                    let lineData = leftover.subdata(in: leftover.startIndex..<range.lowerBound)
                    leftover.removeSubrange(leftover.startIndex..<range.upperBound)
                    return String(data: lineData, encoding: .utf8)
                }
                let before = leftover.count
                try fill(before + 8192)
                if leftover.count == before { return nil }
            }
        }

        while true {
            guard let sizeLine = try readLine() else { break }
            let sizeToken = sizeLine.split(separator: ";").first.map(String.init) ?? sizeLine
            guard let size = Int(sizeToken.trimmingCharacters(in: .whitespaces), radix: 16) else { break }
            if size == 0 {
                _ = try? readLine()
                break
            }
            try fill(size + 2)
            guard leftover.count >= size else { break }
            decoded.append(leftover.subdata(in: leftover.startIndex..<leftover.index(leftover.startIndex, offsetBy: size)))
            leftover.removeSubrange(leftover.startIndex..<leftover.index(leftover.startIndex, offsetBy: size))
            _ = try? readLine() // trailing CRLF after the chunk data
            if decoded.count > 20_000_000 { break }
        }
        return decoded
    }

    // MARK: - Message construction

    private static func buildForwardedRequest(head: HTTPRequestHead, body: Data?) -> Data {
        var lines = ["\(head.method) \(head.target) \(head.httpVersion)"]
        for (key, value) in head.headers where !["connection", "proxy-connection", "content-length", "transfer-encoding"].contains(key) {
            lines.append("\(key): \(value)")
        }
        if let body, !body.isEmpty {
            lines.append("content-length: \(body.count)")
        }
        lines.append("connection: close")
        var data = (lines.joined(separator: "\r\n") + "\r\n\r\n").data(using: .utf8)!
        if let body { data.append(body) }
        return data
    }

    private static func blockedResponse(categories: [String]) -> Data {
        let names = categories.joined(separator: ", ")
        let json = "{\"error\":{\"type\":\"piiguard_blocked\",\"message\":\"\(AppIdentity.displayName) blocked this message: detected \(names).\"}}"
        return httpResponse(status: "403 Forbidden", contentType: "application/json", body: json)
    }

    private static func upstreamErrorResponse() -> Data {
        let json = "{\"error\":{\"type\":\"piiguard_upstream_error\",\"message\":\"\(AppIdentity.displayName) could not reach the provider.\"}}"
        return httpResponse(status: "502 Bad Gateway", contentType: "application/json", body: json)
    }

    private static func httpResponse(status: String, contentType: String, body: String) -> Data {
        let bodyData = body.data(using: .utf8)!
        let head = "HTTP/1.1 \(status)\r\nContent-Type: \(contentType)\r\nContent-Length: \(bodyData.count)\r\nConnection: close\r\n\r\n"
        var data = head.data(using: .utf8)!
        data.append(bodyData)
        return data
    }
}
