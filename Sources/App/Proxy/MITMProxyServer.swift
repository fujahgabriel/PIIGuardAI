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
        stop()
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
        guard let head = parsed?.head else {
            Darwin.close(clientFD); return
        }
        guard head.method.uppercased() == "CONNECT",
              let target = HTTPParser.parseConnectTarget(head.target) else {
            // Non-CONNECT request (e.g. plain HTTP via HTTP_PROXY without a
            // CONNECT tunnel). Return a readable error instead of a silent
            // connection reset so the calling tool can diagnose the problem.
            let response = Self.badRequestResponse()
            _ = try? POSIXSocket.writeAll(clientFD, response)
            Darwin.close(clientFD); return
        }

        let established = "HTTP/1.1 200 Connection Established\r\n\r\n".data(using: .utf8)!
        guard (try? POSIXSocket.writeAll(clientFD, established)) != nil else {
            Darwin.close(clientFD); return
        }

        let host = target.host
        NSLog("%@", "[PIIGuardProxy] CONNECT tunnel to \(target.host):\(target.port)")
        guard let identity = try? identityStore.identity(forHost: host) else {
            NSLog("%@", "[PIIGuardProxy] FAILED to get identity for \(host)")
            Darwin.close(clientFD); return
        }
        guard let clientTLS = try? TLSSocket(fd: clientFD, role: .server(identity: identity)) else {
            NSLog("%@", "[PIIGuardProxy] FAILED to create server TLSSocket for \(host)")
            Darwin.close(clientFD); return
        }
        do {
            try clientTLS.handshake()
            NSLog("%@", "[PIIGuardProxy] Client TLS handshake SUCCEEDED for \(host)")
        } catch {
            NSLog("%@", "[PIIGuardProxy] Client TLS handshake FAILED for \(host): \(error)")
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
        let (head, body): (HTTPRequestHead, Data?)
        do {
            guard let req = try readFullClientRequest(clientTLS) else {
                NSLog("%@", "[PIIGuardProxy] readFullClientRequest returned nil for \(host)")
                return false
            }
            (head, body) = req
        } catch {
            NSLog("%@", "[PIIGuardProxy] readFullClientRequest threw for \(host): \(error)")
            return false
        }
        NSLog("%@", "[PIIGuardProxy] Request: \(head.method) https://\(host)\(head.target)")

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
            let detectionPreviews = matches
                .sorted { $0.categoryName < $1.categoryName }
                .map { "\($0.categoryName): \($0.redactedPreview)" }
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

    private func forward(head: HTTPRequestHead, body: Data?, host: String, providerName: String, port: UInt16, clientTLS: TLSSocket, notifyOutcome: TrafficEvent.Outcome? = nil) -> Bool {
        let isWebSocket = head.headers["upgrade"]?.lowercased() == "websocket"
        let forwardRequest = Self.buildForwardedRequest(head: head, body: body)

        guard let upstreamFD = try? POSIXSocket.connect(host: host, port: port) else {
            NSLog("%@", "[PIIGuardProxy] POSIXSocket.connect FAILED for \(host):\(port)")
            try? clientTLS.write(Self.upstreamErrorResponse())
            return false
        }
        guard let upstreamTLS = try? TLSSocket(fd: upstreamFD, role: .client(sniHostname: host)) else {
            NSLog("%@", "[PIIGuardProxy] TLSSocket creation FAILED for \(host)")
            Darwin.close(upstreamFD)
            try? clientTLS.write(Self.upstreamErrorResponse())
            return false
        }
        do {
            try upstreamTLS.handshake()
        } catch {
            NSLog("%@", "[PIIGuardProxy] upstreamTLS.handshake FAILED for \(host): \(error)")
            upstreamTLS.close()
            try? clientTLS.write(Self.upstreamErrorResponse())
            return false
        }
        defer { upstreamTLS.close() }

        do {
            try upstreamTLS.write(forwardRequest)
        } catch {
            NSLog("%@", "[PIIGuardProxy] upstreamTLS.write FAILED for \(host): \(error)")
            return false
        }

        if let notifyOutcome {
            notify(host: host, providerName: providerName, outcome: notifyOutcome, categories: [])
        }

        NSLog("%@", "[PIIGuardProxy] Relay starting: \(head.method) https://\(host)\(head.target)")
        if isWebSocket {
            relayBidirectional(clientTLS, upstreamTLS)
        } else {
            relay(from: upstreamTLS, to: clientTLS, isHead: head.method.uppercased() == "HEAD")
        }
        NSLog("%@", "[PIIGuardProxy] Relay finished: \(head.method) https://\(host)\(head.target)")
        return false
    }

    private func relay(from source: TLSSocket, to destination: TLSSocket, isHead: Bool = false) {
        var headerBuffer = Data()
        var responseHead: HTTPResponseHead?
        var bodyBytesRelayed = 0
        var expectedContentLength: Int?
        var isChunked = false
        var isNoBody = false

        while true {
            guard let chunk = try? source.read(maxLength: 8192), !chunk.isEmpty else {
                NSLog("%@", "[PIIGuardProxy] source.read returned empty/closed (relayed \(bodyBytesRelayed) bytes)")
                break
            }

            if responseHead == nil {
                headerBuffer.append(chunk)
                if let (parsed, bodyOffset) = HTTPParser.parseResponseHead([UInt8](headerBuffer)) {
                    responseHead = parsed
                    expectedContentLength = parsed.contentLength
                    isChunked = parsed.isChunked
                    isNoBody = isHead || parsed.isNoBodyStatus
                    NSLog("%@", "[PIIGuardProxy] Response status: \(parsed.statusCode), contentLength: \(String(describing: parsed.contentLength)), chunked: \(isChunked), noBody: \(isNoBody)")

                    let (rewrittenHeaders, trailingBody) = prepareResponseHeaders(headerBuffer, head: parsed, bodyOffset: bodyOffset)
                    do {
                        try destination.write(rewrittenHeaders)
                    } catch {
                        NSLog("%@", "[PIIGuardProxy] destination.write headers FAILED: \(error)")
                        break
                    }

                    if isNoBody {
                        NSLog("%@", "[PIIGuardProxy] Response has no body, relay complete")
                        break
                    }

                    if !trailingBody.isEmpty {
                        do {
                            try destination.write(trailingBody)
                        } catch {
                            NSLog("%@", "[PIIGuardProxy] destination.write trailingBody FAILED: \(error)")
                            break
                        }
                        bodyBytesRelayed += trailingBody.count

                        if let expected = expectedContentLength, bodyBytesRelayed >= expected {
                            NSLog("%@", "[PIIGuardProxy] Content-Length reached in initial buffer: \(bodyBytesRelayed)/\(expected)")
                            break
                        }
                        if isChunked, hasTerminalChunk(in: trailingBody) {
                            NSLog("%@", "[PIIGuardProxy] Terminal chunk found in initial buffer")
                            break
                        }
                    }
                    headerBuffer.removeAll()
                    continue
                }
                if headerBuffer.count > 1_000_000 { break }
                continue
            }

            // Headers were already sent; relay this body chunk directly
            do {
                try destination.write(chunk)
            } catch {
                NSLog("%@", "[PIIGuardProxy] destination.write body chunk FAILED: \(error)")
                break
            }
            bodyBytesRelayed += chunk.count

            if let expected = expectedContentLength, bodyBytesRelayed >= expected {
                NSLog("%@", "[PIIGuardProxy] Content-Length reached: \(bodyBytesRelayed)/\(expected)")
                break
            }
            if isChunked, hasTerminalChunk(in: chunk) {
                NSLog("%@", "[PIIGuardProxy] Terminal chunk reached")
                break
            }
        }
    }

    private func prepareResponseHeaders(_ data: Data, head: HTTPResponseHead, bodyOffset: Int) -> (headers: Data, trailingBody: Data) {
        let rawHeaderData = data.subdata(in: data.startIndex..<bodyOffset)
        let trailingBody = data.subdata(in: bodyOffset..<data.endIndex)

        guard let headerString = String(data: rawHeaderData, encoding: .utf8) else {
            return (rawHeaderData, trailingBody)
        }

        let lines = headerString.components(separatedBy: "\r\n")
        var filteredLines: [String] = []
        for line in lines {
            let lower = line.lowercased()
            // Strip Alt-Svc so browsers don't try HTTP/3
            if lower.hasPrefix("alt-svc:") { continue }
            // Replace keep-alive Connection header with close so client knows connection terminates
            if lower.hasPrefix("connection:") || lower.hasPrefix("proxy-connection:") { continue }
            if !line.isEmpty {
                filteredLines.append(line)
            }
        }
        filteredLines.append("Connection: close")

        let newHeaderString = filteredLines.joined(separator: "\r\n") + "\r\n\r\n"
        let newHeaderData = newHeaderString.data(using: .utf8) ?? rawHeaderData
        return (newHeaderData, trailingBody)
    }

    private func hasTerminalChunk(in data: Data) -> Bool {
        let terminalWithPrefix = Data([0x0D, 0x0A, 0x30, 0x0D, 0x0A, 0x0D, 0x0A]) // \r\n0\r\n\r\n
        let terminalAlone = Data([0x30, 0x0D, 0x0A, 0x0D, 0x0A]) // 0\r\n\r\n
        return data.range(of: terminalWithPrefix) != nil || data.range(of: terminalAlone) != nil
    }

    private func relayBidirectional(_ a: TLSSocket, _ b: TLSSocket) {
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            while true {
                guard let chunk = try? a.read(maxLength: 8192), !chunk.isEmpty else { break }
                guard (try? b.write(chunk)) != nil else { break }
            }
            b.close()
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            while true {
                guard let chunk = try? b.read(maxLength: 8192), !chunk.isEmpty else { break }
                guard (try? a.write(chunk)) != nil else { break }
            }
            a.close()
            group.leave()
        }
        group.wait()
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
            guard buffer.count >= bodyOffset + contentLength else { return nil }
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
        let isWebSocket = head.headers["upgrade"]?.lowercased() == "websocket"
        let stripped = isWebSocket ?
            ["proxy-connection", "content-length", "transfer-encoding"] :
            ["connection", "proxy-connection", "content-length", "transfer-encoding"]
        for (key, value) in head.headers where !stripped.contains(key) {
            lines.append("\(key): \(value)")
        }
        if isWebSocket {
            if head.headers["connection"] == nil {
                lines.append("connection: Upgrade")
            }
        } else {
            lines.append("connection: close")
        }
        if let body, !body.isEmpty {
            lines.append("content-length: \(body.count)")
        }
        var data = (lines.joined(separator: "\r\n") + "\r\n\r\n").data(using: .utf8)!
        if let body { data.append(body) }
        return data
    }

    private static func blockedResponse(categories: [String]) -> Data {
        let names = categories.joined(separator: ", ")
        let json = "{\"error\":{\"type\":\"piiguard_blocked\",\"message\":\"\(AppIdentity.displayName) blocked this message: detected \(names).\"}}"
        return httpResponse(status: "403 Forbidden", contentType: "application/json", body: json)
    }

    private static func badRequestResponse() -> Data {
        let json = "{\"error\":{\"type\":\"piiguard_bad_request\",\"message\":\"\(AppIdentity.displayName) proxy only handles CONNECT tunnels. Configure your client to use HTTPS_PROXY, not HTTP_PROXY, for direct (non-tunnel) requests.\"}}"
        return httpResponse(status: "400 Bad Request", contentType: "application/json", body: json)
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
