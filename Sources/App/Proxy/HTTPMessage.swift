import Foundation

/// Minimal HTTP/1.1 request-line + header parser, enough to read a CONNECT
/// tunnel request and to pull the body out of a JSON POST so it can be PII
/// scanned. Deliberately not a general-purpose HTTP parser.
///
/// Known limitations:
///  - Headers with duplicate field names: only the last value is kept
///    (Dictionary semantics). Multi-value headers like `Set-Cookie` are not
///    relevant for the outbound request scanning this parser does.
///  - RFC 7230 §3.2.6 obs-fold (header continuation lines starting with
///    leading whitespace) is not handled — practically absent in LLM API
///    traffic.
struct HTTPRequestHead {
    let method: String
    let target: String
    let httpVersion: String
    let headers: [String: String]

    var contentLength: Int? {
        headers["content-length"].flatMap(Int.init)
    }

    var isChunked: Bool {
        (headers["transfer-encoding"] ?? "").lowercased().contains("chunked")
    }

    var host: String? {
        headers["host"]
    }
}

struct HTTPResponseHead {
    let httpVersion: String
    let statusCode: Int
    let statusMessage: String
    let headers: [String: String]

    var contentLength: Int? {
        headers["content-length"].flatMap(Int.init)
    }

    var isChunked: Bool {
        (headers["transfer-encoding"] ?? "").lowercased().contains("chunked")
    }

    var isNoBodyStatus: Bool {
        // RFC 7230 §3.3.3: 1xx, 204, and 304 have no body
        (statusCode >= 100 && statusCode < 200) || statusCode == 204 || statusCode == 304
    }
}

enum HTTPParser {
    /// Parses headers out of `buffer` if a full header block (terminated by
    /// \r\n\r\n) is present. Returns the head and the byte offset where the
    /// body begins, or nil if more data is needed.
    static func parseHead(_ buffer: [UInt8]) -> (head: HTTPRequestHead, bodyOffset: Int)? {
        let terminator: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        guard let range = firstRange(of: terminator, in: buffer) else { return nil }

        let headerBytes = Array(buffer[0..<range.lowerBound])
        guard let headerString = String(bytes: headerBytes, encoding: .utf8) else { return nil }

        let lines = headerString.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.split(separator: " ", maxSplits: 2)
        guard parts.count == 3 else { return nil }

        var headers: [String: String] = [:]
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colonIndex = line.firstIndex(of: ":") else { continue }
            let key = line[line.startIndex..<colonIndex].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colonIndex)...].trimmingCharacters(in: .whitespaces)
            headers[key] = value
        }

        let head = HTTPRequestHead(
            method: String(parts[0]),
            target: String(parts[1]),
            httpVersion: String(parts[2]),
            headers: headers
        )
        return (head, range.upperBound)
    }

    /// Parses HTTP response headers out of `buffer` if a full header block
    /// (terminated by \r\n\r\n) is present.
    static func parseResponseHead(_ buffer: [UInt8]) -> (head: HTTPResponseHead, bodyOffset: Int)? {
        let terminator: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        guard let range = firstRange(of: terminator, in: buffer) else { return nil }

        let headerBytes = Array(buffer[0..<range.lowerBound])
        guard let headerString = String(bytes: headerBytes, encoding: .utf8) else { return nil }

        let lines = headerString.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else { return nil }
        let parts = statusLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2, let code = Int(parts[1]) else { return nil }
        let message = parts.count > 2 ? String(parts[2]) : ""

        var headers: [String: String] = [:]
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colonIndex = line.firstIndex(of: ":") else { continue }
            let key = line[line.startIndex..<colonIndex].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colonIndex)...].trimmingCharacters(in: .whitespaces)
            headers[key] = value
        }

        let head = HTTPResponseHead(
            httpVersion: String(parts[0]),
            statusCode: code,
            statusMessage: message,
            headers: headers
        )
        return (head, range.upperBound)
    }

    /// Splits a "host:port" CONNECT target into its components.
    static func parseConnectTarget(_ target: String) -> (host: String, port: UInt16)? {
        let parts = target.split(separator: ":")
        guard parts.count == 2, let port = UInt16(parts[1]) else { return nil }
        return (String(parts[0]), port)
    }

    /// Finds the first occurrence of `pattern` in `buffer` using a
    /// sliding-window index comparison. This avoids allocating a new Array
    /// slice on every iteration — the previous `Array(buffer[i..<i+n]) ==
    /// pattern` approach was O(n·m) in both time and allocations.
    private static func firstRange(of pattern: [UInt8], in buffer: [UInt8]) -> Range<Int>? {
        guard pattern.count <= buffer.count else { return nil }
        let limit = buffer.count - pattern.count
        outer: for i in 0...limit {
            for j in 0..<pattern.count {
                if buffer[i + j] != pattern[j] { continue outer }
            }
            return i..<(i + pattern.count)
        }
        return nil
    }
}
