import Foundation
#if canImport(Darwin)
import Darwin
#endif

enum POSIXSocketError: Error {
    case failed(String, Int32)
}

/// Thin wrappers around BSD sockets. We use raw sockets (rather than
/// Network.framework) for the proxy data path because SecureTransport needs
/// direct read/write access to the file descriptor, and because we need to
/// speak plaintext HTTP CONNECT and *then* start TLS on the same socket --
/// a "STARTTLS" pattern Network.framework's connection/parameters model
/// doesn't support after a connection is already established.
enum POSIXSocket {
    static func makeLoopbackListener(port: UInt16) throws -> Int32 {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { throw POSIXSocketError.failed("socket", errno) }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bindResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                bind(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            Darwin.close(fd)
            throw POSIXSocketError.failed("bind", errno)
        }

        // A real page load (chatgpt.com fires 450+ requests) can burst far
        // more simultaneous connection attempts at this one local port than
        // a typical backlog absorbs, even though each is accepted and handed
        // off almost immediately -- once the kernel's pending-connection
        // queue overflows, it refuses/resets the excess outright, which
        // surfaces in the browser as ERR_PROXY_CONNECTION_FAILED rather than
        // a slow request.
        guard listen(fd, 1024) == 0 else {
            Darwin.close(fd)
            throw POSIXSocketError.failed("listen", errno)
        }
        return fd
    }

    static func accept(_ listenerFD: Int32) throws -> Int32 {
        let clientFD = Darwin.accept(listenerFD, nil, nil)
        guard clientFD >= 0 else { throw POSIXSocketError.failed("accept", errno) }
        var noSigPipe: Int32 = 1
        setsockopt(clientFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        return clientFD
    }

    /// Resolves `host` and connects to the first working address on `port`.
    static func connect(host: String, port: UInt16) throws -> Int32 {
        var hints = addrinfo(
            ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP, ai_addrlen: 0, ai_canonname: nil,
            ai_addr: nil, ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &result)
        guard status == 0, let firstResult = result else {
            throw POSIXSocketError.failed("getaddrinfo(\(host))", status)
        }
        defer { freeaddrinfo(result) }

        var pointer: UnsafeMutablePointer<addrinfo>? = firstResult
        var lastErrno: Int32 = 0
        while let info = pointer {
            let fd = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
            if fd >= 0 {
                let connectResult = Darwin.connect(fd, info.pointee.ai_addr, info.pointee.ai_addrlen)
                if connectResult == 0 {
                    var noSigPipe: Int32 = 1
                    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
                    return fd
                }
                lastErrno = errno
                Darwin.close(fd)
            }
            pointer = info.pointee.ai_next
        }
        throw POSIXSocketError.failed("connect(\(host):\(port))", lastErrno)
    }

    /// Reads plaintext bytes from a not-yet-TLS-wrapped socket (used only for
    /// the initial CONNECT line before the handshake begins).
    static func readSome(_ fd: Int32, maxLength: Int) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: maxLength)
        let n = read(fd, &buffer, maxLength)
        guard n >= 0 else { throw POSIXSocketError.failed("read", errno) }
        return Data(buffer[0..<n])
    }

    static func writeAll(_ fd: Int32, _ data: Data) throws {
        let bytes = [UInt8](data)
        var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeBufferPointer { ptr -> Int in
                write(fd, ptr.baseAddress! + offset, ptr.count - offset)
            }
            guard n > 0 else { throw POSIXSocketError.failed("write", errno) }
            offset += n
        }
    }
}
