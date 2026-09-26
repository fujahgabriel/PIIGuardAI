import Foundation
import Security

enum TLSSocketError: Error {
    case socketFailure(String)
    case handshakeFailed(OSStatus)
    case ioFailed(OSStatus)
}

/// Boxes a raw file descriptor so it can be smuggled through SecureTransport's
/// C-callback `SSLConnectionRef` (an opaque `UnsafeRawPointer`).
final class FDBox {
    let fd: Int32
    init(fd: Int32) { self.fd = fd }
}

private func piiguard_sslRead(
    connection: SSLConnectionRef,
    data: UnsafeMutableRawPointer,
    dataLength: UnsafeMutablePointer<Int>
) -> OSStatus {
    let box = Unmanaged<FDBox>.fromOpaque(connection).takeUnretainedValue()
    let requested = dataLength.pointee
    let buffer = data.assumingMemoryBound(to: UInt8.self)
    var totalRead = 0
    while totalRead < requested {
        let n = read(box.fd, buffer + totalRead, requested - totalRead)
        if n > 0 {
            totalRead += n
        } else if n == 0 {
            dataLength.pointee = totalRead
            return OSStatus(errSSLClosedGraceful)
        } else {
            if errno == EINTR { continue }
            dataLength.pointee = totalRead
            return OSStatus(errSecIO)
        }
    }
    dataLength.pointee = totalRead
    return errSecSuccess
}

private func piiguard_sslWrite(
    connection: SSLConnectionRef,
    data: UnsafeRawPointer,
    dataLength: UnsafeMutablePointer<Int>
) -> OSStatus {
    let box = Unmanaged<FDBox>.fromOpaque(connection).takeUnretainedValue()
    let requested = dataLength.pointee
    let buffer = data.assumingMemoryBound(to: UInt8.self)
    var totalWritten = 0
    while totalWritten < requested {
        let n = write(box.fd, buffer + totalWritten, requested - totalWritten)
        if n > 0 {
            totalWritten += n
        } else {
            if errno == EINTR { continue }
            dataLength.pointee = totalWritten
            return OSStatus(errSecIO)
        }
    }
    dataLength.pointee = totalWritten
    return errSecSuccess
}

/// A blocking TLS-over-raw-socket wrapper built on SecureTransport, used for
/// both legs of the MITM proxy:
///  - server role, presenting a per-host leaf identity, on the client-facing
///    socket (this is the leg that needs a plaintext CONNECT exchange before
///    TLS starts on the *same* socket, which `Network.framework` cannot do)
///  - client role, verifying the real certificate chain normally, on the
///    upstream socket to the real provider
final class TLSSocket {
    enum Role {
        case server(identity: SecIdentity)
        case client(sniHostname: String)
    }

    private let box: FDBox
    private var context: SSLContext!

    init(fd: Int32, role: Role) throws {
        self.box = FDBox(fd: fd)
        let protocolSide: SSLProtocolSide = {
            switch role {
            case .server: return .serverSide
            case .client: return .clientSide
            }
        }()
        guard let ctx = SSLCreateContext(nil, protocolSide, .streamType) else {
            throw TLSSocketError.socketFailure("SSLCreateContext failed")
        }
        context = ctx

        SSLSetIOFuncs(context, piiguard_sslRead, piiguard_sslWrite)
        SSLSetConnection(context, Unmanaged.passUnretained(box).toOpaque())
        SSLSetProtocolVersionMin(context, .tlsProtocol12)

        switch role {
        case .server(let identity):
            let status = SSLSetCertificate(context, [identity] as CFArray)
            guard status == errSecSuccess else { throw TLSSocketError.handshakeFailed(status) }
        case .client(let hostname):
            SSLSetPeerDomainName(context, hostname, hostname.utf8.count)
        }
    }

    func handshake() throws {
        var status: OSStatus = errSSLWouldBlock
        while status == errSSLWouldBlock {
            status = SSLHandshake(context)
        }
        guard status == errSecSuccess else {
            throw TLSSocketError.handshakeFailed(status)
        }
    }

    /// Reads up to `maxLength` bytes (may return fewer than that on a short
    /// read from the underlying stream). Returns empty data on clean close.
    func read(maxLength: Int) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: maxLength)
        var processed = 0
        let status = SSLRead(context, &buffer, maxLength, &processed)
        switch status {
        case errSecSuccess, errSSLWouldBlock:
            return Data(buffer[0..<processed])
        case OSStatus(errSSLClosedGraceful), OSStatus(errSSLClosedAbort), OSStatus(errSSLClosedNoNotify):
            return Data(buffer[0..<processed])
        default:
            throw TLSSocketError.ioFailed(status)
        }
    }

    func write(_ data: Data) throws {
        var bytes = [UInt8](data)
        var processed = 0
        while processed < bytes.count {
            var written = 0
            let remaining = bytes.count - processed
            let status = bytes.withUnsafeMutableBufferPointer { ptr -> OSStatus in
                SSLWrite(context, ptr.baseAddress! + processed, remaining, &written)
            }
            guard status == errSecSuccess else { throw TLSSocketError.ioFailed(status) }
            processed += written
        }
    }

    func close() {
        SSLClose(context)
        Darwin.close(box.fd)
    }
}
