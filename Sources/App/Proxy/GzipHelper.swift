import Foundation
#if canImport(zlib)
import zlib
#endif

/// Provides fast, memory-safe gzip and zlib decompression and compression
/// for inspecting and modifying HTTP request/response payloads.
enum GzipHelper {
    /// Decompresses gzip or zlib-compressed data into raw uncompressed bytes.
    /// Returns nil if the data is not valid compressed data.
    static func decompress(_ data: Data) -> Data? {
        guard !data.isEmpty else { return data }
        var stream = z_stream()
        // 32 + MAX_WBITS enables automatic detection and decoding of both gzip (RFC 1952) and zlib (RFC 1950)
        let initStatus = inflateInit2_(&stream, 32 + MAX_WBITS, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard initStatus == Z_OK else { return nil }
        defer { inflateEnd(&stream) }

        var decompressed = Data()
        let bufferSize = 65536
        var buffer = [UInt8](repeating: 0, count: bufferSize)

        return data.withUnsafeBytes { rawPtr -> Data? in
            guard let baseAddr = rawPtr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            stream.next_in = UnsafeMutablePointer<UInt8>(mutating: baseAddr)
            stream.avail_in = uInt(data.count)

            var status = Z_OK
            while status == Z_OK {
                stream.next_out = buffer.withUnsafeMutableBufferPointer { $0.baseAddress }
                stream.avail_out = uInt(bufferSize)

                status = inflate(&stream, Z_NO_FLUSH)
                let bytesWritten = bufferSize - Int(stream.avail_out)
                if bytesWritten > 0 {
                    decompressed.append(buffer, count: bytesWritten)
                }
            }
            return (status == Z_STREAM_END || status == Z_OK) ? decompressed : nil
        }
    }

    /// Compresses uncompressed data into gzip format (RFC 1952).
    static func compress(_ data: Data) -> Data? {
        guard !data.isEmpty else { return data }
        var stream = z_stream()
        // 16 + MAX_WBITS formats output with a gzip header and trailer
        let initStatus = deflateInit2_(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard initStatus == Z_OK else { return nil }
        defer { deflateEnd(&stream) }

        var compressed = Data()
        let bufferSize = 65536
        var buffer = [UInt8](repeating: 0, count: bufferSize)

        return data.withUnsafeBytes { rawPtr -> Data? in
            guard let baseAddr = rawPtr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            stream.next_in = UnsafeMutablePointer<UInt8>(mutating: baseAddr)
            stream.avail_in = uInt(data.count)

            var status = Z_OK
            while status == Z_OK {
                stream.next_out = buffer.withUnsafeMutableBufferPointer { $0.baseAddress }
                stream.avail_out = uInt(bufferSize)

                status = deflate(&stream, Z_FINISH)
                let bytesWritten = bufferSize - Int(stream.avail_out)
                if bytesWritten > 0 {
                    compressed.append(buffer, count: bytesWritten)
                }
            }
            return status == Z_STREAM_END ? compressed : nil
        }
    }
}
