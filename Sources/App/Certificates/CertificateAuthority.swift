import Foundation
import Crypto
import X509
import SwiftASN1
import Security

enum CertificateAuthorityError: Error {
    case keychainFailure(OSStatus)
    case notInitialized
}

extension CertificateAuthorityError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .keychainFailure(let status):
            let message = (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown reason"
            return "Keychain error \(status): \(message)"
        case .notInitialized:
            return "The local certificate authority has not been created yet."
        }
    }
}

/// Owns the app's local root CA: a self-signed certificate the user installs
/// into System trust once, plus the private key that signs per-host leaf
/// certificates at proxy time. The private key never touches disk directly —
/// it's stored as an opaque secret in the login Keychain (a generic password
/// item, not a "key" class item -- we only ever need the raw bytes back to
/// re-create a software `P256.Signing.PrivateKey` for signing, never a
/// hardware-backed SecKey, so there's no reason to fight Keychain's stricter
/// rules around persisting/reading back EC "key" class items).
final class CertificateAuthority {
    static let commonName = AppIdentity.caCommonName
    private static let keychainService = AppIdentity.bundleIdentifier
    private static let keychainAccount = "ca-private-key"

    private(set) var certificate: Certificate?
    private(set) var privateKey: P256.Signing.PrivateKey?

    var appSupportDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent(AppIdentity.shortName, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    var certificateFileURL: URL {
        appSupportDirectory.appendingPathComponent(AppIdentity.fileName("root-ca.cer"))
    }

    /// Loads an existing CA from the Keychain + disk, or generates a fresh
    /// one on first run.
    func loadOrCreate() throws {
        if let existingKey = try loadPrivateKeyFromKeychain(),
           FileManager.default.fileExists(atPath: certificateFileURL.path),
           let certData = try? Data(contentsOf: certificateFileURL),
           let cert = try? Certificate(derEncoded: [UInt8](certData)) {
            self.privateKey = existingKey
            self.certificate = cert
            return
        }
        try generateAndPersist()
    }

    private func generateAndPersist() throws {
        let key = P256.Signing.PrivateKey()
        let subjectName = try DistinguishedName {
            CommonName(Self.commonName)
            OrganizationName("\(AppIdentity.displayName) (local)")
        }
        let now = Date()
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
            Critical(KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true))
            SubjectKeyIdentifier(hash: Certificate.PublicKey(key.publicKey))
        }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: now.addingTimeInterval(-60 * 60),
            notValidAfter: now.addingTimeInterval(60 * 60 * 24 * 365 * 10),
            issuer: subjectName,
            subject: subjectName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(key)
        )

        try savePrivateKeyToKeychain(key)
        var serializer = DER.Serializer()
        try certificate.serialize(into: &serializer)
        let der = Data(serializer.serializedBytes)
        try der.write(to: certificateFileURL, options: .atomic)

        self.privateKey = key
        self.certificate = certificate
    }

    // MARK: - Keychain storage for the CA private key

    private func savePrivateKeyToKeychain(_ key: P256.Signing.PrivateKey) throws {
        SecItemDelete(Self.keychainQuery as CFDictionary)

        var attributes = Self.keychainQuery
        attributes[kSecValueData] = key.rawRepresentation
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw CertificateAuthorityError.keychainFailure(status) }
    }

    private func loadPrivateKeyFromKeychain() throws -> P256.Signing.PrivateKey? {
        var query = Self.keychainQuery
        query[kSecReturnData] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw CertificateAuthorityError.keychainFailure(status)
        }
        return try P256.Signing.PrivateKey(rawRepresentation: data)
    }

    private static var keychainQuery: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
        ]
    }

    /// Removes the CA key from the Keychain and its certificate file. Does
    /// NOT remove it from System trust — see TrustStoreInstaller for that.
    func destroyLocalMaterial() {
        SecItemDelete(Self.keychainQuery as CFDictionary)
        try? FileManager.default.removeItem(at: certificateFileURL)
        privateKey = nil
        certificate = nil
    }
}
