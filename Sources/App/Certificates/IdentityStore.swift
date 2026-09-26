import Foundation
import Crypto
import X509
import SwiftASN1
import Security

enum IdentityStoreError: Error {
    case keychainFailure(OSStatus)
    case identityCreationFailed(OSStatus)
    case caNotReady
}

extension IdentityStoreError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .keychainFailure(let status):
            let message = (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown reason"
            return "Keychain error \(status): \(message)"
        case .identityCreationFailed(let status):
            let message = (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown reason"
            return "Could not create a TLS identity (\(status)): \(message)"
        case .caNotReady:
            return "The local certificate authority is not ready yet."
        }
    }
}

/// Issues short-lived, per-hostname leaf certificates signed by the app's
/// local CA, and turns them into `SecIdentity` values the proxy's fake
/// TLS server side can present during the handshake.
///
/// The leaf private key is generated *natively* via `SecKeyCreateRandomKey`
/// (not with swift-crypto + imported via `SecKeyCreateWithData`): on this
/// macOS version, `SecKeyCreateWithData(..., kSecAttrIsPermanent: true, ...)`
/// reports success but the item is never actually queryable again --
/// `SecItemCopyMatching` and `SecIdentityCreateWithCertificate` both then
/// fail with errSecItemNotFound (-25300), regardless of code signing. Keys
/// generated with `SecKeyCreateRandomKey` persist correctly, so we generate
/// the key that way and build the certificate around its public key instead.
final class IdentityStore {
    private let ca: CertificateAuthority
    private var cache: [String: SecIdentity] = [:]
    private let lock = NSLock()

    init(ca: CertificateAuthority) {
        self.ca = ca
    }

    func identity(forHost host: String) throws -> SecIdentity {
        lock.lock()
        defer { lock.unlock() }
        if let cached = cache[host] { return cached }

        let identity = try makeIdentity(forHost: host)
        cache[host] = identity
        return identity
    }

    private func makeIdentity(forHost host: String) throws -> SecIdentity {
        guard let caKey = ca.privateKey, let caCert = ca.certificate else {
            throw IdentityStoreError.caNotReady
        }

        let tag = AppIdentity.queueLabel("leaf.\(host)").data(using: .utf8)!
        let leafPublicKey = try generateLeafKey(tag: tag)

        let subjectName = try DistinguishedName {
            CommonName(host)
            OrganizationName("\(AppIdentity.displayName) (local, per-host)")
        }
        let now = Date()
        let caSubjectKeyID = SubjectKeyIdentifier(hash: Certificate.PublicKey(caKey.publicKey))
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.notCertificateAuthority)
            Critical(KeyUsage(digitalSignature: true, keyEncipherment: true))
            try ExtendedKeyUsage([.serverAuth])
            SubjectAlternativeNames([.dnsName(host)])
            AuthorityKeyIdentifier(keyIdentifier: caSubjectKeyID.keyIdentifier)
        }
        let leafCert = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(leafPublicKey),
            notValidBefore: now.addingTimeInterval(-60 * 60),
            notValidAfter: now.addingTimeInterval(60 * 60 * 24 * 30),
            issuer: caCert.subject,
            subject: subjectName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(caKey)
        )

        var serializer = DER.Serializer()
        try leafCert.serialize(into: &serializer)
        let leafDER = Data(serializer.serializedBytes)

        guard let secCert = SecCertificateCreateWithData(nil, leafDER as CFData) else {
            throw IdentityStoreError.identityCreationFailed(errSecParam)
        }

        var identityRef: SecIdentity?
        let status = SecIdentityCreateWithCertificate(nil, secCert, &identityRef)
        guard status == errSecSuccess, let identityRef else {
            throw IdentityStoreError.identityCreationFailed(status)
        }

        return identityRef
    }

    /// Generates a fresh P-256 private key directly in the Keychain under
    /// `tag` and returns its public key (as a software `P256.Signing.PublicKey`
    /// so it can be embedded in the certificate we build around it).
    private func generateLeafKey(tag: Data) throws -> P256.Signing.PublicKey {
        SecItemDelete([
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ] as CFDictionary)

        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: tag,
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let error {
                throw IdentityStoreError.keychainFailure(OSStatus((error.takeRetainedValue() as Error as NSError).code))
            }
            throw IdentityStoreError.keychainFailure(errSecParam)
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw IdentityStoreError.identityCreationFailed(errSecParam)
        }
        var pubError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &pubError) as Data? else {
            throw IdentityStoreError.identityCreationFailed(errSecParam)
        }
        return try P256.Signing.PublicKey(x963Representation: publicKeyData)
    }

    /// Removes every leaf key this run generated. Call on quit so we don't
    /// accumulate keychain items across restarts.
    func purgeAll() {
        lock.lock()
        defer { lock.unlock() }
        for host in cache.keys {
            let tag = AppIdentity.queueLabel("leaf.\(host)").data(using: .utf8)!
            SecItemDelete([
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: tag,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            ] as CFDictionary)
        }
        cache.removeAll()
    }
}
