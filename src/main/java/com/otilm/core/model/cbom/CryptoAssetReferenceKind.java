package com.otilm.core.model.cbom;

/**
 * What an asset's reference to another component of the same document names. Stored by constant name, so a new constant
 * needs the migration's CHECK widened.
 */
public enum CryptoAssetReferenceKind {
    /** The public key a certificate certifies. */
    SUBJECT_PUBLIC_KEY,
    /** The algorithm a certificate is signed with. */
    SIGNATURE_ALGORITHM,
    /** An algorithm one of a protocol's cipher suites names. */
    CIPHER_SUITE_ALGORITHM,
    /** The algorithm a key or other cryptographic material is for. */
    ALGORITHM,
    /** An asset a protocol names at the protocol level, outside any cipher suite. */
    PROTOCOL_ALGORITHM,
    /** A key exchange method an IKEv2 proposal offers. */
    KEY_EXCHANGE_TRANSFORM
}
