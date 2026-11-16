package com.otilm.core.certificate.type;

import java.security.PublicKey;
import java.time.Instant;

/**
 * What every certificate type can say about a certificate, whatever its encoding.
 *
 * @param identifier the type's own identifier of the certificate, such as the serial number
 * @param issuerReference how the certificate names its issuer, or null when the type has no such reference
 * @param holder who the certificate was issued to
 * @param validity the validity period with its precision
 * @param publicKey the certified public key
 * @param fingerprint the fingerprint that identifies the certificate content
 */
public record CertificateProperties(String identifier, String issuerReference, String holder, Validity validity,
        PublicKey publicKey, String fingerprint) {

    /** The validity status of the certificate at the moment, which depends on its validity period only. */
    public ValidityStatus statusAt(Instant moment) {
        return validity.statusAt(moment);
    }
}
