package com.otilm.core.service.est.authentication;

import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;

/**
 * The certificate an EST client renews, as the inventory knows it.
 *
 * @param uuid the certificate in the inventory
 * @param fingerprint SHA-256 of the certificate in lower-case hexadecimal
 * @param publicKey the public key of the certificate, as BouncyCastle decodes it
 * @param subjectDn the subject as the inventory stores it
 * @param subjectAlternativeNames the subject alternative names as the inventory stores them
 * @param notBefore the start of the validity
 * @param notAfter the end of the validity
 */
public record EstSourceCertificate(UUID uuid, String fingerprint, PublicKey publicKey, String subjectDn,
        String subjectAlternativeNames, Date notBefore, Date notAfter) {
}
