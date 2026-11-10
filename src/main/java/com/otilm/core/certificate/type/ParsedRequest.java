package com.otilm.core.certificate.type;

import com.otilm.api.model.core.enums.CertificateRequestFormat;
import java.security.PublicKey;

/**
 * A certificate request read by the handler of its type.
 *
 * @param typeCode the code of the type whose handler read it
 * @param format the format the request was written in
 * @param encoded the request in its binary encoding
 * @param holder who the certificate is requested for
 * @param publicKey the public key to certify
 */
public record ParsedRequest(String typeCode, CertificateRequestFormat format, byte[] encoded, String holder,
        PublicKey publicKey) {
}
