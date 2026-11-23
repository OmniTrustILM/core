package com.otilm.core.certificate.type;

import com.otilm.api.model.core.enums.CertificateRequestFormat;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * A certificate request read by the handler of its type.
 *
 * @param typeCode the code of the type whose handler read it
 * @param format the format the request was written in
 * @param encoded the request in its binary encoding
 * @param holder who the certificate is requested for
 * @param publicKey the public key to certify, or null when a request read in a named format carries a key that cannot
 * be decoded
 */
public record ParsedRequest(String typeCode, CertificateRequestFormat format, byte[] encoded, String holder,
        PublicKey publicKey) {

    @Override
    public boolean equals(Object other) {
        return other instanceof ParsedRequest(String otherTypeCode, CertificateRequestFormat otherFormat, byte[] otherEncoded, String otherHolder, PublicKey otherPublicKey)
                && Objects.equals(typeCode, otherTypeCode) && format == otherFormat
                && Arrays.equals(encoded, otherEncoded) && Objects.equals(holder, otherHolder)
                && Objects.equals(publicKey, otherPublicKey);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(typeCode, format, holder, publicKey) + Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "ParsedRequest[typeCode=" + typeCode + ", format=" + format + ", encoded=" + encoded.length
                + " bytes, holder=" + holder + "]";
    }
}
