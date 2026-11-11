package com.otilm.core.certificate.type;

import java.util.Arrays;
import java.util.Objects;

/**
 * A certificate read by the handler of its type.
 *
 * @param typeCode the code of the type whose handler read it
 * @param encoded the content as it was read, in the type's binary encoding
 * @param properties the common properties of the certificate
 */
public record ParsedCertificate(String typeCode, byte[] encoded, CertificateProperties properties) {

    @Override
    public boolean equals(Object other) {
        return other instanceof ParsedCertificate(String otherTypeCode, byte[] otherEncoded, CertificateProperties otherProperties)
                && Objects.equals(typeCode, otherTypeCode) && Arrays.equals(encoded, otherEncoded)
                && Objects.equals(properties, otherProperties);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(typeCode, properties) + Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "ParsedCertificate[typeCode=" + typeCode + ", encoded=" + encoded.length + " bytes, properties="
                + properties + "]";
    }
}
