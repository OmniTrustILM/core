package com.otilm.core.certificate.type;

/**
 * A certificate read by the handler of its type.
 *
 * @param typeCode the code of the type whose handler read it
 * @param encoded the content as it was read, in the type's binary encoding
 * @param properties the common properties of the certificate
 */
public record ParsedCertificate(String typeCode, byte[] encoded, CertificateProperties properties) {
}
