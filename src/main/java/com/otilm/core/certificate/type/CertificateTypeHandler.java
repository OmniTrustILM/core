package com.otilm.core.certificate.type;

import com.otilm.api.model.core.certificate.CertificateFormat;
import com.otilm.api.model.core.certificate.CertificateFormatEncoding;
import com.otilm.core.dao.entity.RaProfile;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The extension point through which a certificate type supplies its own handling. A handler is a Spring bean; the
 * {@link CertificateTypeHandlerRegistry} finds it by {@link #typeCode()} and adding a type adds a bean, nothing else.
 *
 * <p>
 * The parse methods return empty when the content is not of this type, so that the registry can ask each handler in
 * turn. They throw {@link CertificateTypeHandlerException} when the content is of this type but invalid.
 */
public interface CertificateTypeHandler {

    String typeCode();

    Set<CertificateOperation> supportedOperations();

    Optional<ParsedCertificate> parseCertificate(byte[] content);

    Optional<ParsedRequest> parseRequest(byte[] content);

    /**
     * Whether the signature of the certificate is valid for the issuer, or for the certificate's own key when the
     * issuer is null.
     */
    boolean verifySignature(ParsedCertificate certificate, ParsedCertificate issuer);

    /**
     * Whether the signature of the request is valid. The current certificate is given when the request replaces one, so
     * that a type whose requests carry a second signature made with it can check that one too.
     */
    boolean verifySignature(ParsedRequest request, ParsedCertificate current);

    /** Whether the issuer issued the certificate; false for a type that links no issuer. */
    boolean isIssuedBy(ParsedCertificate certificate, ParsedCertificate issuer);

    Set<CertificateFormat> downloadFormats();

    byte[] encode(ParsedCertificate certificate, CertificateFormat format, CertificateFormatEncoding encoding);

    /** The details only this type has, or empty when everything it has is among the common properties. */
    Optional<CertificateTypeDetails> describeDetails(ParsedCertificate certificate);

    /** The reasons the request exceeds the limits of the RA profile for this type; empty when it is within them. */
    default List<String> checkProfileLimits(ParsedRequest request, RaProfile raProfile) {
        return List.of();
    }

    default boolean supports(CertificateOperation operation) {
        return supportedOperations().contains(operation);
    }

    default void requireSupport(CertificateOperation operation) {
        if (!supports(operation)) {
            throw UnsupportedCertificateTypeException.unsupportedOperation(typeCode(), operation);
        }
    }
}
