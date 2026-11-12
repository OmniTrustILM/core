package com.otilm.core.certificate.type;

import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateFormat;
import com.otilm.api.model.core.certificate.CertificateFormatEncoding;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.api.model.core.certificate.CertificateRequestDetail;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.dao.entity.RaProfile;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The extension point through which a certificate type supplies its own handling. A handler is a Spring bean; the
 * {@link CertificateTypeHandlerRegistry} finds it by {@link #typeCode()}, and the code that reads, checks and describes
 * a certificate of the type goes through it. A new type also needs its own certificate and request entity subclasses,
 * which set the discriminator, and the detail and request subclasses of the API that the detail mapper builds.
 *
 * <p>
 * The parse methods return empty when the content is not of this type, so that the registry can ask each handler in
 * turn. They throw {@link CertificateTypeHandlerException} when the content is of this type but invalid.
 */
public interface CertificateTypeHandler {

    String typeCode();

    Set<CertificateOperation> supportedOperations();

    /** The format a request of this type is read in when the client does not name one. */
    CertificateRequestFormat defaultRequestFormat();

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

    /**
     * The certificates in the format and encoding, in the given order. A format that holds one certificate only refuses
     * more than one.
     */
    byte[] encode(List<ParsedCertificate> certificates, CertificateFormat format, CertificateFormatEncoding encoding);

    /**
     * Adjusts the certificate detail for the client, where what the type stores differs from what is shown, such as
     * codes that have display names. By default nothing changes.
     */
    default void presentDetail(CertificateDetail detail) {
    }

    /**
     * Gives the request the attributes that signed with its alternative key, for a type whose requests have one. By
     * default nothing changes.
     */
    default void setAlternativeSignatureAttributes(CertificateRequestDetail request,
            List<ResponseAttribute> attributes) {
    }

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
