package com.otilm.core.certificate.type;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateFormat;
import com.otilm.api.model.core.certificate.CertificateFormatEncoding;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.api.model.core.certificate.CertificateRequestDetail;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import java.security.cert.CertificateException;
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
     * Reads a request that is known to be of this type, in the named format.
     *
     * @param content the request as the client sent it or as it is stored
     * @throws CertificateRequestException when the content is not a valid request of the format
     */
    ParsedRequest readRequest(String content, CertificateRequestFormat format) throws CertificateRequestException;

    /**
     * Builds the request for a new certificate from its request attributes and signs it.
     *
     * @param definitions the definitions of the request attributes of the RA profile
     * @return the request in Base64
     * @throws CertificateException when no request of the format can be built from the attributes
     */
    String generateRequest(List<DataAttributeV3> definitions, List<RequestAttribute> requestAttributes,
            CertificateRequestFormat format, RequestSigning signing) throws NotFoundException, CertificateException;

    /**
     * Builds the request that asks for the current certificate again for another key and signs it.
     *
     * @return the request in Base64, in the default format of the type
     */
    String generateRekeyRequest(ParsedCertificate current, RequestSigning signing) throws NotFoundException;

    /** Refuses a request whose key is not the key of the certificate, as renewing it requires. */
    void requireSameKey(ParsedRequest request, ParsedCertificate certificate);

    /** Refuses a request to rekey the current certificate that keeps its key or names another holder. */
    void checkRekeyRequest(ParsedRequest request, ParsedCertificate current);

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

    /**
     * Fills the certificate with what the type stores about an issued certificate and returns it as the entity of the
     * type. The state of the certificate is left as it is.
     */
    Certificate stampIssued(Certificate certificate, ParsedCertificate issued);

    /** The text the content of the certificate is stored as. */
    String contentToStore(ParsedCertificate certificate);

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
