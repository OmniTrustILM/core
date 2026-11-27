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
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.RaProfile;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Objects;
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

    /** The formats a request of this type can be in; a request in another format is refused. */
    default Set<CertificateRequestFormat> supportedRequestFormats() {
        return Set.of(defaultRequestFormat());
    }

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

    /**
     * The certificates in the format and encoding, in the given order. A format that holds one certificate only refuses
     * more than one.
     */
    byte[] encode(List<ParsedCertificate> certificates, CertificateFormat format, CertificateFormatEncoding encoding);

    /** Whether certificates of the type can be stored; a type without an entity cannot, which is the default. */
    default boolean storesCertificates() {
        return false;
    }

    /**
     * A new, empty certificate entity of the type, for a certificate that enters the inventory with its content.
     *
     * @throws UnsupportedCertificateTypeException when certificates of the type cannot be stored
     */
    default Certificate newCertificate() {
        throw UnsupportedCertificateTypeException.notStored(typeCode());
    }

    /**
     * Fills the certificate with what the type stores about a certificate that is requested and not yet issued, and
     * returns it as the entity of the type. The state of the certificate is left as it is.
     */
    Certificate stampRequested(Certificate certificate, ParsedRequest request)
            throws CertificateRequestException, NoSuchAlgorithmException;

    /**
     * A new request entity of the type, filled with what the type stores about the request. The content, the
     * fingerprint and the keys of the request are left to the caller.
     */
    CertificateRequestEntity newCertificateRequest(ParsedRequest request)
            throws CertificateRequestException, NoSuchAlgorithmException;

    /**
     * The public key of the request, decoded for a caller that needs the reason when it cannot be. By default the key
     * the request was read with, which is null when it could not be decoded; a type that can tell why overrides this to
     * throw.
     */
    default PublicKey publicKeyOf(ParsedRequest request) throws CertificateRequestException, NoSuchAlgorithmException {
        return request.publicKey();
    }

    /** The alternative public key of the request, for a type whose requests can carry one. By default none. */
    default Optional<PublicKey> alternativePublicKey(ParsedRequest request)
            throws CertificateRequestException, NoSuchAlgorithmException {
        return Optional.empty();
    }

    /**
     * Checks what the request asks for against the request attributes of the RA profile, for a type that has such
     * attributes. By default nothing is checked.
     *
     * @return the warnings about the request; empty when there are none
     * @throws CertificateException when the request attributes of the RA profile cannot be resolved
     * @throws RequestAttributePolicyViolationException when a strict profile refuses the request
     */
    default List<String> validateRequestAttributes(ParsedRequest request, RaProfile raProfile)
            throws CertificateException {
        return List.of();
    }

    /**
     * Whether the two stored certificates of the type name the same holder and the same issuer, as a certificate and
     * the one that renews or rekeys it do. By default they do not, so that one replaces the other.
     */
    default boolean sameHolderAndIssuer(Certificate certificate, Certificate other) {
        return false;
    }

    /** Whether the two stored certificates of the type certify the same keys. By default the public key decides. */
    default boolean sameKeys(Certificate certificate, Certificate other) {
        return Objects.equals(certificate.getPublicKeyFingerprint(), other.getPublicKeyFingerprint());
    }

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
