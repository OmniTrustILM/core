package com.otilm.core.service.est.message;

import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * What the platform reads from the certification request of a {@code /serverkeygen} request (RFC 7030 section 4.4.1):
 * the subject and the requested extensions that the issued request carries, and whether the client asks for the key to
 * be delivered encrypted. The signature and the public key of the request are not used.
 */
@Slf4j
public final class EstServerKeyGenerationRequest {

    /**
     * {@code id-aa-KP-contentDecryptKeyID} (RFC 7030 section 4.4.1), the attribute that names a symmetric key for the
     * delivery.
     */
    private static final ASN1ObjectIdentifier DECRYPT_KEY_IDENTIFIER = PKCSObjectIdentifiers.id_aa.branch("37");

    /** {@code id-aa-asymmDecryptKeyID}, the attribute that names an asymmetric key for the delivery. */
    private static final ASN1ObjectIdentifier ASYMMETRIC_DECRYPT_KEY_IDENTIFIER = PKCSObjectIdentifiers.id_aa
            .branch("54");

    private EstServerKeyGenerationRequest() {
    }

    /**
     * @param request a request that {@link EstRequestDecoder#decode} returned
     * @throws EstException {@link EstError#ENCRYPTED_KEY_DELIVERY_UNSUPPORTED} when the request carries a
     * {@code DecryptKeyIdentifier} or an {@code AsymmetricDecryptKeyIdentifier} attribute
     */
    public static void requireUnprotectedDelivery(PKCS10CertificationRequest request) {
        if (hasAttribute(request, DECRYPT_KEY_IDENTIFIER) || hasAttribute(request, ASYMMETRIC_DECRYPT_KEY_IDENTIFIER)) {
            log
                    .debug("EST request refused as {}: it asks for encrypted key delivery",
                            EstError.ENCRYPTED_KEY_DELIVERY_UNSUPPORTED);
            throw new EstException(EstError.ENCRYPTED_KEY_DELIVERY_UNSUPPORTED);
        }
    }

    /**
     * @param request a request that {@link EstRequestDecoder#decode} returned
     * @return its subject and its requested extensions, the only parts of it that the issued request carries, without a
     * subject key identifier, which describes the client's key and not the generated one
     */
    public static Content contentOf(PKCS10CertificationRequest request) {
        Extensions requested = EstRequestDecoder.requestedExtensions(request);
        return new Content(request.getSubject(), withoutSubjectKeyIdentifier(requested));
    }

    private static Extensions withoutSubjectKeyIdentifier(Extensions requested) {
        if (requested == null || requested.getExtension(Extension.subjectKeyIdentifier) == null) {
            return requested;
        }
        Extension[] kept = Arrays
                .stream(requested.getExtensionOIDs())
                .filter(oid -> !Extension.subjectKeyIdentifier.equals(oid))
                .map(requested::getExtension)
                .toArray(Extension[]::new);
        return kept.length == 0 ? null : new Extensions(kept);
    }

    /**
     * @param subject the subject name of the request
     * @param extensions the extensions of its {@code extensionRequest} attribute; {@code null} when it has none
     */
    public record Content(X500Name subject, Extensions extensions) {
    }

    private static boolean hasAttribute(PKCS10CertificationRequest request, ASN1ObjectIdentifier type) {
        return request.getAttributes(type).length > 0;
    }
}
