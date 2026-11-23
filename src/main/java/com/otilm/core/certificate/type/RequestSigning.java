package com.otilm.core.certificate.type;

import com.otilm.api.model.client.attribute.RequestAttribute;
import java.util.List;
import java.util.UUID;

/**
 * The keys a generated certificate request is signed with.
 *
 * @param keyUuid the key the certificate is requested for
 * @param tokenProfileUuid the token profile the key is used through
 * @param signatureAttributes the attributes of the signature made with the key
 * @param altKeyUuid the alternative key of a request that carries one, or null
 * @param altTokenProfileUuid the token profile the alternative key is used through, or null
 * @param altSignatureAttributes the attributes of the signature made with the alternative key, or null
 */
public record RequestSigning(UUID keyUuid, UUID tokenProfileUuid, List<RequestAttribute> signatureAttributes,
        UUID altKeyUuid, UUID altTokenProfileUuid, List<RequestAttribute> altSignatureAttributes) {
}
