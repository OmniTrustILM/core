package com.otilm.core.model.crypto;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.attribute.SignatureAlgorithmFields;
import java.util.List;
import java.util.UUID;

/**
 * Attributes applicable for a cryptography key operation.
 *
 * @param ownerConnectorUuid the connector that publishes the definitions; null for Core's own registry (crypto v1)
 * @param presentedDefinitions the definitions as Core presents them to a caller
 * @param connectorDefinitions the definitions as the connector published them, before Core presented them
 * @param keyAlgorithm the signing key's algorithm, which picks the fields; null for Core's own registry
 */
public record OperationAttributeSchema(UUID ownerConnectorUuid, List<BaseAttribute> presentedDefinitions,
        List<BaseAttribute> connectorDefinitions, KeyAlgorithm keyAlgorithm) {

    /** The schema of a signing scheme that has no platform key to ask. */
    public static final OperationAttributeSchema NONE = new OperationAttributeSchema(null, List.of(), List.of(), null);

    /** A schema of Core's own registry, with no connector definitions. */
    public static OperationAttributeSchema ofCoreRegistry(List<BaseAttribute> definitions) {
        return new OperationAttributeSchema(null, definitions, List.of(), null);
    }

    /**
     * Refuses a submitted field the key does not present. A connector's key is also asked for the scheme and digest as
     * a pair, because content validation checks each field alone.
     *
     * @throws ValidationException when the key does not present a submitted field, or a connector's key offers no
     * algorithm the fields choose
     */
    public void requireOfferedSignatureAlgorithm(List<RequestAttribute> signatureAttributes) {
        SignatureAlgorithmFields.requirePresented(presentedDefinitions, signatureAttributes);
        if (keyAlgorithm != null) {
            SignatureAlgorithmFields.toConnector(keyAlgorithm, connectorDefinitions, signatureAttributes);
        }
    }
}
