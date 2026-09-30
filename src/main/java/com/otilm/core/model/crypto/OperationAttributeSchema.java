package com.otilm.core.model.crypto;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.attribute.SignatureAlgorithmFields;
import java.util.List;
import java.util.UUID;

/**
 * Attributes applicable for a cryptography key operation.
 *
 * @param ownerConnectorUuid the connector that publishes the definitions; null for Core's own registry (crypto v1)
 * @param definitions the attribute definitions
 * @param connectorDefinitions the definitions as the connector published them, before Core presented them
 */
public record OperationAttributeSchema(UUID ownerConnectorUuid, List<BaseAttribute> definitions,
        List<BaseAttribute> connectorDefinitions) {

    /** The schema of a signing scheme that has no platform key to ask. */
    public static final OperationAttributeSchema NONE = new OperationAttributeSchema(null, List.of());

    public OperationAttributeSchema(UUID ownerConnectorUuid, List<BaseAttribute> definitions) {
        this(ownerConnectorUuid, definitions, List.of());
    }

    /**
     * Saving validates each field against its own definition, and a key can offer a scheme and a digest without
     * offering the two together.
     *
     * @throws ValidationException when the fields choose no algorithm the key offers
     */
    public void requireOfferedSignatureAlgorithm(List<RequestAttribute> signatureAttributes) {
        SignatureAlgorithmFields.selection(connectorDefinitions, signatureAttributes);
    }
}
