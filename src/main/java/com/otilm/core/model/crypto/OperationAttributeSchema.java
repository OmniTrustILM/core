package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import java.util.List;
import java.util.UUID;

/**
 * Attributes applicable for a cryptography key operation.
 *
 * @param ownerConnectorUuid the connector that publishes the definitions; null for Core's own registry (crypto v1)
 * @param definitions the attribute definitions
 */
public record OperationAttributeSchema(UUID ownerConnectorUuid, List<BaseAttribute> definitions) {

    /** The schema of a signing scheme that has no platform key to ask. */
    public static final OperationAttributeSchema NONE = new OperationAttributeSchema(null, List.of());
}
