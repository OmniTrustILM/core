package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import java.util.List;
import java.util.UUID;

/**
 * Attribute definitions together with their owner.
 *
 * @param ownerConnectorUuid the owning connector's UUID, or {@code null} for attributes owned by Core
 * @param definitions the attribute definitions associated with the owner
 */
public record AttributesWithOwner(UUID ownerConnectorUuid, List<BaseAttribute> definitions) {

}
