package com.otilm.core.model.crypto;

import com.otilm.api.model.client.attribute.RequestAttribute;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * What an imported key is registered with.
 *
 * @param name the key's name
 * @param description the key's description, or {@code null}
 * @param groupUuids the groups the key joins
 * @param customAttributes the custom attributes the key is registered with
 */
public record KeyImportMetadata(String name, String description, Set<UUID> groupUuids,
        List<RequestAttribute> customAttributes) {
}
