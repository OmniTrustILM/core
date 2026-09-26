package com.otilm.core.model.crypto;

import java.util.Set;
import java.util.UUID;

/**
 * What an imported key is registered with.
 *
 * @param name the key's name
 * @param description the key's description, or {@code null}
 * @param groupUuids the groups the key joins
 */
public record KeyImportMetadata(String name, String description, Set<UUID> groupUuids) {
}
