package com.otilm.core.service.handler.discovery;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.List;
import java.util.Objects;

/**
 * Whether two run checkpoints name the same position. The checkpoint stays opaque to Core: it is compared, never read.
 *
 * <p>
 * Both sides are typed values written by one mapper, never the stored jsonb text: jsonb reorders the keys of an object
 * and drops its whitespace, so the stored text never equals what the connector sends. Map entries are written in key
 * order for the same reason, since an object inside an attribute's content comes back from jsonb in jsonb's order.
 */
public final class CheckpointComparison {

    private static final ObjectMapper CANONICAL = ObjectMapperFactory
            .jsonColumn()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    private CheckpointComparison() {
    }

    public static boolean same(List<MetadataAttribute> stored, List<MetadataAttribute> answered) {
        return Objects.equals(canonical(stored), canonical(answered));
    }

    private static String canonical(List<MetadataAttribute> checkpoint) {
        if (checkpoint == null) {
            return null;
        }
        try {
            return CANONICAL.writeValueAsString(checkpoint);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("A run checkpoint could not be serialized for comparison", e);
        }
    }
}
