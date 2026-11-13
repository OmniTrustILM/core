package com.otilm.core.attribute.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.serialization.ObjectMapperFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Compares attribute definitions by their JSON value. The attribute model has no value-based {@code equals} on its
 * nested types, and a definition read back from a {@code jsonb} column may list object keys in another order than the
 * one a connector sent.
 */
final class AttributeDefinitionValues {

    private static final Logger logger = LoggerFactory.getLogger(AttributeDefinitionValues.class);

    private static final ObjectMapper MAPPER = ObjectMapperFactory.attributeContent();

    private AttributeDefinitionValues() {
    }

    /**
     * Returns whether both definitions have the same JSON value. Either side may already be a {@link JsonNode}. A side
     * that cannot be rendered counts as different, so the caller writes the definition.
     */
    static boolean sameValue(Object stored, Object candidate) {
        try {
            return toTree(stored).equals(toTree(candidate));
        } catch (IllegalArgumentException e) {
            logger.debug("Attribute definition comparison failed to serialize; persisting the definition", e);
            return false;
        }
    }

    static JsonNode toTree(Object value) {
        return value instanceof JsonNode tree ? tree : MAPPER.valueToTree(value);
    }
}
