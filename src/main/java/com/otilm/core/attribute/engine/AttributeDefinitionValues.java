package com.otilm.core.attribute.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Compares attribute definitions by their JSON value. The attribute model has no value-based {@code equals} on its
 * nested types, and a definition read back from a {@code jsonb} column may list object keys in another order than the
 * one a connector sent.
 */
final class AttributeDefinitionValues {

    private static final Logger logger = LoggerFactory.getLogger(AttributeDefinitionValues.class);

    /**
     * Writes dates as the ISO text connectors send, where the attribute-content recipe would write a decrypted date as
     * an array.
     */
    private static final ObjectMapper MAPPER = ObjectMapperFactory
            .attributeContent()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private AttributeDefinitionValues() {
    }

    /**
     * Returns whether both definitions have the same JSON value. Either side may already be a {@link JsonNode}. A side
     * that cannot be rendered counts as different, so the caller writes the definition.
     */
    static boolean sameValue(Object stored, Object candidate) {
        try {
            return withSetsSorted(toTree(stored))
                    .equals(AttributeDefinitionValues::compareNumbersByValue, withSetsSorted(toTree(candidate)));
        } catch (IllegalArgumentException e) {
            logger.debug("Attribute definition comparison failed to serialize; persisting the definition", e);
            return false;
        }
    }

    /**
     * Compares numbers by value rather than node type. Decrypted content holds a {@code Float} where a connector's JSON
     * gives a {@code Double} or an {@code Integer}, and keeps only float precision, so a float on either side compares
     * as a float. Other numbers compare by the JSON text they write.
     */
    private static int compareNumbersByValue(JsonNode left, JsonNode right) {
        if (left.equals(right)) {
            return 0;
        }
        if (!left.isNumber() || !right.isNumber()) {
            return 1;
        }
        if (left.isFloat() || right.isFloat()) {
            return Float.compare(left.floatValue(), right.floatValue()) == 0 ? 0 : 1;
        }
        return left.asText().equals(right.asText()) ? 0 : 1;
    }

    static JsonNode toTree(Object value) {
        return value instanceof JsonNode tree ? tree : MAPPER.valueToTree(value);
    }

    /**
     * Callback mappings and their targets are sets in the attribute model, and a set read back from JSON has no fixed
     * order, so their order is normalized before comparing.
     */
    private static JsonNode withSetsSorted(JsonNode tree) {
        JsonNode copy = tree.deepCopy();
        if (copy.path("attributeCallback").path("mappings") instanceof ArrayNode mappings) {
            for (JsonNode mapping : mappings) {
                if (mapping.path("targets") instanceof ArrayNode targets) {
                    sortElements(targets);
                }
            }
            sortElements(mappings);
        }
        return copy;
    }

    private static void sortElements(ArrayNode array) {
        List<JsonNode> elements = new ArrayList<>();
        array.forEach(elements::add);
        elements.sort(Comparator.comparing(JsonNode::toString));
        array.removeAll();
        array.addAll(elements);
    }
}
