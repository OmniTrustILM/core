package com.otilm.core.attribute.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    private static final ObjectMapper MAPPER = ObjectMapperFactory.attributeContent();

    private AttributeDefinitionValues() {
    }

    /**
     * Returns whether both definitions have the same JSON value. A side that cannot be rendered counts as different, so
     * the caller writes the definition.
     */
    static boolean sameValue(Object stored, Object candidate) {
        try {
            return withSetsSorted(MAPPER.valueToTree(stored))
                    .equals(AttributeDefinitionValues::compareNumbersByValue,
                            withSetsSorted(MAPPER.valueToTree(candidate)));
        } catch (IllegalArgumentException e) {
            logger.debug("Attribute definition comparison failed to serialize; persisting the definition", e);
            return false;
        }
    }

    /**
     * Compares numbers by value rather than by node type or written form: a {@code jsonb} column returns
     * {@code 10000000} where a connector's JSON gave {@code 1.0E7}.
     */
    private static int compareNumbersByValue(JsonNode left, JsonNode right) {
        boolean sameValue = left.equals(right)
                || (left.isNumber() && right.isNumber() && left.decimalValue().compareTo(right.decimalValue()) == 0);
        return sameValue ? 0 : 1;
    }

    /**
     * Callback mappings and their targets are sets in the attribute model, and a set read back from JSON has no fixed
     * order, so their order is normalized before comparing.
     */
    private static JsonNode withSetsSorted(JsonNode tree) {
        if (tree.path("attributeCallback").path("mappings") instanceof ArrayNode mappings) {
            for (JsonNode mapping : mappings) {
                if (mapping.path("targets") instanceof ArrayNode targets) {
                    sortElements(targets);
                }
            }
            sortElements(mappings);
        }
        return tree;
    }

    private static void sortElements(ArrayNode array) {
        List<JsonNode> elements = new ArrayList<>();
        array.forEach(elements::add);
        elements.sort(Comparator.comparing(JsonNode::toString));
        array.removeAll();
        array.addAll(elements);
    }
}
