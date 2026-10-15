package com.otilm.core.attribute;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Separates algorithm-selection attributes from the connector's other signing or verification parameters. */
public final class SignatureOperationAttributes {

    private static final Map<UUID, String> ALGORITHM_ATTRIBUTE_NAMES = algorithmAttributeNames();

    private SignatureOperationAttributes() {
    }

    /**
     * Replaces the algorithm selection with one v3 connector attribute, preserving other parameters and the input. An
     * omitted selection is left omitted; validation against the connector's schema checks whether it is required.
     */
    public static List<RequestAttribute> toConnector(List<RequestAttribute> attributes) {
        Objects.requireNonNull(attributes, "attributes must not be null");
        List<RequestAttribute> selection = algorithmSelection(attributes);
        if (selection.isEmpty()) {
            return attributes;
        }
        SignatureAlgorithm algorithm = SignatureAlgorithmMapping.toAlgorithm(selection);
        List<RequestAttribute> connectorAttributes = new ArrayList<>(attributes);
        connectorAttributes.removeIf(SignatureOperationAttributes::isAlgorithmAttribute);
        connectorAttributes.add(SignatureAlgorithmAttribute.request(algorithm));
        return connectorAttributes;
    }

    /** Resolves the algorithm locally, without including unrelated connector parameters in the exact lookup. */
    public static SignatureAlgorithm resolveAlgorithm(List<RequestAttribute> attributes) {
        Objects.requireNonNull(attributes, "attributes must not be null");
        return SignatureAlgorithmMapping.toAlgorithm(algorithmSelection(attributes));
    }

    private static List<RequestAttribute> algorithmSelection(List<RequestAttribute> attributes) {
        return attributes.stream().filter(SignatureOperationAttributes::isAlgorithmAttribute).toList();
    }

    /** Recognizing either identifier lets the exact mapper diagnose malformed algorithm attributes. */
    private static boolean isAlgorithmAttribute(RequestAttribute attribute) {
        if (attribute == null) {
            return true;
        }
        UUID uuid = attribute.getUuid();
        if (uuid != null && ALGORITHM_ATTRIBUTE_NAMES.containsKey(uuid)) {
            return true;
        }
        String name = attribute.getName();
        return name != null && ALGORITHM_ATTRIBUTE_NAMES.containsValue(name);
    }

    /** Deriving identifiers from the mapping keeps new mapped attributes discoverable without another registry. */
    private static Map<UUID, String> algorithmAttributeNames() {
        Map<UUID, String> names = new LinkedHashMap<>();
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            for (RequestAttribute attribute : SignatureAlgorithmMapping.toAttributes(algorithm)) {
                names.put(attribute.getUuid(), attribute.getName());
            }
        }
        return Map.copyOf(names);
    }
}
