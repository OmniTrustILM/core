package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.EncryptionAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptionAlgorithmAttribute;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Converts {@link RsaEncryptionAttributes} selections to {@link EncryptionAlgorithmAttribute} for
 * {@code KeyProviderV2Adapter.encryptData} and {@code KeyProviderV2Adapter.decryptData}.
 */
public final class EncryptionOperationAttributes {

    private static final Map<UUID, String> ALGORITHM_ATTRIBUTE_NAMES = algorithmAttributeNames();

    private EncryptionOperationAttributes() {
    }

    /**
     * Resolves {@code data_rsaEncScheme}, {@code data_rsaOaepHash} and {@code data_rsaOaepMgf} through
     * {@link EncryptionAlgorithmMapping#toAlgorithm}. Replaces selection with
     * {@link EncryptionAlgorithmAttribute#request}; accepts joint {@code encryptionAlgorithm} too. Retains unrelated
     * attributes and input. Missing selection stays missing for connector schema validation.
     *
     * @throws ValidationException for malformed, incomplete, duplicate or mixed selections
     */
    public static List<RequestAttribute> toConnector(List<RequestAttribute> attributes) {
        Objects.requireNonNull(attributes, "attributes must not be null");
        List<RequestAttribute> selection = attributes
                .stream()
                .filter(EncryptionOperationAttributes::isAlgorithmAttribute)
                .toList();
        if (selection.isEmpty()) {
            return attributes;
        }
        EncryptionAlgorithm algorithm = EncryptionAlgorithmMapping.toAlgorithm(selection);
        List<RequestAttribute> connectorAttributes = new ArrayList<>(attributes);
        connectorAttributes.removeIf(EncryptionOperationAttributes::isAlgorithmAttribute);
        connectorAttributes.add(EncryptionAlgorithmAttribute.request(algorithm));
        return connectorAttributes;
    }

    /**
     * Matches UUID or name so {@link EncryptionAlgorithmMapping#toAlgorithm} rejects mismatched identities and nulls.
     */
    private static boolean isAlgorithmAttribute(RequestAttribute attribute) {
        if (attribute == null) {
            return true;
        }
        UUID uuid = attribute.getUuid();
        String name = attribute.getName();
        return (uuid != null && ALGORITHM_ATTRIBUTE_NAMES.containsKey(uuid))
                || (name != null && ALGORITHM_ATTRIBUTE_NAMES.containsValue(name));
    }

    /**
     * Registers {@code encryptionAlgorithm} plus split identities returned by
     * {@link EncryptionAlgorithmMapping#toAttributes}.
     */
    private static Map<UUID, String> algorithmAttributeNames() {
        Map<UUID, String> names = new LinkedHashMap<>();
        names.put(EncryptionAlgorithmAttribute.ATTRIBUTE_UUID, EncryptionAlgorithmAttribute.NAME);
        for (EncryptionAlgorithm algorithm : EncryptionAlgorithm.values()) {
            for (RequestAttribute attribute : EncryptionAlgorithmMapping.toAttributes(algorithm)) {
                names.put(attribute.getUuid(), attribute.getName());
            }
        }
        return Map.copyOf(names);
    }
}
