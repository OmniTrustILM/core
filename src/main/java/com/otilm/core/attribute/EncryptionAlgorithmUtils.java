package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.enums.cryptography.EncryptionAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptionAlgorithmAttribute;
import java.util.List;

/**
 * Expands {@link EncryptionAlgorithmAttribute} definitions using {@link EncryptionAlgorithmMapping} and
 * {@link RsaEncryptionAttributes}. Used by {@code KeyProviderV2Adapter.listEncryptAttributes} and
 * {@code KeyProviderV2Adapter.listDecryptAttributes}.
 */
public final class EncryptionAlgorithmUtils {

    private EncryptionAlgorithmUtils() {
    }

    /**
     * Replaces {@code encryptionAlgorithm} with advertised {@code data_rsaEncScheme}, {@code data_rsaOaepHash} and
     * BOOLEAN {@code data_rsaOaepMgf} choices. PKCS1-only definitions expose scheme alone. Mixed PKCS1/OAEP definitions
     * keep OAEP fields optional. Retains unrelated definitions and input. Caller checks connector response for secret
     * echoes before expansion.
     *
     * @throws ValidationException for duplicate selectors, malformed choices, mixed split/original representations or
     * replacement UUID/name collisions
     */
    public static List<BaseAttribute> expandEncryptionAlgorithmDefinition(List<BaseAttribute> connectorDefinitions) {
        return AlgorithmDefinitionMapping
                .expand(connectorDefinitions, EncryptionAlgorithmAttribute.ATTRIBUTE_UUID,
                        EncryptionAlgorithmAttribute.NAME, EncryptionAlgorithmUtils::mapDefinition);
    }

    /**
     * Merges {@link EncryptionAlgorithmMapping#toAttributes} results; retains selector when every choice stays joint.
     */
    private static List<BaseAttribute> mapDefinition(BaseAttribute definition) {
        if (!(definition.getContent() instanceof List<?> choices) || choices.isEmpty()) {
            throw new ValidationException("Connector encryptionAlgorithm definition must contain algorithm codes.");
        }
        List<List<RequestAttribute>> mappedChoices = choices
                .stream()
                .map(EncryptionAlgorithmUtils::parseChoice)
                .map(EncryptionAlgorithmMapping::toAttributes)
                .toList();
        long originalChoices = mappedChoices
                .stream()
                .filter(attributes -> attributes
                        .stream()
                        .anyMatch(attribute -> EncryptionAlgorithmAttribute.ATTRIBUTE_UUID.equals(attribute.getUuid())))
                .count();
        if (originalChoices == mappedChoices.size()) {
            return List.of(definition);
        }
        if (originalChoices != 0) {
            throw new ValidationException(
                    "Connector encryption algorithms do not share a common attribute representation.");
        }
        return AlgorithmDefinitionMapping.merge(mappedChoices, EncryptionAlgorithmUtils::fieldTemplate);
    }

    /** Reads string {@link AttributeContent#getData()} through {@link EncryptionAlgorithm#lookupByCode}. */
    private static EncryptionAlgorithm parseChoice(Object choice) {
        if (!(choice instanceof AttributeContent value) || !(value.getData() instanceof String code)) {
            throw new ValidationException("Connector encryptionAlgorithm choices must contain string algorithm codes.");
        }
        return EncryptionAlgorithm
                .lookupByCode(code)
                .orElseThrow(() -> new ValidationException(
                        "Connector encryptionAlgorithm definition contains an unknown algorithm code."));
    }

    /** Selects {@link RsaEncryptionAttributes} template by split field name. */
    private static DataAttribute fieldTemplate(RequestAttribute attribute) {
        return (DataAttribute) switch (attribute.getName()) {
            case RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME ->
                RsaEncryptionAttributes.buildDataEncryptionScheme();
            case RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME ->
                RsaEncryptionAttributes.buildDataOaepHash();
            case RsaEncryptionAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME ->
                RsaEncryptionAttributes.buildDataOaepMgf();
            default -> throw new IllegalArgumentException("Unknown RSA encryption field.");
        };
    }
}
