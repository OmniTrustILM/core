package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Expands {@link SignatureAlgorithmAttribute} choices through {@link SignatureAlgorithmMapping} and
 * {@link AlgorithmDefinitionMapping}.
 */
public final class SignatureAlgorithmUtils {

    private SignatureAlgorithmUtils() {
    }

    /**
     * Replaces {@code signatureAlgorithm} with {@code data_rsaSigScheme} and {@code data_sigDigest} choices through
     * {@link AlgorithmDefinitionMapping#expand}. ECDSA exposes digest alone; unsplit algorithms retain selector.
     * Rejects malformed definitions, incompatible representations and field collisions. Caller checks raw connector
     * response for secret echoes before expansion.
     *
     * @throws ValidationException when the connector's signature definitions are duplicated, malformed or conflicting
     */
    public static List<BaseAttribute> expandSignatureAlgorithmDefinition(List<BaseAttribute> connectorDefinitions) {
        return AlgorithmDefinitionMapping
                .expand(connectorDefinitions, SignatureAlgorithmAttribute.ATTRIBUTE_UUID,
                        SignatureAlgorithmAttribute.NAME, SignatureAlgorithmUtils::mapAlgorithmDefinition);
    }

    /**
     * Reads all advertised algorithms from the definition identified by its reserved UUID and name. Missing definitions
     * and empty choice lists return an empty list. Every choice is validated before returning, even after a match could
     * have been found, so callers cannot overlook malformed trailing values.
     *
     * @throws ValidationException when definitions are duplicated or their content contains invalid algorithm codes
     */
    public static List<SignatureAlgorithm> extractSupportedSignatureAlgorithms(
            List<BaseAttribute> connectorDefinitions) {
        Objects.requireNonNull(connectorDefinitions, "connectorDefinitions must not be null");
        return findAlgorithmDefinition(connectorDefinitions)
                .map(SignatureAlgorithmUtils::readSupportedAlgorithms)
                .orElseGet(List::of);
    }

    private static Optional<BaseAttribute> findAlgorithmDefinition(List<BaseAttribute> connectorDefinitions) {
        List<BaseAttribute> algorithmDefinitions = connectorDefinitions
                .stream()
                .filter(SignatureAlgorithmUtils::isSignatureAlgorithm)
                .toList();
        if (algorithmDefinitions.size() > 1) {
            throw new ValidationException(ValidationError
                    .create("Connector publishes more than one signatureAlgorithm attribute definition."));
        }
        return algorithmDefinitions.stream().findFirst();
    }

    private static boolean isSignatureAlgorithm(BaseAttribute definition) {
        return definition != null && SignatureAlgorithmAttribute.NAME.equals(definition.getName())
                && SignatureAlgorithmAttribute.ATTRIBUTE_UUID.toString().equals(definition.getUuid());
    }

    private static List<BaseAttribute> mapAlgorithmDefinition(BaseAttribute originalDefinition) {
        List<SignatureAlgorithm> algorithmChoices = readSupportedAlgorithms(originalDefinition);
        if (algorithmChoices.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("Connector signatureAlgorithm definition must contain at least one algorithm code."));
        }
        List<List<RequestAttribute>> mappedChoices = mapAndValidateChoices(algorithmChoices);
        if (usesOriginalAlgorithmAttribute(mappedChoices.getFirst())) {
            return List.of(originalDefinition);
        }
        return AlgorithmDefinitionMapping.merge(mappedChoices, SignatureAlgorithmUtils::coreFieldTemplate);
    }

    private static List<SignatureAlgorithm> readSupportedAlgorithms(BaseAttribute originalDefinition) {
        Object content = originalDefinition.getContent();
        if (!(content instanceof List<?> choices)) {
            throw new ValidationException(ValidationError
                    .create("Connector signatureAlgorithm definition must contain a list of algorithm codes."));
        }
        return choices.stream().map(SignatureAlgorithmUtils::parseAlgorithmChoice).toList();
    }

    private static List<List<RequestAttribute>> mapAndValidateChoices(List<SignatureAlgorithm> algorithmChoices) {
        SignatureAlgorithm firstAlgorithm = algorithmChoices.getFirst();
        List<RequestAttribute> firstMappedChoice = SignatureAlgorithmMapping.toAttributes(firstAlgorithm);
        Set<UUID> expectedAttributeUuids = attributeUuids(firstMappedChoice);
        List<List<RequestAttribute>> mappedChoices = new ArrayList<>();
        mappedChoices.add(firstMappedChoice);

        // Later choices may offer different values, but must use the same attributes to share one set of definitions.
        for (SignatureAlgorithm algorithm : algorithmChoices.subList(1, algorithmChoices.size())) {
            List<RequestAttribute> attributes = SignatureAlgorithmMapping.toAttributes(algorithm);
            Set<UUID> mappedAttributeUuids = attributeUuids(attributes);
            requireSameAttributeUuids(expectedAttributeUuids, mappedAttributeUuids);
            mappedChoices.add(attributes);
        }
        return mappedChoices;
    }

    private static SignatureAlgorithm parseAlgorithmChoice(Object choice) {
        if (!(choice instanceof AttributeContent value) || !(value.getData() instanceof String code)) {
            throw new ValidationException(ValidationError
                    .create("Connector signatureAlgorithm choices must contain string algorithm codes."));
        }
        return SignatureAlgorithm
                .lookupByCode(code)
                .orElseThrow(() -> new ValidationException(ValidationError
                        .create("Connector signatureAlgorithm definition contains an unknown algorithm code.")));
    }

    private static Set<UUID> attributeUuids(List<RequestAttribute> attributes) {
        return attributes.stream().map(RequestAttribute::getUuid).collect(Collectors.toSet());
    }

    private static void requireSameAttributeUuids(Set<UUID> expectedAttributeUuids, Set<UUID> actualAttributeUuids) {
        if (!expectedAttributeUuids.equals(actualAttributeUuids)) {
            throw new ValidationException(ValidationError
                    .create("Connector signature algorithms do not share a common attribute representation."));
        }
    }

    private static boolean usesOriginalAlgorithmAttribute(List<RequestAttribute> attributes) {
        return attributeUuids(attributes).contains(SignatureAlgorithmAttribute.ATTRIBUTE_UUID);
    }

    /**
     * Selects {@link RsaSignatureAttributes#buildDataRsaSigScheme()} or
     * {@link RsaSignatureAttributes#buildDataDigest()}.
     */
    private static DataAttribute coreFieldTemplate(RequestAttribute attribute) {
        if (RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME.equals(attribute.getName())) {
            return (DataAttribute) RsaSignatureAttributes.buildDataRsaSigScheme();
        }
        return (DataAttribute) RsaSignatureAttributes.buildDataDigest();
    }

}
