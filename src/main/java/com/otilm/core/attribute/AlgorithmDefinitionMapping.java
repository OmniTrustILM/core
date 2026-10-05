package com.otilm.core.attribute;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

/**
 * Definition expansion shared by {@link SignatureAlgorithmUtils} and {@link EncryptionAlgorithmUtils}. Builds
 * {@link DataAttributeV3} choices from {@link RequestAttributeV3} values.
 */
final class AlgorithmDefinitionMapping {

    private AlgorithmDefinitionMapping() {
    }

    /**
     * Replaces definition matching both UUID and name at its original position. Retains unrelated {@link BaseAttribute}
     * instances. Returns input when no replacement is needed.
     *
     * @throws ConnectorException for mismatched reserved identities, duplicate selectors or replacement UUID/name
     * collisions
     */
    static List<BaseAttribute> expand(List<BaseAttribute> definitions, UUID uuid, String name, DefinitionMapper mapping)
            throws ConnectorException {
        Objects.requireNonNull(definitions, "definitions must not be null");
        Objects.requireNonNull(uuid, "uuid must not be null");
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(mapping, "mapping must not be null");
        Optional<BaseAttribute> selector = findDefinition(definitions, uuid, name);
        if (selector.isEmpty()) {
            return definitions;
        }
        BaseAttribute original = selector.get();
        List<BaseAttribute> replacements = mapping.map(original);
        for (BaseAttribute definition : definitions) {
            if (definition == null || definition == original) {
                continue;
            }
            for (BaseAttribute replacement : replacements) {
                if (replacement.getUuid().equals(definition.getUuid())
                        || replacement.getName().equals(definition.getName())) {
                    String algorithmKind = name.replace("Algorithm", "");
                    throw new ConnectorException(
                            "Connector publishes conflicting " + algorithmKind + " attribute UUIDs or names.");
                }
            }
        }
        if (replacements.size() == 1 && replacements.getFirst() == original) {
            return definitions;
        }
        List<BaseAttribute> result = new ArrayList<>();
        for (BaseAttribute definition : definitions) {
            if (definition == original) {
                result.addAll(replacements);
            } else {
                result.add(definition);
            }
        }
        return result;
    }

    static Optional<BaseAttribute> findDefinition(List<BaseAttribute> definitions, UUID uuid, String name)
            throws ConnectorException {
        String reservedUuid = uuid.toString();
        BaseAttribute match = null;
        for (BaseAttribute definition : definitions) {
            if (definition == null) {
                continue;
            }
            boolean matchesName = name.equals(definition.getName());
            boolean matchesUuid = reservedUuid.equals(definition.getUuid());
            if (matchesName != matchesUuid) {
                throw new ConnectorException("Connector publishes mismatched " + name + " attribute UUID and name.");
            }
            if (matchesName) {
                if (match != null) {
                    throw new ConnectorException(
                            "Connector publishes more than one " + name + " attribute definition.");
                }
                match = definition;
            }
        }
        return Optional.ofNullable(match);
    }

    /**
     * A connector-definition transformation that can report malformed schema as a checked connector fault.
     */
    @FunctionalInterface
    interface DefinitionMapper {
        List<BaseAttribute> map(BaseAttribute definition) throws ConnectorException;
    }

    /**
     * Merges {@link SignatureAlgorithmMapping#toAttributes} or {@link EncryptionAlgorithmMapping#toAttributes} results
     * by UUID. Deduplicates content by data value; retains first-seen field and value order. A field is required only
     * when every choice supplies it, regardless of its template's required flag. For mixed PKCS1/OAEP offers, hash and
     * MGF remain optional globally; exact algorithm matching enforces their presence for an OAEP selection.
     */
    static List<BaseAttribute> merge(List<List<RequestAttribute>> choices,
            Function<RequestAttribute, DataAttribute> templateProvider) {
        Objects.requireNonNull(choices, "choices must not be null");
        Objects.requireNonNull(templateProvider, "templateProvider must not be null");
        Map<UUID, DataAttributeV3> definitions = new LinkedHashMap<>();
        for (List<RequestAttribute> choice : choices) {
            for (RequestAttribute attribute : choice) {
                DataAttributeV3 definition = definitions
                        .computeIfAbsent(attribute.getUuid(),
                                uuid -> emptyDefinition(attribute, templateProvider.apply(attribute)));
                BaseAttributeContentV3<?> option = ((RequestAttributeV3) attribute).getContent().getFirst();
                boolean alreadyPresent = definition
                        .getContent()
                        .stream()
                        .anyMatch(existing -> Objects.equals(existing.getData(), option.getData()));
                if (!alreadyPresent) {
                    definition.getContent().add(option);
                }
            }
        }
        definitions.forEach((uuid, definition) -> {
            boolean presentInEveryChoice = choices
                    .stream()
                    .allMatch(choice -> choice.stream().anyMatch(attribute -> uuid.equals(attribute.getUuid())));
            definition.getProperties().setRequired(presentInEveryChoice);
        });
        return new ArrayList<>(definitions.values());
    }

    /** Copies field identity and content type from request; description and properties from Core's RSA template. */
    private static DataAttributeV3 emptyDefinition(RequestAttribute attribute, DataAttribute template) {
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid(attribute.getUuid().toString());
        definition.setName(attribute.getName());
        definition.setDescription(template.getDescription());
        definition.setContentType(attribute.getContentType());
        definition.setProperties(template.getProperties());
        definition.setContent(new ArrayList<>());
        return definition;
    }
}
