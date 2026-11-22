package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.AttributeContentData;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Checks the request attributes set by a signing request against its Signing Profile and the formatter's listing. A
 * profile allows a grouped request attribute by its group and an ungrouped one by its own name.
 */
public final class RequestAttributesCheck {

    private RequestAttributesCheck() {
    }

    /**
     * Refuses the request, naming every attribute that is a profile attribute, undeclared, sent twice, not allowed by
     * the profile, or refused by its definition. The refusal leaves out each value, which may be personal data.
     */
    public static void requireAccepted(String profileName, ContentSigningFormattingDefinitions definitions,
            Set<String> allowed, List<RequestAttribute> requested) throws SigningEngineException {
        Set<String> problems = problems(definitions, allowed, requested);
        if (!problems.isEmpty()) {
            String refusal = "Request attributes refused: " + String.join("; ", problems);
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "Signing Profile '%s' refuses the request. %s".formatted(profileName, refusal), refusal);
        }
    }

    /** The allowed names outside the declared groups and ungrouped request attributes. */
    public static List<String> undeclaredAllowedNames(ContentSigningFormattingDefinitions definitions,
            Set<String> allowed) {
        Set<String> permissionNames = definitions
                .requestAttributes()
                .stream()
                .map(RequestAttributesCheck::permissionName)
                .collect(Collectors.toSet());
        return allowed.stream().filter(name -> !permissionNames.contains(name)).toList();
    }

    private static Set<String> problems(ContentSigningFormattingDefinitions definitions, Set<String> allowed,
            List<RequestAttribute> requested) {
        Set<String> profileNames = definitions
                .profileAttributes()
                .stream()
                .map(BaseAttribute::getName)
                .collect(Collectors.toSet());
        Map<String, DataAttribute> declared = requestDefinitionsByName(definitions);
        Set<String> problems = new LinkedHashSet<>();
        for (Map.Entry<String, List<RequestAttribute>> sent : sentByName(requested).entrySet()) {
            String name = sent.getKey();
            List<RequestAttribute> copies = sent.getValue();
            if (copies.size() > 1) {
                problems.add("'%s' is sent %d times".formatted(name, copies.size()));
            }
            DataAttribute definition = declared.get(name);
            if (profileNames.contains(name)) {
                problems.add("'%s' is a profile attribute, which only the Signing Profile sets".formatted(name));
            } else if (definition == null) {
                problems.add("'%s' is not a request attribute the formatter declares".formatted(name));
            } else if (!isAllowed(definition, allowed)) {
                problems.add(notAllowedReason(definition));
            } else {
                copies.forEach(copy -> valueProblem(definition, copy).ifPresent(problems::add));
            }
        }
        return problems;
    }

    private static boolean isAllowed(DataAttribute definition, Set<String> allowed) {
        return allowed.contains(permissionName(definition));
    }

    private static String notAllowedReason(DataAttribute definition) {
        String group = ContentSigningFormattingAttributes.groupOf(definition);
        return group == null
                ? "'%s' is not allowed by the Signing Profile".formatted(definition.getName())
                : "'%s' belongs to group '%s', which the Signing Profile does not allow"
                        .formatted(definition.getName(), group);
    }

    /**
     * Returns the first problem of one value. The shared validator throws on missing data and skips the content type,
     * structured content data, the item count and closed lists, so those checks run before it.
     */
    private static Optional<String> valueProblem(DataAttribute definition, RequestAttribute sent) {
        String name = definition.getName();
        AttributeVersion definitionVersion = AttributeVersion.fromIntVersion(definition.getVersion());
        if (sent.getVersion() != definitionVersion) {
            return Optional
                    .of("'%s' is attribute version %s, but its definition is version %s"
                            .formatted(name, codeOf(sent.getVersion()), definitionVersion.getCode()));
        }
        if (sent.getContentType() != definition.getContentType()) {
            return Optional
                    .of("'%s' has content type %s, but its definition has %s"
                            .formatted(name, codeOf(sent.getContentType()), codeOf(definition.getContentType())));
        }
        List<AttributeContent> items = sent.getContent();
        if (items == null || items.isEmpty()) {
            return Optional.of("'%s' carries no value".formatted(name));
        }
        if (items.stream().anyMatch(item -> item == null || item.getData() == null)) {
            return Optional.of("'%s' carries an item without data".formatted(name));
        }
        if (items.stream().anyMatch(RequestAttributesCheck::hasIncompleteData)) {
            return Optional.of("'%s' carries incomplete content data".formatted(name));
        }
        DataAttributeProperties properties = propertiesOf(definition);
        if (items.size() > 1 && !properties.isMultiSelect()) {
            return Optional.of("'%s' carries %d values, but its definition takes one".formatted(name, items.size()));
        }
        if (isClosedList(definition, properties) && !items.stream().allMatch(item -> isOption(definition, item))) {
            return Optional.of("'%s' carries a value outside its definition's options".formatted(name));
        }
        try {
            AttributeDefinitionUtils.validateAttributes(List.of(definition), List.of(sent));
            return Optional.empty();
        } catch (ValidationException e) {
            return Optional.of("'%s' has a value its definition refuses".formatted(name));
        }
    }

    private static boolean hasIncompleteData(AttributeContent item) {
        if (!(item.getData() instanceof AttributeContentData data)) {
            return false;
        }
        try {
            data.validate();
            return false;
        } catch (ValidationException e) {
            return true;
        }
    }

    private static DataAttributeProperties propertiesOf(DataAttribute definition) {
        return definition.getProperties() == null ? new DataAttributeProperties() : definition.getProperties();
    }

    private static boolean isClosedList(DataAttribute definition, DataAttributeProperties properties) {
        List<AttributeContent> options = definition.getContent();
        return properties.isList() && !properties.isExtensibleList() && options != null && !options.isEmpty();
    }

    private static boolean isOption(DataAttribute definition, AttributeContent item) {
        List<AttributeContent> options = definition.getContent();
        return options.stream().anyMatch(option -> Objects.equals(option.getData(), item.getData()));
    }

    private static String codeOf(AttributeVersion version) {
        return version == null ? "unset" : version.getCode();
    }

    private static String codeOf(AttributeContentType contentType) {
        return contentType == null ? "unset" : contentType.getCode();
    }

    private static String permissionName(DataAttribute definition) {
        String group = ContentSigningFormattingAttributes.groupOf(definition);
        return group == null ? definition.getName() : group;
    }

    private static Map<String, DataAttribute> requestDefinitionsByName(
            ContentSigningFormattingDefinitions definitions) {
        return definitions
                .requestAttributes()
                .stream()
                .collect(Collectors.toMap(DataAttribute::getName, Function.identity()));
    }

    private static Map<String, List<RequestAttribute>> sentByName(List<RequestAttribute> requested) {
        Map<String, List<RequestAttribute>> byName = new LinkedHashMap<>();
        for (RequestAttribute attribute : requested) {
            byName.computeIfAbsent(attribute.getName(), name -> new ArrayList<>()).add(attribute);
        }
        return byName;
    }
}
