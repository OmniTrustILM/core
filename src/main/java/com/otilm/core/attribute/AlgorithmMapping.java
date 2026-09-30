package com.otilm.core.attribute;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.BooleanAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;

/** Shared exact matching and DTO validation for algorithm selectors and their split representations. */
final class AlgorithmMapping<A> {

    private static final ObjectMapper LOG_MAPPER = ObjectMapperFactory.emptyBeanTolerantStorage();

    private final String kind;
    private final UUID originalUuid;
    private final String originalName;
    private final Function<A, RequestAttribute> originalRequest;
    private final Function<String, Optional<A>> lookup;
    private final Map<A, List<AttributeValue>> splitAttributes;
    private final String noMatchMessage;
    private final Logger logger;
    private final int maximumAttributes;
    private final Set<AttributeContentType> contentTypes;

    AlgorithmMapping(String kind, UUID originalUuid, String originalName, Function<A, RequestAttribute> originalRequest,
            Function<String, Optional<A>> lookup, Map<A, List<AttributeValue>> splitAttributes, String noMatchMessage,
            Logger logger) {
        this.kind = Objects.requireNonNull(kind, "kind must not be null");
        this.originalUuid = Objects.requireNonNull(originalUuid, "originalUuid must not be null");
        this.originalName = Objects.requireNonNull(originalName, "originalName must not be null");
        this.originalRequest = Objects.requireNonNull(originalRequest, "originalRequest must not be null");
        this.lookup = Objects.requireNonNull(lookup, "lookup must not be null");
        this.splitAttributes = Map.copyOf(Objects.requireNonNull(splitAttributes, "splitAttributes must not be null"));
        this.noMatchMessage = Objects.requireNonNull(noMatchMessage, "noMatchMessage must not be null");
        this.logger = Objects.requireNonNull(logger, "logger must not be null");
        maximumAttributes = splitAttributes.values().stream().mapToInt(List::size).max().orElse(1);
        contentTypes = splitAttributes
                .values()
                .stream()
                .flatMap(List::stream)
                .map(AttributeValue::contentType)
                .collect(Collectors.toSet());
        contentTypes.add(AttributeContentType.STRING);
    }

    List<RequestAttribute> toAttributes(A algorithm) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        List<AttributeValue> fields = splitAttributes.get(algorithm);
        if (fields == null) {
            return List.of(originalRequest.apply(algorithm));
        }
        return fields.stream().map(AttributeValue::toRequestAttribute).toList();
    }

    A toAlgorithm(List<RequestAttribute> attributes) {
        Objects.requireNonNull(attributes, "attributes must not be null");
        try {
            return matchAlgorithm(attributes);
        } catch (ValidationException e) {
            logger
                    .atError()
                    .addArgument(kind)
                    .addArgument(e.getMessage())
                    .addArgument(() -> attributesForLog(attributes))
                    .log("{} algorithm mapping failed: {} Submitted attributes: {}");
            throw e;
        }
    }

    private A matchAlgorithm(List<RequestAttribute> attributes) {
        if (attributes.isEmpty() || attributes.size() > maximumAttributes) {
            String count = maximumAttributes == 2 ? "one or two" : "one to " + maximumAttributes;
            throw validationError(kind + " attributes must contain " + count + " attributes.");
        }
        Map<UUID, AttributeValue> selectedValues = new HashMap<>();
        for (int index = 0; index < attributes.size(); index++) {
            int attributePosition = index + 1;
            AttributeValue attributeValue = readValue(attributes.get(index), attributePosition);
            if (selectedValues.putIfAbsent(attributeValue.uuid(), attributeValue) != null) {
                throw validationError(kind + " attribute at position {} repeats an attribute UUID.", attributePosition);
            }
        }
        AttributeValue originalAlgorithm = selectedValues.get(originalUuid);
        if (originalAlgorithm != null && originalName.equals(originalAlgorithm.name())) {
            if (attributes.size() != 1) {
                throw validationError("The " + originalName + " attribute must be supplied alone.");
            }
            if (!(originalAlgorithm.value() instanceof String code)) {
                throw validationError("The " + originalName + " attribute must contain a string algorithm code.");
            }
            return lookup
                    .apply(code)
                    .orElseThrow(() -> validationError(
                            "The " + originalName + " attribute contains an unknown algorithm code."));
        }
        for (Map.Entry<A, List<AttributeValue>> mapping : splitAttributes.entrySet()) {
            List<AttributeValue> expectedAttributes = mapping.getValue();
            if (doAttributesMatch(expectedAttributes, selectedValues)) {
                return mapping.getKey();
            }
        }
        throw validationError(noMatchMessage);
    }

    /** Equal counts exclude missing or extra fields; UUID lookup makes attribute order irrelevant. */
    private static boolean doAttributesMatch(List<AttributeValue> expectedAttributes,
            Map<UUID, AttributeValue> selectedValues) {
        if (expectedAttributes.size() != selectedValues.size()) {
            return false;
        }
        for (AttributeValue expectedAttribute : expectedAttributes) {
            if (!expectedAttribute.equals(selectedValues.get(expectedAttribute.uuid()))) {
                return false;
            }
        }
        return true;
    }

    /** V2 declares the content type only on the attribute; V3 also declares it on each content item. */
    private AttributeValue readValue(RequestAttribute attribute, int position) {
        String field = kind + " attribute at position {}";
        if (attribute == null) {
            throw validationError(field + " must not be null.", position);
        }
        if (attribute.getUuid() == null) {
            throw validationError(field + " must have a UUID.", position);
        }
        AttributeContentType declaredType = attribute.getContentType();
        if (!contentTypes.contains(declaredType)) {
            String requiredType = contentTypes.size() == 1 ? "STRING" : "STRING or BOOLEAN";
            throw validationError(field + " must declare content type " + requiredType + ".", position);
        }
        Object content = attribute.getContent();
        if (!(content instanceof List<?> values)) {
            throw validationError(field + " must contain a list of values.", position);
        }
        if (values.size() != 1) {
            throw validationError(field + " must contain exactly one value.", position);
        }
        if (!(values.getFirst() instanceof AttributeContent value)) {
            throw validationError(field + " must contain a non-null attribute content item.", position);
        }
        AttributeContentType contentType = value.getContentType();
        if (contentType != null && contentType != declaredType) {
            throw validationError(field + " must contain " + declaredType + " content.", position);
        }
        Object data = value.getData();
        if (declaredType == AttributeContentType.STRING && !(data instanceof String)) {
            throw validationError(field + " must contain a non-null string value.", position);
        }
        if (declaredType == AttributeContentType.BOOLEAN && !(data instanceof Boolean)) {
            throw validationError(field + " must contain a non-null boolean value.", position);
        }
        return new AttributeValue(attribute.getUuid(), attribute.getName(), declaredType, data);
    }

    private static ValidationException validationError(String message, Object... arguments) {
        return new ValidationException(ValidationError.create(message, arguments));
    }

    /** Logging must not replace the validation failure when malformed content cannot be serialized. */
    private static String attributesForLog(List<RequestAttribute> attributes) {
        try {
            return LOG_MAPPER.writeValueAsString(attributes);
        } catch (JsonProcessingException | RuntimeException e) {
            return "<unable to serialize " + attributes.size() + " submitted attributes>";
        }
    }

    record AttributeValue(UUID uuid, String name, AttributeContentType contentType, Object value) {

        static AttributeValue string(UUID uuid, String name, String value) {
            return new AttributeValue(uuid, name, AttributeContentType.STRING, value);
        }

        static AttributeValue bool(UUID uuid, String name, boolean value) {
            return new AttributeValue(uuid, name, AttributeContentType.BOOLEAN, value);
        }

        RequestAttribute toRequestAttribute() {
            BaseAttributeContentV3<?> content = contentType == AttributeContentType.BOOLEAN
                    ? new BooleanAttributeContentV3((Boolean) value)
                    : new StringAttributeContentV3((String) value);
            return new RequestAttributeV3(uuid, name, contentType, List.of(content));
        }
    }
}
