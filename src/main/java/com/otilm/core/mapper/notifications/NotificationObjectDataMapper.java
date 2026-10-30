package com.otilm.core.mapper.notifications;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.metadata.MetadataResponseDto;
import com.otilm.api.model.client.metadata.ResponseMetadata;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.connector.notification.NotificationAttributeDto;
import com.otilm.api.model.connector.notification.NotificationEventObjectDataDto;
import com.otilm.api.model.connector.notification.NotificationMetadataGroupDto;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pure mapping kernel between the attribute engine's response DTOs and the notification wire contract. Value
 * extraction, secret filtering, duplicate-name policy, and payload bounding live here and nowhere else, so they are
 * unit-testable without Spring and cannot drift between categories. The wire DTOs carry plain scalars and reference
 * strings only -- attribute-engine content evolution never reaches notification templates.
 */
public final class NotificationObjectDataMapper {

    /**
     * Individual string values above this length are truncated; a certificate would be useless truncated, so content is
     * exempt.
     */
    static final int MAX_VALUE_LENGTH = 4096;
    /** Cap on the serialized objectData contribution to the connector request. */
    static final int MAX_TOTAL_BYTES = 131_072;
    static final String TRUNCATION_SUFFIX = "...[truncated]";

    private static final Logger logger = LoggerFactory.getLogger(NotificationObjectDataMapper.class);

    // CREDENTIAL is the legacy predecessor of SECRET and is treated identically: not even its
    // reference string is exported.
    private static final Set<AttributeContentType> SECRET_BEARING_TYPES = Set
            .of(AttributeContentType.SECRET, AttributeContentType.CREDENTIAL);

    private static final Set<AttributeContentType> SCALAR_TYPES = Set
            .of(AttributeContentType.STRING, AttributeContentType.TEXT, AttributeContentType.INTEGER,
                    AttributeContentType.FLOAT, AttributeContentType.BOOLEAN, AttributeContentType.DATE,
                    AttributeContentType.TIME, AttributeContentType.DATETIME);

    private NotificationObjectDataMapper() {
    }

    /**
     * Maps custom attributes to the name-keyed wire map. Custom attribute names are kept unique platform-wide by an
     * application-level check, so a duplicate is a defect state: the first definition in attribute-UUID order wins
     * deterministically and the rest are dropped with a warning. Attributes whose definition is excluded (protected or
     * secret-bearing) or that yield no values are omitted.
     */
    public static Map<String, NotificationAttributeDto> mapCustomAttributes(List<ResponseAttribute> attributes,
            Set<UUID> excludedDefinitions) {
        if (attributes == null || attributes.isEmpty()) {
            return Map.of();
        }
        Map<String, NotificationAttributeDto> byName = new LinkedHashMap<>();
        for (ResponseAttribute attribute : sortedByUuid(attributes, ResponseAttribute::getUuid)) {
            toWireAttribute(attribute.getUuid(), attribute.getName(), attribute.getLabel(), attribute.getContentType(),
                    attribute.getContent(), excludedDefinitions).ifPresent(dto -> putFirstWins(byName, dto));
        }
        return byName;
    }

    private static void putFirstWins(Map<String, NotificationAttributeDto> byName, NotificationAttributeDto dto) {
        if (byName.putIfAbsent(dto.getName(), dto) != null) {
            logger
                    .warn("Duplicate custom attribute name {} on the notification subject; keeping the first definition",
                            dto.getName());
        }
    }

    /**
     * One admissible wire attribute, or empty when the definition is excluded (secret-bearing or protected) or its
     * content yields no values.
     */
    private static Optional<NotificationAttributeDto> toWireAttribute(UUID uuid, String name, String label,
            AttributeContentType contentType, List<? extends AttributeContent> content, Set<UUID> excludedDefinitions) {
        if (isExcluded(contentType, uuid, excludedDefinitions)) {
            return Optional.empty();
        }
        List<Object> values = extractValues(contentType, content);
        if (values.isEmpty()) {
            return Optional.empty();
        }
        NotificationAttributeDto dto = new NotificationAttributeDto();
        dto.setName(name);
        dto.setLabel(label);
        dto.setContentType(contentType);
        dto.setValues(values);
        return Optional.of(dto);
    }

    /**
     * Maps metadata preserving the engine's connector + source-object grouping. Within a group, same-named entries are
     * merged in attribute-UUID order (a connector legitimately re-declares a metadata attribute over time):
     * {@code values} is the deduplicated union, {@code
     * sourceObjects} the union of contributors, label from the first sorted entry. A same-named entry that disagrees on
     * content type is excluded with a warning instead of merged -- fail-safe for templates that assume a type. The two
     * aggregates are independent: values are never positionally paired with source objects.
     */
    public static List<NotificationMetadataGroupDto> mapMetadata(List<MetadataResponseDto> groups,
            Set<UUID> excludedDefinitions) {
        if (groups == null || groups.isEmpty()) {
            return List.of();
        }
        List<NotificationMetadataGroupDto> result = new ArrayList<>();
        for (MetadataResponseDto group : groups) {
            Map<String, NotificationAttributeDto> attributes = mergeGroupItems(group, excludedDefinitions);
            if (attributes.isEmpty()) {
                continue;
            }
            NotificationMetadataGroupDto groupDto = new NotificationMetadataGroupDto();
            groupDto.setConnectorName(group.getConnectorName());
            groupDto.setSourceObjectType(group.getSourceObjectType());
            groupDto.setAttributes(attributes);
            result.add(groupDto);
        }
        return result;
    }

    private static Map<String, NotificationAttributeDto> mergeGroupItems(MetadataResponseDto group,
            Set<UUID> excludedDefinitions) {
        MetadataGroupAccumulator accumulator = new MetadataGroupAccumulator(group);
        List<ResponseMetadata> items = group.getItems() == null ? List.of() : group.getItems();
        for (ResponseMetadata item : sortedByUuid(items, ResponseMetadata::getUuid)) {
            toWireAttribute(item.getUuid(), item.getName(), item.getLabel(), item.getContentType(), item.getContent(),
                    excludedDefinitions).ifPresent(dto -> accumulator.merge(dto, item.getSourceObjects()));
        }
        return accumulator.finish();
    }

    /**
     * Accumulates one metadata group's same-named entries: values as a deduplicated union, source objects as a union
     * keyed by UUID, label and content type fixed by the first entry in attribute-UUID order.
     */
    private static final class MetadataGroupAccumulator {

        private final MetadataResponseDto group;
        private final Map<String, NotificationAttributeDto> attributes = new LinkedHashMap<>();
        private final Map<String, LinkedHashSet<Object>> valuesByName = new LinkedHashMap<>();
        private final Map<String, LinkedHashMap<String, NameAndUuidDto>> sourcesByName = new LinkedHashMap<>();

        private MetadataGroupAccumulator(MetadataResponseDto group) {
            this.group = group;
        }

        private void merge(NotificationAttributeDto dto, List<NameAndUuidDto> sourceObjects) {
            NotificationAttributeDto existing = attributes.get(dto.getName());
            if (existing == null) {
                attributes.put(dto.getName(), dto);
                valuesByName.put(dto.getName(), new LinkedHashSet<>());
                sourcesByName.put(dto.getName(), new LinkedHashMap<>());
            } else if (existing.getContentType() != dto.getContentType()) {
                logger
                        .warn("Metadata attribute {} in group {}/{} re-declared with conflicting content type {}; excluding the conflicting definition",
                                dto.getName(), group.getConnectorName(), group.getSourceObjectType(),
                                dto.getContentType());
                return;
            }
            valuesByName.get(dto.getName()).addAll(dto.getValues());
            for (NameAndUuidDto source : sourceObjects == null ? List.<NameAndUuidDto>of() : sourceObjects) {
                sourcesByName.get(dto.getName()).putIfAbsent(source.getUuid(), source);
            }
        }

        private Map<String, NotificationAttributeDto> finish() {
            for (Map.Entry<String, NotificationAttributeDto> entry : attributes.entrySet()) {
                entry.getValue().setValues(new ArrayList<>(valuesByName.get(entry.getKey())));
                LinkedHashMap<String, NameAndUuidDto> sources = sourcesByName.get(entry.getKey());
                if (!sources.isEmpty()) {
                    entry.getValue().setSourceObjects(new ArrayList<>(sources.values()));
                }
            }
            return attributes;
        }
    }

    /**
     * Enforces the total serialized-size cap by dropping whole categories in deterministic order -- metadata, custom
     * attributes, object content, associations -- until the payload fits. The size is measured with the caller's wire
     * mapper so it matches what the connector request will actually carry.
     */
    public static void applyTotalCap(NotificationEventObjectDataDto objectData, ObjectMapper wireMapper) {
        if (serializedSize(objectData, wireMapper) <= MAX_TOTAL_BYTES) {
            return;
        }
        if (objectData.getMetadata() != null) {
            objectData.setMetadata(null);
            logger.warn("Notification object data exceeded {} bytes; dropped the metadata category", MAX_TOTAL_BYTES);
            if (serializedSize(objectData, wireMapper) <= MAX_TOTAL_BYTES) {
                return;
            }
        }
        if (objectData.getCustomAttributes() != null) {
            objectData.setCustomAttributes(null);
            logger
                    .warn("Notification object data exceeded {} bytes; dropped the custom attributes category",
                            MAX_TOTAL_BYTES);
            if (serializedSize(objectData, wireMapper) <= MAX_TOTAL_BYTES) {
                return;
            }
        }
        if (objectData.getContent() != null) {
            objectData.setContent(null);
            logger
                    .warn("Notification object data exceeded {} bytes; dropped the object content category",
                            MAX_TOTAL_BYTES);
            if (serializedSize(objectData, wireMapper) <= MAX_TOTAL_BYTES) {
                return;
            }
        }
        if (objectData.getAssociations() != null) {
            objectData.setAssociations(null);
            logger
                    .warn("Notification object data exceeded {} bytes; dropped the associations category",
                            MAX_TOTAL_BYTES);
        }
    }

    /**
     * Extracts template-ready values: scalar content types contribute raw data, every other non-secret type contributes
     * only its human-readable reference string, so nested internal structures (including secret-bearing shapes)
     * structurally cannot reach the wire. String values are truncated at {@link #MAX_VALUE_LENGTH}.
     */
    private static List<Object> extractValues(AttributeContentType contentType,
            List<? extends AttributeContent> content) {
        if (content == null || content.isEmpty()) {
            return List.of();
        }
        List<Object> values = new ArrayList<>(content.size());
        for (AttributeContent item : content) {
            if (item == null) {
                continue;
            }
            if (SCALAR_TYPES.contains(contentType)) {
                Object data = item.getData();
                if (data != null) {
                    values.add(truncate(data));
                }
            } else {
                String reference = item.getReference();
                if (reference != null && !reference.isBlank()) {
                    values.add(truncate(reference));
                }
            }
        }
        return values;
    }

    private static Object truncate(Object value) {
        if (value instanceof String text && text.length() > MAX_VALUE_LENGTH) {
            logger
                    .warn("Notification attribute value of {} characters truncated to {}", text.length(),
                            MAX_VALUE_LENGTH);
            return text.substring(0, MAX_VALUE_LENGTH) + TRUNCATION_SUFFIX;
        }
        return value;
    }

    private static boolean isExcluded(AttributeContentType contentType, UUID definitionUuid,
            Set<UUID> excludedDefinitions) {
        return contentType == null || SECRET_BEARING_TYPES.contains(contentType)
                || (excludedDefinitions != null && excludedDefinitions.contains(definitionUuid));
    }

    private static <T> List<T> sortedByUuid(List<T> items, Function<T, UUID> uuidAccessor) {
        return items
                .stream()
                .sorted(Comparator.comparing(uuidAccessor, Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();
    }

    private static int serializedSize(NotificationEventObjectDataDto objectData, ObjectMapper wireMapper) {
        try {
            return wireMapper.writeValueAsBytes(objectData).length;
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException("Notification object data is not serializable", e);
        }
    }
}
