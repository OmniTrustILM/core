package com.otilm.core.attribute;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.core.util.IdentifierStringUtils;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Formats metadata names and scalar values for diagnostic messages.
 * <p>
 * Redaction follows attribute visibility, protection level, and content type. Attribute definitions and structured
 * values are never serialized. Unprotected scalar values are included as supplied by the provider, so this formatter
 * does not detect secrets that a provider incorrectly labels as ordinary scalar metadata.
 */
public final class MetadataIdentifier {

    private static final String REDACTED = "[redacted]";

    private MetadataIdentifier() {
    }

    /**
     * Formats attributes in iteration order as {@code {alias=[signing-key], slot=[3]}}.
     * <p>
     * Names and scalar values have line breaks escaped. Hidden, protected, unknown, and non-scalar attribute types
     * produce {@code name=[redacted]}. Individual values whose declared type or runtime data type conflicts with the
     * attribute type are redacted within the value list. Missing properties or a null protection level do not imply
     * protection.
     * <p>
     * Null or empty metadata produces {@code {}}. Null attributes, names, and values are represented by {@code null};
     * missing content produces an empty value list. Callers supply any domain-specific prefix. The input is not
     * modified.
     *
     * @param attributes metadata to format, or {@code null}
     * @return single-line diagnostic text containing names and permitted values
     */
    public static String format(Collection<? extends MetadataAttribute> attributes) {
        if (attributes == null) {
            return "{}";
        }
        return attributes.stream().map(MetadataIdentifier::formatAttribute).collect(Collectors.joining(", ", "{", "}"));
    }

    private static String formatAttribute(MetadataAttribute attribute) {
        if (attribute == null) {
            return "null";
        }
        String name = IdentifierStringUtils.escapeLineBreaks(String.valueOf(attribute.getName()));
        MetadataAttributeProperties properties = attribute.getProperties();
        boolean hidden = properties != null && !properties.isVisible();
        ProtectionLevel protectionLevel = properties == null ? null : properties.getProtectionLevel();
        boolean protectedContent = protectionLevel != null && protectionLevel != ProtectionLevel.NONE;
        if (hidden || protectedContent) {
            return name + "=" + REDACTED;
        }
        AttributeContentType type = attribute.getContentType();
        if (!isScalar(type)) {
            return name + "=" + REDACTED;
        }
        List<AttributeContent> content = attribute.getContent();
        String values = content == null
                ? "[]"
                : content.stream().map(item -> formatValue(item, type)).collect(Collectors.joining(", ", "[", "]"));
        return name + "=" + values;
    }

    /**
     * Formats one scalar value only when its declared and runtime types agree with the attribute type. V2 content may
     * omit its own type, in which case the enclosing attribute supplies it.
     *
     * @param content content entry to format, or {@code null}
     * @param type the enclosing attribute's supported scalar type
     * @return an escaped scalar value, {@code null} text, or the redaction marker
     */
    private static String formatValue(AttributeContent content, AttributeContentType type) {
        if (content == null) {
            return "null";
        }
        AttributeContentType contentType = content.getContentType();
        boolean conflictingContentType = contentType != null && contentType != type;
        if (conflictingContentType) {
            return REDACTED;
        }
        Object data = content.getData();
        if (data == null) {
            return "null";
        }
        boolean matchingDataType = type.getContentDataClass().isInstance(data);
        if (!matchingDataType) {
            return REDACTED;
        }
        return IdentifierStringUtils.escapeLineBreaks(data.toString());
    }

    private static boolean isScalar(AttributeContentType type) {
        return switch (type) {
            case STRING, TEXT, INTEGER, BOOLEAN, FLOAT, DATE, TIME, DATETIME -> true;
            case null, default -> false;
        };
    }
}
