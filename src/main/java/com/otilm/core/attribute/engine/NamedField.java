package com.otilm.core.attribute.engine;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.model.SearchFieldObject;
import com.otilm.core.util.SearchHelper;
import java.util.Arrays;
import java.util.Optional;

/** A field a request names, by the source and identifier the catalogue publishes it under. */
public record NamedField(FilterFieldSource source, String fieldIdentifier) {

    private static final char CONTENT_TYPE_SEPARATOR = '|';

    public static NamedField of(FilterFieldSource source, String fieldIdentifier) {
        return new NamedField(source, fieldIdentifier);
    }

    /** The field a definition of this type, name and content type is published as. */
    public static NamedField ofDefinition(AttributeType type, String name, AttributeContentType contentType) {
        FilterFieldSource source = Arrays
                .stream(FilterFieldSource.values())
                .filter(candidate -> candidate.getAttributeType() == type)
                .findFirst()
                .orElse(null);
        return new NamedField(source, name + CONTENT_TYPE_SEPARATOR + contentType.name());
    }

    /** Whether the field is attribute-sourced, which is all the attribute catalogue can answer for. */
    public boolean isAttribute() {
        return source != null && source.getAttributeType() != null;
    }

    /** The attribute name an attribute identifier carries ahead of its content type. */
    public Optional<String> attributeName() {
        if (!isAttribute() || fieldIdentifier == null) {
            return Optional.empty();
        }
        int separator = fieldIdentifier.lastIndexOf(CONTENT_TYPE_SEPARATOR);
        return separator > 0 ? Optional.of(fieldIdentifier.substring(0, separator)) : Optional.empty();
    }

    /** Whether a catalogue row is this field. */
    public boolean names(SearchFieldObject row) {
        return isAttribute() && row.getAttributeType() == source.getAttributeType()
                && SearchHelper.buildFieldIdentifier(row).equals(fieldIdentifier);
    }
}
