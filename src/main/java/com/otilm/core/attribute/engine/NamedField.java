package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.model.SearchFieldObject;
import com.otilm.core.util.SearchHelper;

/** A field a request names, by the source and identifier the catalogue publishes it under. */
public record NamedField(FilterFieldSource source, String fieldIdentifier) {

    public static NamedField of(FilterFieldSource source, String fieldIdentifier) {
        return new NamedField(source, fieldIdentifier);
    }

    /** Whether the field is attribute-sourced, which is all the attribute catalogue can answer for. */
    public boolean isAttribute() {
        return source != null && source.getAttributeType() != null;
    }

    /** Whether a catalogue row is this field. */
    public boolean names(SearchFieldObject row) {
        return isAttribute() && row.getAttributeType() == source.getAttributeType()
                && SearchHelper.buildFieldIdentifier(row).equals(fieldIdentifier);
    }
}
