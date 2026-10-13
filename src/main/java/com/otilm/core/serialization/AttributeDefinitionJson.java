package com.otilm.core.serialization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.otilm.api.model.common.attribute.common.BaseAttribute;

/**
 * Renders an attribute definition for a native statement that writes the {@code attribute_definition.definition}
 * column.
 *
 * <p>
 * Like {@link AttributeContentJson}, it writes through the declared type, as Hibernate's {@code FormatMapper} does for
 * the mapped column: a definition stored with any other rendering would not read back equal, and every later
 * registration would rewrite it.
 */
public final class AttributeDefinitionJson {

    private static final ObjectWriter JSON_COLUMN_WRITER = ObjectMapperFactory
            .jsonColumn()
            .writerFor(BaseAttribute.class);

    private AttributeDefinitionJson() {
    }

    public static String render(BaseAttribute definition) {
        try {
            return JSON_COLUMN_WRITER.writeValueAsString(definition);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("An attribute definition could not be rendered for storage", e);
        }
    }
}
