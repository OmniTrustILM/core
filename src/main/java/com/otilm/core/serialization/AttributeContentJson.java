package com.otilm.core.serialization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.otilm.api.model.common.attribute.common.AttributeContent;

/**
 * Renders an attribute value for a native statement that reads or writes the {@code attribute_content_item.json}
 * column.
 *
 * <p>
 * The text must match what Hibernate's {@code FormatMapper} writes for the mapped column, which goes through the
 * declared type rather than the runtime one: a row stored with any other rendering would not match the lookup of the
 * same value, and the definition would hold it twice.
 */
public final class AttributeContentJson {

    private static final ObjectWriter JSON_COLUMN_WRITER = ObjectMapperFactory
            .jsonColumn()
            .writerFor(AttributeContent.class);

    private static final ObjectWriter KEY_ORDERED_WRITER = JSON_COLUMN_WRITER
            .with(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    private AttributeContentJson() {
    }

    public static String render(AttributeContent content) {
        return write(JSON_COLUMN_WRITER, content);
    }

    /**
     * {@link #render} with a map's entries in key order. The database stores a value once whatever order its keys
     * arrive in, and this gives every such arrival the same text, which {@link #render} does not.
     */
    public static String canonical(AttributeContent content) {
        return write(KEY_ORDERED_WRITER, content);
    }

    private static String write(ObjectWriter writer, AttributeContent content) {
        try {
            return writer.writeValueAsString(content);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("An attribute value could not be rendered for storage", e);
        }
    }
}
