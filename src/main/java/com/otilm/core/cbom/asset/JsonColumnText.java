package com.otilm.core.cbom.asset;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.otilm.core.serialization.ObjectMapperFactory;

/**
 * Renders a JSONB column's value for a native query.
 *
 * <p>
 * The entity mapping reaches a JSONB column through Hibernate's {@code FormatMapper}; a native {@code @Modifying}
 * statement does not, and binds text that the statement casts. Both paths must produce the same bytes, so both use
 * {@link ObjectMapperFactory#jsonColumn()} -- the single recipe {@code JsonColumnFormatMapperConfig} states for the
 * mapped path.
 */
public final class JsonColumnText {

    private static final ObjectWriter WRITER = ObjectMapperFactory.jsonColumn().writer();

    private JsonColumnText() {
    }

    /** The value as JSON text, or {@code null} for a {@code null} value, which the statement stores as SQL NULL. */
    public static String render(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return WRITER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            // The value came from parsed JSON, so it is maps, lists and scalars. The message deliberately carries no
            // payload content: this text can reach an operator.
            throw new IllegalStateException("A cryptographic asset JSON column could not be rendered for storage");
        }
    }
}
