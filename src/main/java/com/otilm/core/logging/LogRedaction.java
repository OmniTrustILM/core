package com.otilm.core.logging;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.introspect.Annotated;
import com.fasterxml.jackson.databind.introspect.NopAnnotationIntrospector;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.io.Serial;
import java.text.ParseException;

/**
 * Writes what the platform logs or records about a request with its secrets left out. A property marked
 * {@link Sensitive} is written as {@value #REDACTED} wherever it sits in the value, and a value that cannot be written
 * is named rather than failing its caller.
 */
public final class LogRedaction {

    /** What a secret is written as. */
    public static final String REDACTED = "***";

    private static final ObjectMapper MAPPER = ObjectMapperFactory.redacting(new SensitiveRedaction());
    private static final ObjectMapper AUDIT_MAPPER = ObjectMapperFactory.redactingAuditLog(new SensitiveRedaction());

    private LogRedaction() {
    }

    /** The value as JSON, for a log line. */
    public static String json(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            return unserializable(value);
        }
    }

    /** The value as plain maps, lists and scalars, for an audit record. */
    public static Object data(Object value) {
        try {
            return AUDIT_MAPPER.convertValue(value, Object.class);
        } catch (IllegalArgumentException e) {
            return unserializable(value);
        }
    }

    /**
     * A signed JWT without its signature, which cannot be replayed but still shows its issuer, subject and expiry; any
     * other token as {@value #REDACTED}.
     */
    public static String token(String token) {
        if (token == null) {
            return null;
        }
        try {
            SignedJWT.parse(token);
            return token.substring(0, token.lastIndexOf('.'));
        } catch (ParseException e) {
            return REDACTED;
        }
    }

    private static String unserializable(Object value) {
        return "[unserializable %s]".formatted(value.getClass().getSimpleName());
    }

    private static final class SensitiveRedaction extends NopAnnotationIntrospector {

        @Serial
        private static final long serialVersionUID = 1L;

        @Override
        public Object findSerializer(Annotated annotated) {
            return annotated.hasAnnotation(Sensitive.class) ? RedactedSerializer.INSTANCE : null;
        }
    }

    private static final class RedactedSerializer extends StdSerializer<Object> {

        @Serial
        private static final long serialVersionUID = 1L;

        private static final RedactedSerializer INSTANCE = new RedactedSerializer();

        private RedactedSerializer() {
            super(Object.class);
        }

        @Override
        public void serialize(Object value, JsonGenerator generator, SerializerProvider provider) throws IOException {
            generator.writeString(REDACTED);
        }

        // Without this, a @Sensitive property whose declared type carries its own @JsonTypeInfo would have Jackson
        // call this instead of serialize(), and the inherited default rejects a type-unaware serializer outright,
        // turning the whole value into "[unserializable ...]" rather than REDACTED.
        @Override
        public void serializeWithType(Object value, JsonGenerator generator, SerializerProvider provider,
                TypeSerializer typeSerializer) throws IOException {
            generator.writeString(REDACTED);
        }
    }
}
