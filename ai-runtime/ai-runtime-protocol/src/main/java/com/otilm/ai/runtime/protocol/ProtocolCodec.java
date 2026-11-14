package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.fasterxml.jackson.core.util.JsonParserDelegate;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.databind.type.LogicalType;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.UUID;
import java.util.regex.Pattern;

public final class ProtocolCodec {
    private final ObjectMapper mapper;

    public ProtocolCodec() {
        JsonFactory factory = JsonFactory
                .builder()
                .streamReadConstraints(StreamReadConstraints
                        .builder()
                        .maxNestingDepth(32)
                        .maxStringLength(65_536)
                        .maxNameLength(128)
                        .maxNumberLength(64)
                        .build())
                .disable(JsonFactory.Feature.CHARSET_DETECTION)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
                .build();
        SimpleModule types = new SimpleModule();
        types.addDeserializer(UUID.class, new StrictUuidDeserializer());
        types.addDeserializer(RuntimeErrorCode.class, new StrictRuntimeErrorCodeDeserializer());
        types.addDeserializer(Instant.class, new StrictInstantDeserializer());
        types.addSerializer(Instant.class, new InstantSerializer());
        mapper = JsonMapper
                .builder(factory)
                .addModule(types)
                .withCoercionConfig(LogicalType.Textual,
                        config -> config
                                .setCoercion(CoercionInputShape.Integer, CoercionAction.Fail)
                                .setCoercion(CoercionInputShape.Float, CoercionAction.Fail)
                                .setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail))
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
                .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                        DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                        DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES,
                        DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES,
                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES,
                        DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS)
                .build();
    }

    /** Parses structure only; authentication, expiry and online intent redemption remain mandatory. */
    public DispatchEnvelope readDispatch(byte[] bytes) {
        return read(bytes, DispatchEnvelope.class, ProtocolValidation.MAX_BYTES,
                ProtocolException.Reason.INVALID_DISPATCH);
    }

    public byte[] writeDispatch(DispatchEnvelope envelope) {
        return write(envelope, DispatchEnvelope.class, ProtocolValidation.MAX_BYTES,
                ProtocolException.Reason.INVALID_DISPATCH);
    }

    public ClaimHeartbeatRequest readClaimHeartbeatRequest(byte[] bytes) {
        return read(bytes, ClaimHeartbeatRequest.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    public byte[] writeClaimHeartbeatRequest(ClaimHeartbeatRequest message) {
        return write(message, ClaimHeartbeatRequest.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    public ClaimHeartbeatReply readClaimHeartbeatReply(byte[] bytes) {
        return read(bytes, ClaimHeartbeatReply.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    public byte[] writeClaimHeartbeatReply(ClaimHeartbeatReply message) {
        return write(message, ClaimHeartbeatReply.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    public RuntimeErrorReply readRuntimeError(byte[] bytes) {
        return read(bytes, RuntimeErrorReply.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    public byte[] writeRuntimeError(RuntimeErrorReply message) {
        return write(message, RuntimeErrorReply.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    public BootstrapRequest readBootstrapRequest(byte[] bytes) {
        return read(bytes, BootstrapRequest.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    public byte[] writeBootstrapRequest(BootstrapRequest message) {
        return write(message, BootstrapRequest.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    public BootstrapReply readBootstrapReply(byte[] bytes) {
        return read(bytes, BootstrapReply.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    public byte[] writeBootstrapReply(BootstrapReply message) {
        return write(message, BootstrapReply.class, ProtocolValidation.MAX_CONTROL_BYTES,
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    private <T> T read(byte[] bytes, Class<T> type, int maximum, ProtocolException.Reason invalidReason) {
        ProtocolValidation.bounded(bytes, maximum, invalidReason);
        validateUtf8(bytes, invalidReason);
        try (JsonParser parser = new TokenBoundedParser(mapper.createParser(bytes))) {
            // Complete the bounded parse before mapping, including otherwise unknown fields.
            JsonNode tree = mapper.readTree(parser);
            if (tree == null || !tree.isObject()) {
                throw new ProtocolException(invalidReason);
            }
            return mapper.treeToValue(tree, type);
        } catch (IOException exception) {
            throw classified(exception, invalidReason);
        } catch (ProtocolException exception) {
            throw controlled(exception.reason(), invalidReason);
        }
    }

    private <T> byte[] write(T message, Class<T> type, int maximum, ProtocolException.Reason invalidReason) {
        ProtocolValidation.required(invalidReason, message);
        try {
            byte[] bytes = mapper.writerFor(type).writeValueAsBytes(message);
            ProtocolValidation.bounded(bytes, maximum, invalidReason);
            return bytes;
        } catch (IOException exception) {
            throw classified(exception, invalidReason);
        }
    }

    private static void validateUtf8(byte[] bytes, ProtocolException.Reason invalidReason) {
        try {
            StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes));
        } catch (CharacterCodingException exception) {
            throw new ProtocolException(invalidReason);
        }
    }

    private static ProtocolException classified(IOException exception, ProtocolException.Reason invalidReason) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof ProtocolException protocolException) {
                return controlled(protocolException.reason(), invalidReason);
            }
            if (cause instanceof StreamConstraintsException) {
                return new ProtocolException(ProtocolException.Reason.LIMIT_EXCEEDED);
            }
        }
        return new ProtocolException(invalidReason);
    }

    private static ProtocolException controlled(ProtocolException.Reason reason,
            ProtocolException.Reason invalidReason) {
        return new ProtocolException(reason == ProtocolException.Reason.INVALID_DISPATCH ? invalidReason : reason);
    }

    private static String string(JsonParser parser) throws IOException {
        if (parser.currentToken() != JsonToken.VALUE_STRING) {
            throw ProtocolValidation.invalid();
        }
        return parser.getText();
    }

    private static final class TokenBoundedParser extends JsonParserDelegate {
        private TokenBoundedParser(JsonParser parser) {
            super(parser);
        }

        @Override
        public JsonToken nextToken() throws IOException {
            JsonToken token = super.nextToken();
            // Jackson's integer constraint counts digits without the leading sign.
            if (token != null && token.isNumeric() && getTextLength() > 64) {
                throw new ProtocolException(ProtocolException.Reason.LIMIT_EXCEEDED);
            }
            return token;
        }
    }

    private static final class StrictRuntimeErrorCodeDeserializer extends StdDeserializer<RuntimeErrorCode> {
        private StrictRuntimeErrorCodeDeserializer() {
            super(RuntimeErrorCode.class);
        }

        @Override
        public RuntimeErrorCode deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            String text = string(parser);
            try {
                return RuntimeErrorCode.valueOf(text);
            } catch (IllegalArgumentException exception) {
                throw ProtocolValidation.invalid();
            }
        }
    }

    private static final class StrictUuidDeserializer extends StdDeserializer<UUID> {
        private static final Pattern UUID_TEXT = Pattern
                .compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

        private StrictUuidDeserializer() {
            super(UUID.class);
        }

        @Override
        public UUID deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            String text = string(parser);
            if (!UUID_TEXT.matcher(text).matches()) {
                throw ProtocolValidation.invalid();
            }
            return UUID.fromString(text);
        }
    }

    private static final class StrictInstantDeserializer extends StdDeserializer<Instant> {
        private static final Pattern YEAR_TEXT = Pattern.compile("\\d{4}|-\\d{4}|[+-]\\d{5,10}");
        private static final Pattern MONTH_DAY_TEXT = Pattern.compile("-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\\d|3[01])");
        private static final Pattern TIME_TEXT = Pattern
                .compile("(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:\\.\\d{1,9})?Z");

        private StrictInstantDeserializer() {
            super(Instant.class);
        }

        @Override
        public Instant deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            String text = string(parser);
            if (!matchesUtcTimestamp(text)) {
                throw ProtocolValidation.invalid();
            }
            try {
                return Instant.parse(text);
            } catch (DateTimeParseException exception) {
                throw ProtocolValidation.invalid();
            }
        }

        private static boolean matchesUtcTimestamp(String text) {
            if (text.length() < 20 || text.length() > 40) {
                return false;
            }
            int timeStart = text.indexOf('T');
            if (timeStart < 10) {
                return false;
            }
            int yearEnd = timeStart - 6;
            return YEAR_TEXT.matcher(text.substring(0, yearEnd)).matches()
                    && MONTH_DAY_TEXT.matcher(text.substring(yearEnd, timeStart)).matches()
                    && TIME_TEXT.matcher(text.substring(timeStart + 1)).matches();
        }
    }

    private static final class InstantSerializer extends StdSerializer<Instant> {
        private InstantSerializer() {
            super(Instant.class);
        }

        @Override
        public void serialize(Instant value, JsonGenerator generator, SerializerProvider provider) throws IOException {
            generator.writeString(value.toString());
        }
    }
}
