package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProtocolCodecTest {
    private static final String CANARY = "private-canary-credential";
    private static final int BODY_LIMIT = 1_048_576;
    private final ProtocolCodec codec = new ProtocolCodec();

    @Test
    void decodesGoldenRunAndWritesExactBytes() throws IOException {
        byte[] bytes = fixture("run");
        RunDispatchEnvelope run = assertInstanceOf(RunDispatchEnvelope.class, codec.readDispatch(bytes));
        assertEquals(1, run.protocolVersion());
        assertEquals(UUID.fromString("11111111-1111-4111-8111-111111111111"), run.intentId());
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", run.payloadSha256());
        assertEquals(new RunBinding(UUID.fromString("22222222-2222-4222-8222-222222222222"),
                UUID.fromString("33333333-3333-4333-8333-333333333333"),
                UUID.fromString("44444444-4444-4444-8444-444444444444"),
                UUID.fromString("55555555-5555-4555-8555-555555555555"), 7, Instant.parse("2026-10-26T12:00:00Z")),
                run.binding());
        assertArrayEquals(bytes, codec.writeDispatch(run));
    }

    @Test
    void decodesBothManagementActionsAndWritesGoldenBytes() throws IOException {
        byte[] bytes = fixture("management");
        ManagementDispatchEnvelope management = assertInstanceOf(ManagementDispatchEnvelope.class,
                codec.readDispatch(bytes));
        assertEquals(new ManagementBinding(UUID.fromString("22222222-2222-4222-8222-222222222222"),
                UUID.fromString("33333333-3333-4333-8333-333333333333"),
                UUID.fromString("44444444-4444-4444-8444-444444444444"), 9, ManagementAction.CONNECTION_CHECK,
                Instant.parse("2026-10-26T12:00:00Z")), management.binding());
        assertArrayEquals(bytes, codec.writeDispatch(management));
        String capability = text(bytes).replace("CONNECTION_CHECK", "CAPABILITY_CHECK");
        assertEquals(ManagementAction.CAPABILITY_CHECK,
                ((ManagementDispatchEnvelope) codec.readDispatch(utf8(capability))).binding().action());
    }

    @Test
    void deserializationDoesNotAuthorizeExpiredTime() throws IOException {
        String expired = text(fixture("run")).replace("2026-10-26T12:00:00Z", "2000-01-01T00:00:00Z");
        assertEquals(Instant.parse("2000-01-01T00:00:00Z"),
                ((RunDispatchEnvelope) codec.readDispatch(utf8(expired))).binding().expiresAt());
    }

    @ParameterizedTest
    @MethodSource("acceptedTimestampForms")
    void acceptsUtcTimestampPrecisionAndExpandedYears(String wire, String normalized) throws IOException {
        String input = text(fixture("run")).replace("2026-10-26T12:00:00Z", wire);
        RunDispatchEnvelope run = (RunDispatchEnvelope) codec.readDispatch(utf8(input));
        assertEquals(Instant.parse(normalized), run.binding().expiresAt());
        String expected = text(fixture("run")).replace("2026-10-26T12:00:00Z", normalized);
        assertArrayEquals(utf8(expected), codec.writeDispatch(run));
    }

    @ParameterizedTest
    @MethodSource("rejectedTimestampForms")
    void rejectsTimestampFormsOutsideUtcContract(String wire) throws IOException {
        reject(text(fixture("run")).replace("2026-10-26T12:00:00Z", wire), ProtocolException.Reason.INVALID_DISPATCH);
    }

    static Stream<Arguments> acceptedTimestampForms() throws IOException {
        Stream.Builder<Arguments> cases = Stream.builder();
        for (JsonNode row : timestampCases().path("accepted")) {
            cases.add(Arguments.of(row.path("wire").asText(), row.path("normalized").asText()));
        }
        return cases.build();
    }

    static Stream<String> rejectedTimestampForms() throws IOException {
        Stream.Builder<String> cases = Stream.builder();
        JsonNode timestamps = timestampCases();
        for (String category : new String[]{"rejected", "semanticRejected"}) {
            for (JsonNode row : timestamps.path(category)) {
                cases.add(row.asText());
            }
        }
        return cases.build();
    }

    private static JsonNode timestampCases() throws IOException {
        return new ObjectMapper().readTree(fixture("timestamps"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "2", "-1", "2147483647"})
    void rejectsUnsupportedVersions(String version) throws IOException {
        reject(text(fixture("run")).replace("\"protocolVersion\":1", "\"protocolVersion\":" + version),
                ProtocolException.Reason.UNSUPPORTED_VERSION);
    }

    @ParameterizedTest
    @MethodSource("invalidDispatches")
    void rejectsInvalidWireWithoutDisclosingInput(String invalid) {
        reject(invalid, ProtocolException.Reason.INVALID_DISPATCH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"run", "management"})
    void rejectsWrapperArrayDispatchEncoding(String kind) throws IOException {
        String object = removeField(text(fixture(kind)), "kind");
        reject("[\"" + kind + "\"," + object + "]", ProtocolException.Reason.INVALID_DISPATCH);
    }

    @ParameterizedTest
    @MethodSource("numericTokenBoundaries")
    void enforcesNumericTokenBoundsAtRootArrayAndTrailingPositions(String token, ProtocolException.Reason reason)
            throws IOException {
        reject(token, reason);
        reject("[" + token + "]", reason);
        reject(text(fixture("run")) + " " + token, reason);
    }

    static Stream<Arguments> numericTokenBoundaries() {
        return Stream
                .of(Arguments.of("-" + "1".repeat(64), ProtocolException.Reason.LIMIT_EXCEEDED),
                        Arguments.of("1." + "1".repeat(63), ProtocolException.Reason.LIMIT_EXCEEDED),
                        Arguments.of("1".repeat(62) + "e+1", ProtocolException.Reason.LIMIT_EXCEEDED),
                        Arguments.of("-" + "1".repeat(63), ProtocolException.Reason.INVALID_DISPATCH),
                        Arguments.of("1." + "1".repeat(62), ProtocolException.Reason.INVALID_DISPATCH),
                        Arguments.of("1".repeat(61) + "e+1", ProtocolException.Reason.INVALID_DISPATCH));
    }

    static Stream<String> invalidDispatches() throws IOException {
        String run = text(fixture("run"));
        String management = text(fixture("management"));
        Stream.Builder<String> invalid = Stream.builder();
        invalid.add("").add("null").add("[]").add("true").add("{}").add(run + " {}").add(run + " " + CANARY);
        for (String field : new String[]{"kind", "protocolVersion", "intentId", "payloadSha256", "binding"}) {
            invalid.add(removeField(run, field));
            invalid.add(replaceValue(run, field, "null"));
        }
        for (String field : new String[]{"runId", "attemptId", "podUid", "claimId", "fence", "expiresAt"}) {
            invalid.add(removeField(run, field));
            invalid.add(replaceValue(run, field, "null"));
        }
        for (String field : new String[]{
                "actorId",
                "sessionId",
                "configurationId",
                "configurationRevision",
                "action",
                "expiresAt"}) {
            invalid.add(removeField(management, field));
            invalid.add(replaceValue(management, field, "null"));
        }
        for (String version : new String[]{"\"1\"", "1.0", "true", "2147483648"}) {
            invalid.add(replaceValue(run, "protocolVersion", version));
        }
        for (String kind : new String[]{"Run", "other", CANARY, "com.otilm.ai.runtime.protocol.RunDispatchEnvelope"}) {
            invalid.add(replaceValue(run, "kind", "\"" + kind + "\""));
        }
        for (String id : new String[]{
                "1-1-1-1-1",
                "11111111111141118111111111111111",
                CANARY,
                "",
                "11111111-1111-4111-8111-11111111111z"}) {
            invalid.add(replaceValue(run, "intentId", "\"" + id + "\""));
        }
        for (String digest : new String[]{"a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64), CANARY}) {
            invalid.add(replaceValue(run, "payloadSha256", "\"" + digest + "\""));
        }
        for (String date : new String[]{"2026-10-26", "2026-10-26T12:00:00", "2026-02-30T12:00:00Z", CANARY}) {
            invalid.add(replaceValue(run, "expiresAt", "\"" + date + "\""));
        }
        invalid.add(replaceValue(run, "expiresAt", "1793016000"));
        for (String counter : new String[]{"0", "-1", "1.5", "\"7\"", "9223372036854775808", "true"}) {
            invalid.add(replaceValue(run, "fence", counter));
            invalid.add(replaceValue(management, "configurationRevision", counter));
        }
        invalid.add(replaceValue(management, "action", "\"TOOLS_LIST\""));
        invalid.add(replaceValue(management, "action", "0"));
        invalid.add(replaceValue(run, "payloadSha256", "1".repeat(64)));
        invalid.add(run.replace("\"kind\":\"run\"", "\"kind\":\"management\""));
        invalid.add(management.replace("\"kind\":\"management\"", "\"kind\":\"run\""));
        invalid.add(run.replace("\"binding\":{", "\"binding\":{\"actorId\":\"22222222-2222-4222-8222-222222222222\","));
        invalid
                .add(management
                        .replace("\"binding\":{", "\"binding\":{\"runId\":\"22222222-2222-4222-8222-222222222222\","));
        invalid.add(run.replace("\"kind\":", "\"providerUrl\":\"" + CANARY + "\",\"kind\":"));
        invalid.add(run.replace("\"fence\":7", "\"fence\":7,\"fence\":8"));
        invalid.add(run.replace("\"protocolVersion\":1", "\"protocolVersion\":1,\"protocolVersion\":1"));
        invalid.add(run.replace("\"kind\":\"run\"", "\"kind\":\"run\",\"kind\":\"run\""));
        invalid.add(run.replace("\"fence\":7", "\"fence\":+7"));
        invalid.add(run.replace("\"fence\":7", "\"fence\":07"));
        invalid.add(run.replace("\"fence\":7", "\"fence\":NaN"));
        invalid.add(run.replace("\"fence\":7", "/*" + CANARY + "*/\"fence\":7"));
        return invalid.build();
    }

    @Test
    void rejectsMalformedUtf8AndNullBodySafely() throws IOException {
        byte[] bytes = fixture("run");
        bytes[10] = (byte) 0xc0;
        safeError(bytes, ProtocolException.Reason.INVALID_DISPATCH);
        safeError(null, ProtocolException.Reason.INVALID_DISPATCH);
        assertThrows(ProtocolException.class, () -> codec.writeDispatch(null));
    }

    @Test
    void rejectsNonUtf8EncodingsEvenWhenTheirBytesAreValidUtf8CodeUnits() throws IOException {
        String run = text(fixture("run"));
        for (Charset encoding : new Charset[]{
                StandardCharsets.UTF_16LE,
                StandardCharsets.UTF_16BE,
                Charset.forName("UTF-32LE"),
                Charset.forName("UTF-32BE")}) {
            safeError(run.getBytes(encoding), ProtocolException.Reason.INVALID_DISPATCH);
        }
    }

    @Test
    void bodyLimitIncludesWhitespaceAndAcceptsExactBoundary() throws IOException {
        byte[] bytes = Arrays.copyOf(fixture("run"), BODY_LIMIT);
        Arrays.fill(bytes, fixture("run").length, bytes.length, (byte) ' ');
        assertInstanceOf(RunDispatchEnvelope.class, codec.readDispatch(bytes));
        safeError(Arrays.copyOf(bytes, BODY_LIMIT + 1), ProtocolException.Reason.INPUT_TOO_LARGE);
    }

    @Test
    void rejectsParserLimitsBeforeTypedMapping() {
        reject("{\"extra\":\"" + "a".repeat(65_537) + "\"}", ProtocolException.Reason.LIMIT_EXCEEDED);
        reject("{\"" + "a".repeat(129) + "\":0}", ProtocolException.Reason.LIMIT_EXCEEDED);
        reject("{\"extra\":" + "1".repeat(65) + "}", ProtocolException.Reason.LIMIT_EXCEEDED);
        reject("{\"extra\":-" + "1".repeat(64) + "}", ProtocolException.Reason.LIMIT_EXCEEDED);
        reject("[".repeat(33) + "0" + "]".repeat(33), ProtocolException.Reason.LIMIT_EXCEEDED);
    }

    @Test
    void acceptsParserBoundariesThenRejectsInvalidSchema() {
        reject("{\"extra\":\"" + "a".repeat(65_536) + "\"}", ProtocolException.Reason.INVALID_DISPATCH);
        reject("{\"" + "a".repeat(128) + "\":0}", ProtocolException.Reason.INVALID_DISPATCH);
        reject("{\"extra\":" + "1".repeat(64) + "}", ProtocolException.Reason.INVALID_DISPATCH);
        reject("{\"extra\":-" + "1".repeat(63) + "}", ProtocolException.Reason.INVALID_DISPATCH);
        reject("[".repeat(32) + "0" + "]".repeat(32), ProtocolException.Reason.INVALID_DISPATCH);
    }

    @Test
    void returnedArraysAreIndependent() throws IOException {
        DispatchEnvelope run = codec.readDispatch(fixture("run"));
        byte[] first = codec.writeDispatch(run);
        byte[] snapshot = first.clone();
        byte[] second = codec.writeDispatch(run);
        second[0] = 0;
        codec.writeDispatch(codec.readDispatch(fixture("management")));
        assertArrayEquals(snapshot, first);
        assertArrayEquals(snapshot, codec.writeDispatch(run));
    }

    private void reject(String body, ProtocolException.Reason reason) {
        safeError(utf8(body), reason);
    }

    private void safeError(byte[] body, ProtocolException.Reason reason) {
        ProtocolException error = assertThrows(ProtocolException.class, () -> codec.readDispatch(body));
        assertEquals(reason, error.reason());
        assertFalse(error.toString().contains(CANARY));
        assertNull(error.getCause());
        assertEquals(0, error.getSuppressed().length);
    }

    private static String removeField(String input, String field) {
        if (field.equals("binding")) {
            return input.substring(0, input.indexOf(",\"binding\":")) + "}";
        }
        return input
                .replaceFirst("\\\"" + field + "\\\":(?:\\\"[^\\\"]*\\\"|[0-9]+|\\{.*\\}),?", "")
                .replace(",}", "}");
    }

    private static String replaceValue(String input, String field, String value) {
        if (field.equals("binding")) {
            return input.substring(0, input.indexOf("\"binding\":")) + "\"binding\":" + value + "}";
        }
        return input.replaceFirst("(\\\"" + field + "\\\":)(?:\\\"[^\\\"]*\\\"|[0-9]+|\\{.*\\})", "$1" + value);
    }

    private static byte[] fixture(String name) throws IOException {
        try (var stream = ProtocolCodecTest.class.getResourceAsStream("/protocol/v1/" + name + ".json")) {
            assertNotNull(stream);
            return stream.readAllBytes();
        }
    }

    private static byte[] utf8(String input) {
        return input.getBytes(StandardCharsets.UTF_8);
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
