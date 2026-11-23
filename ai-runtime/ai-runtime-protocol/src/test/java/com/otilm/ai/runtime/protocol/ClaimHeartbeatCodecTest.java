package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ClaimHeartbeatCodecTest {
    private static final String CANARY = "private-canary-credential";
    private static final UUID ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final Instant EXPIRY = Instant.parse("2026-10-26T12:00:00Z");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String[] FAMILIES = {"claim-heartbeat-request", "claim-heartbeat-reply", "runtime-error"};
    private final ProtocolCodec codec = new ProtocolCodec();

    @Test
    void readsAndWritesCanonicalHeartbeatRequest() throws IOException {
        byte[] bytes = fixture(FAMILIES[0]);
        ClaimHeartbeatRequest request = assertDoesNotThrow(() -> codec.readClaimHeartbeatRequest(bytes));
        assertEquals(new ClaimHeartbeatRequest(1, expectedBinding(), 9), request);
        assertArrayEquals(bytes, codec.writeClaimHeartbeatRequest(request));
    }

    @Test
    void readsAndWritesReceiverIssuedLeaseReply() throws IOException {
        byte[] bytes = fixture(FAMILIES[1]);
        ClaimHeartbeatReply reply = assertDoesNotThrow(() -> codec.readClaimHeartbeatReply(bytes));
        assertEquals(new ClaimHeartbeatReply(1, expectedBinding(), 9, EXPIRY), reply);
        assertArrayEquals(bytes, codec.writeClaimHeartbeatReply(reply));
    }

    @ParameterizedTest
    @EnumSource(RuntimeErrorCode.class)
    void roundTripsEveryControlledErrorWithoutFreeText(RuntimeErrorCode code) throws IOException {
        byte[] expected = text(fixture(FAMILIES[2]))
                .replace("INVALID_REQUEST", code.name())
                .getBytes(StandardCharsets.UTF_8);
        RuntimeErrorReply error = codec.readRuntimeError(expected);
        assertEquals(new RuntimeErrorReply(1, code, ID), error);
        assertArrayEquals(expected, codec.writeRuntimeError(error));
    }

    @ParameterizedTest
    @MethodSource("invalidMessages")
    void rejectsClosedShapeViolationsWithoutLeakingInput(String family, String body) {
        reject(family, utf8(body), ProtocolException.Reason.INVALID_MESSAGE);
    }

    static Stream<Arguments> invalidMessages() throws IOException {
        Stream.Builder<Arguments> cases = Stream.builder();
        for (String family : FAMILIES) {
            String wire = text(fixture(family));
            ObjectNode original = (ObjectNode) JSON.readTree(wire);
            for (String malformed : new String[]{
                    "",
                    "null",
                    "true",
                    "1",
                    "[]",
                    "{}",
                    wire + " {}",
                    wire + " " + CANARY}) {
                cases.add(Arguments.of(family, malformed));
            }
            for (String field : iterableFields(original)) {
                ObjectNode missing = original.deepCopy();
                missing.remove(field);
                cases.add(Arguments.of(family, missing.toString()));
                ObjectNode nil = original.deepCopy();
                nil.putNull(field);
                cases.add(Arguments.of(family, nil.toString()));
                cases
                        .add(Arguments
                                .of(family, wire.substring(0, wire.length() - 1) + ",\"" + field + "\":"
                                        + original.get(field) + "}"));
            }
            for (String field : new String[]{
                    "kind",
                    "intentId",
                    "payloadSha256",
                    "runId",
                    "attemptId",
                    "podUid",
                    "claimId",
                    "fence",
                    "actorId",
                    "sessionId",
                    "configurationId",
                    "action",
                    "expiresAt",
                    "url",
                    "token",
                    "permission",
                    CANARY}) {
                ObjectNode injected = original.deepCopy();
                injected.put(field, CANARY);
                cases.add(Arguments.of(family, injected.toString()));
            }
            for (String version : new String[]{"null", "\"1\"", "1.0", "1e0", "true", "2147483648"}) {
                cases
                        .add(Arguments
                                .of(family, wire.replace("\"protocolVersion\":1", "\"protocolVersion\":" + version)));
            }
            if (!family.equals("runtime-error")) {
                ObjectNode binding = (ObjectNode) original.get("binding");
                for (String field : iterableFields(binding)) {
                    ObjectNode missing = original.deepCopy();
                    ((ObjectNode) missing.get("binding")).remove(field);
                    cases.add(Arguments.of(family, missing.toString()));
                    ObjectNode nil = original.deepCopy();
                    ((ObjectNode) nil.get("binding")).putNull(field);
                    cases.add(Arguments.of(family, nil.toString()));
                    cases
                            .add(Arguments
                                    .of(family, wire
                                            .replace("\"binding\":{",
                                                    "\"binding\":{\"" + field + "\":" + binding.get(field) + ",")));
                }
                for (String field : new String[]{
                        "actorId",
                        "sessionId",
                        "configurationId",
                        "configurationRevision",
                        "action",
                        "expiresAt",
                        "leaseExpiresAt",
                        "token",
                        "url",
                        "permission"}) {
                    ObjectNode injected = original.deepCopy();
                    ((ObjectNode) injected.get("binding")).put(field, CANARY);
                    cases.add(Arguments.of(family, injected.toString()));
                }
                for (String counter : new String[]{
                        "0",
                        "-1",
                        "9223372036854775808",
                        "1e0",
                        "1.0",
                        "\"1\"",
                        "true",
                        "null"}) {
                    cases.add(Arguments.of(family, wire.replace("\"sequence\":9", "\"sequence\":" + counter)));
                    cases.add(Arguments.of(family, wire.replace("\"fence\":7", "\"fence\":" + counter)));
                }
            }
            for (String field : family.equals("runtime-error")
                    ? new String[]{"correlationId"}
                    : new String[]{"runId", "attemptId", "podUid", "claimId"}) {
                for (String bad : new String[]{"\"1-1-1-1-1\"", "\"" + CANARY + "\"", "1", "true", "\"é😀\""}) {
                    cases
                            .add(Arguments
                                    .of(family, wire
                                            .replaceFirst("\"" + field + "\":\"[^\"]*\"", "\"" + field + "\":" + bad)));
                }
            }
            for (String other : FAMILIES) {
                if (!other.equals(family)) {
                    cases.add(Arguments.of(family, text(fixture(other))));
                }
            }
            cases.add(Arguments.of(family, text(fixture("run"))));
            cases.add(Arguments.of(family, text(fixture("management"))));
        }
        String request = text(fixture(FAMILIES[0]));
        cases
                .add(Arguments
                        .of(FAMILIES[0], request.substring(0, request.length() - 1)
                                + ",\"leaseExpiresAt\":\"2026-10-26T12:00:00Z\"}"));
        for (String bad : new String[]{
                "0",
                "\"DENIED \"",
                "\" DENIED\"",
                "\"\"",
                "\"UNKNOWN\"",
                "\"denied\"",
                "true",
                "\"" + CANARY + "\""}) {
            cases.add(Arguments.of(FAMILIES[2], text(fixture(FAMILIES[2])).replace("\"INVALID_REQUEST\"", bad)));
        }
        return cases.build();
    }

    @ParameterizedTest
    @MethodSource("unsupportedVersions")
    void preservesUnsupportedVersionClassification(String family, int version) throws IOException {
        reject(family, utf8(text(fixture(family)).replace("\"protocolVersion\":1", "\"protocolVersion\":" + version)),
                ProtocolException.Reason.UNSUPPORTED_VERSION);
    }

    static Stream<Arguments> unsupportedVersions() {
        return Arrays
                .stream(FAMILIES)
                .flatMap(
                        family -> Stream.of(0, 2, -1, Integer.MAX_VALUE).map(version -> Arguments.of(family, version)));
    }

    @ParameterizedTest
    @MethodSource("acceptedTimes")
    void retainsExistingUtcTimestampNormalization(String wire, String normalized) throws IOException {
        String input = text(fixture(FAMILIES[1])).replace(EXPIRY.toString(), wire);
        ClaimHeartbeatReply reply = codec.readClaimHeartbeatReply(utf8(input));
        assertEquals(Instant.parse(normalized), reply.leaseExpiresAt());
        assertArrayEquals(utf8(text(fixture(FAMILIES[1])).replace(EXPIRY.toString(), normalized)),
                codec.writeClaimHeartbeatReply(reply));
    }

    static Stream<Arguments> acceptedTimes() throws IOException {
        Stream.Builder<Arguments> cases = Stream.builder();
        for (JsonNode row : JSON.readTree(fixture("timestamps")).get("accepted")) {
            cases.add(Arguments.of(row.get("wire").asText(), row.get("normalized").asText()));
        }
        return cases.build();
    }

    @ParameterizedTest
    @MethodSource("rejectedTimes")
    void rejectsMalformedCalendarAndNonUtcLeaseExpiry(String wire) throws IOException {
        reject(FAMILIES[1], utf8(text(fixture(FAMILIES[1])).replace(EXPIRY.toString(), wire)),
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    static Stream<String> rejectedTimes() throws IOException {
        JsonNode cases = JSON.readTree(fixture("timestamps"));
        return Stream.concat(streamText(cases.get("rejected")), streamText(cases.get("semanticRejected")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"claim-heartbeat-request", "claim-heartbeat-reply", "runtime-error"})
    void boundsAllMessagesByUtf8BytesIncludingWhitespace(String family) throws IOException {
        byte[] canonical = fixture(family);
        byte[] maximum = Arrays.copyOf(canonical, 4096);
        Arrays.fill(maximum, canonical.length, maximum.length, (byte) ' ');
        assertNotNull(read(family, maximum));
        reject(family, Arrays.copyOf(maximum, 4097), ProtocolException.Reason.INPUT_TOO_LARGE);
        reject(family, utf8("{\"unknown\":\"" + "é".repeat(2048) + "\"}"), ProtocolException.Reason.INPUT_TOO_LARGE);
        reject(family, utf8("{\"unknown\":\"" + CANARY.repeat(200) + "\"}"), ProtocolException.Reason.INPUT_TOO_LARGE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"claim-heartbeat-request", "claim-heartbeat-reply", "runtime-error"})
    void rejectsMalformedUtf8AndParserLimitViolations(String family) throws IOException {
        reject(family, null, ProtocolException.Reason.INVALID_MESSAGE);
        reject(family, new byte[]{(byte) 0xc3, 0x28}, ProtocolException.Reason.INVALID_MESSAGE);
        reject(family, new byte[]{(byte) 0xff}, ProtocolException.Reason.INVALID_MESSAGE);
        reject(family, utf8("{\"" + "x".repeat(129) + "\":0}"), ProtocolException.Reason.LIMIT_EXCEEDED);
        reject(family, utf8("[".repeat(33) + "0" + "]".repeat(33)), ProtocolException.Reason.LIMIT_EXCEEDED);
        for (String token : new String[]{
                "1".repeat(65),
                "-" + "1".repeat(64),
                "1." + "1".repeat(63),
                "1".repeat(62) + "e+1"}) {
            reject(family, utf8("{\"unknown\":" + token + "}"), ProtocolException.Reason.LIMIT_EXCEEDED);
            reject(family, utf8(text(fixture(family)) + " " + token), ProtocolException.Reason.LIMIT_EXCEEDED);
        }
        reject(family, utf8("{\"" + "x".repeat(128) + "\":0}"), ProtocolException.Reason.INVALID_MESSAGE);
    }

    @Test
    void doesNotInterpretParsedSequenceOrExpiryAsCurrentLeaseAuthority() throws IOException {
        ClaimHeartbeatReply reply = codec
                .readClaimHeartbeatReply(utf8(text(fixture(FAMILIES[1]))
                        .replace(EXPIRY.toString(), "2000-01-01T00:00:00Z")
                        .replace("\"sequence\":9", "\"sequence\":9223372036854775807")
                        .replace("\"fence\":7", "\"fence\":9223372036854775807")));
        assertEquals(Instant.parse("2000-01-01T00:00:00Z"), reply.leaseExpiresAt());
        assertEquals(Long.MAX_VALUE, reply.sequence());
        assertEquals(Long.MAX_VALUE, reply.binding().fence());
        assertEquals(reply, codec.readClaimHeartbeatReply(codec.writeClaimHeartbeatReply(reply)));
    }

    @Test
    void rejectsInvalidDirectValuesBeforeSerialization() {
        invalid(() -> new ClaimBinding(null, ID, ID, ID, 1));
        invalid(() -> new ClaimBinding(ID, null, ID, ID, 1));
        invalid(() -> new ClaimBinding(ID, ID, null, ID, 1));
        invalid(() -> new ClaimBinding(ID, ID, ID, null, 1));
        invalid(() -> new ClaimBinding(ID, ID, ID, ID, 0));
        invalid(() -> new ClaimBinding(ID, ID, ID, ID, -1));
        invalid(() -> new ClaimHeartbeatRequest(1, null, 1));
        invalid(() -> new ClaimHeartbeatReply(1, null, 1, EXPIRY));
        invalid(() -> new ClaimHeartbeatReply(1, expectedBinding(), 1, null));
        invalid(() -> new RuntimeErrorReply(1, null, ID));
        invalid(() -> new RuntimeErrorReply(1, RuntimeErrorCode.DENIED, null));
        for (long sequence : new long[]{0, -1}) {
            invalid(() -> new ClaimHeartbeatRequest(1, expectedBinding(), sequence));
            invalid(() -> new ClaimHeartbeatReply(1, expectedBinding(), sequence, EXPIRY));
        }
        invalid(() -> codec.writeClaimHeartbeatRequest(null));
        invalid(() -> codec.writeClaimHeartbeatReply(null));
        invalid(() -> codec.writeRuntimeError(null));
        assertReason(() -> new ClaimHeartbeatRequest(2, expectedBinding(), 1),
                ProtocolException.Reason.UNSUPPORTED_VERSION);
        assertReason(() -> new ClaimHeartbeatReply(2, expectedBinding(), 1, EXPIRY),
                ProtocolException.Reason.UNSUPPORTED_VERSION);
        assertReason(() -> new RuntimeErrorReply(2, RuntimeErrorCode.DENIED, ID),
                ProtocolException.Reason.UNSUPPORTED_VERSION);
    }

    @Test
    void retainsDispatchOnlyBoundaryAndIndependentSerializationBuffers() throws IOException {
        for (String family : FAMILIES) {
            assertReason(() -> codec.readDispatch(fixture(family)), ProtocolException.Reason.INVALID_DISPATCH);
        }
        ClaimHeartbeatRequest request = codec.readClaimHeartbeatRequest(fixture(FAMILIES[0]));
        byte[] first = codec.writeClaimHeartbeatRequest(request);
        byte[] second = codec.writeClaimHeartbeatRequest(request);
        second[0] = 0;
        assertArrayEquals(fixture(FAMILIES[0]), first);
        assertArrayEquals(first, codec.writeClaimHeartbeatRequest(request));
    }

    private Object read(String family, byte[] bytes) {
        return switch (family) {
            case "claim-heartbeat-request" -> codec.readClaimHeartbeatRequest(bytes);
            case "claim-heartbeat-reply" -> codec.readClaimHeartbeatReply(bytes);
            case "runtime-error" -> codec.readRuntimeError(bytes);
            default -> throw new AssertionError(family);
        };
    }

    private void reject(String family, byte[] bytes, ProtocolException.Reason reason) {
        assertReason(() -> read(family, bytes), reason);
    }

    private static void invalid(org.junit.jupiter.api.function.Executable action) {
        assertReason(action, ProtocolException.Reason.INVALID_MESSAGE);
    }

    private static void assertReason(org.junit.jupiter.api.function.Executable action,
            ProtocolException.Reason reason) {
        ProtocolException error = assertThrows(ProtocolException.class, action);
        assertEquals(reason, error.reason());
        assertEquals(reason.name(), error.getMessage());
        assertNull(error.getCause());
        assertEquals(0, error.getSuppressed().length);
        assertEquals(0, error.getStackTrace().length);
    }

    private static ClaimBinding expectedBinding() {
        return new ClaimBinding(UUID.fromString("22222222-2222-4222-8222-222222222222"),
                UUID.fromString("33333333-3333-4333-8333-333333333333"),
                UUID.fromString("44444444-4444-4444-8444-444444444444"),
                UUID.fromString("55555555-5555-4555-8555-555555555555"), 7);
    }

    private static Iterable<String> iterableFields(ObjectNode node) {
        return node::fieldNames;
    }

    private static Stream<String> streamText(JsonNode node) {
        return java.util.stream.StreamSupport.stream(node.spliterator(), false).map(JsonNode::asText);
    }

    private static byte[] fixture(String name) throws IOException {
        try (var stream = ClaimHeartbeatCodecTest.class.getResourceAsStream("/protocol/v1/" + name + ".json")) {
            assertNotNull(stream);
            return stream.readAllBytes();
        }
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
