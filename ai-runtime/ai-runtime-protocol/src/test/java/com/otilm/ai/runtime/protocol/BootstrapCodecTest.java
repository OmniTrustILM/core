package com.otilm.ai.runtime.protocol;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BootstrapCodecTest {
    private static final UUID RUN = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID ATTEMPT = UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static final UUID POD = UUID.fromString("44444444-4444-4444-8444-444444444444");
    private static final UUID CLAIM = UUID.fromString("55555555-5555-4555-8555-555555555555");
    private static final Instant LEASE = Instant.parse("2026-10-29T12:00:00Z");
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ProtocolCodec codec = new ProtocolCodec();

    @Test
    void roundTripsTheBoundedReferenceRequest() throws IOException {
        byte[] bytes = fixture("request");
        assertEquals(new BootstrapRequest(1, RUN, ATTEMPT, POD), codec.readBootstrapRequest(bytes));
        assertArrayEquals(bytes, codec.writeBootstrapRequest(codec.readBootstrapRequest(bytes)));
    }

    @Test
    void roundTripsAnExclusiveClaimedReplyWithReceiverLease() throws IOException {
        byte[] bytes = fixture("claimed");
        BootstrapClaimedReply claimed = assertInstanceOf(BootstrapClaimedReply.class, codec.readBootstrapReply(bytes));
        assertEquals(new BootstrapClaimedReply(1, binding(), LEASE), claimed);
        assertArrayEquals(bytes, codec.writeBootstrapReply(claimed));
    }

    @Test
    void roundTripsPendingWithoutAnyClaimFields() throws IOException {
        byte[] bytes = fixture("pending");
        BootstrapPendingReply pending = assertInstanceOf(BootstrapPendingReply.class, codec.readBootstrapReply(bytes));
        assertEquals(new BootstrapPendingReply(1, 250), pending);
        assertArrayEquals(bytes, codec.writeBootstrapReply(pending));
        assertEquals(3, JSON.readTree(bytes).size());
    }

    @ParameterizedTest
    @ValueSource(ints = {100, 1000})
    void acceptsBothRetryHintBoundaries(int hint) {
        BootstrapReply pending = new BootstrapPendingReply(1, hint);
        assertEquals(pending, codec.readBootstrapReply(codec.writeBootstrapReply(pending)));
    }

    @ParameterizedTest
    @ValueSource(ints = {Integer.MIN_VALUE, -1, 0, 99, 1001, Integer.MAX_VALUE})
    void rejectsRetryHintsOutsideTheFixedRange(int hint) {
        ProtocolException failure = assertThrows(ProtocolException.class, () -> new BootstrapPendingReply(1, hint));
        safe(failure, ProtocolException.Reason.INVALID_MESSAGE);
    }

    @ParameterizedTest
    @MethodSource("malformed")
    void rejectsMalformedClosedShapesWithoutInputOrNestedCauses(String family, String wire) {
        rejected(family, utf8(wire), ProtocolException.Reason.INVALID_MESSAGE);
    }

    static Stream<Arguments> malformed() throws IOException {
        Stream.Builder<Arguments> cases = Stream.builder();
        for (String family : new String[]{"request", "claimed", "pending"}) {
            String wire = new String(fixture(family), StandardCharsets.UTF_8);
            ObjectNode original = (ObjectNode) JSON.readTree(wire);
            for (String invalid : new String[]{"", "null", "[]", "true", "0", "{}", wire + " {}"}) {
                cases.add(Arguments.of(family, invalid));
            }
            for (String field : original.propertyStream().map(Map.Entry::getKey).toList()) {
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
                    "actorId",
                    "token",
                    "url",
                    "expiresAt",
                    "namespace",
                    "@class",
                    "instruction"}) {
                ObjectNode injected = original.deepCopy();
                injected.put(field, "untrusted-canary");
                cases.add(Arguments.of(family, injected.toString()));
            }
            for (String version : new String[]{"\"1\"", "1.0", "1e0", "true", "2147483648"}) {
                cases
                        .add(Arguments
                                .of(family, wire.replace("\"protocolVersion\":1", "\"protocolVersion\":" + version)));
            }
            if (family.equals("request")) {
                for (String field : new String[]{"runId", "attemptId", "podUid"}) {
                    ObjectNode shortId = original.deepCopy();
                    shortId.put(field, "1-1-1-1-1");
                    cases.add(Arguments.of(family, shortId.toString()));
                }
            } else {
                for (String status : new String[]{"CLAIMED", "com.otilm.Untrusted", "unknown", ""}) {
                    ObjectNode wrongStatus = original.deepCopy();
                    wrongStatus.put("status", status);
                    cases.add(Arguments.of(family, wrongStatus.toString()));
                }
            }
            if (family.equals("pending")) {
                for (String hint : new String[]{"99", "1001", "1.0", "1e2", "\"250\"", "true", "2147483648"}) {
                    cases
                            .add(Arguments
                                    .of(family,
                                            wire.replace("\"retryAfterMillis\":250", "\"retryAfterMillis\":" + hint)));
                }
                ObjectNode mixed = original.deepCopy();
                mixed.set("binding", JSON.valueToTree(binding()));
                cases.add(Arguments.of(family, mixed.toString()));
            }
            if (family.equals("claimed")) {
                ObjectNode mixed = original.deepCopy();
                mixed.put("retryAfterMillis", 250);
                cases.add(Arguments.of(family, mixed.toString()));
                for (String instant : new String[]{
                        "2026-02-30T00:00:00Z",
                        "2026-10-29T12:00:00+00:00",
                        "untrusted-canary"}) {
                    ObjectNode badLease = original.deepCopy();
                    badLease.put("leaseExpiresAt", instant);
                    cases.add(Arguments.of(family, badLease.toString()));
                }
                ObjectNode binding = (ObjectNode) original.get("binding");
                for (String field : binding.propertyStream().map(Map.Entry::getKey).toList()) {
                    ObjectNode incomplete = original.deepCopy();
                    ((ObjectNode) incomplete.get("binding")).remove(field);
                    cases.add(Arguments.of(family, incomplete.toString()));
                }
                cases.add(Arguments.of(family, wire.replace("\"fence\":7", "\"fence\":0")));
            }
        }
        return cases.build();
    }

    @ParameterizedTest
    @ValueSource(strings = {"request", "claimed", "pending"})
    void rejectsFutureVersionsAndInvalidUtf8WithinTheControlBound(String family) throws IOException {
        byte[] bytes = fixture(family);
        String wire = new String(bytes, StandardCharsets.UTF_8);
        rejected(family, utf8(wire.replace("\"protocolVersion\":1", "\"protocolVersion\":2")),
                ProtocolException.Reason.UNSUPPORTED_VERSION);
        byte[] malformed = Arrays.copyOf(bytes, bytes.length + 1);
        malformed[bytes.length] = (byte) 0xff;
        rejected(family, malformed, ProtocolException.Reason.INVALID_MESSAGE);
        byte[] maximum = Arrays.copyOf(bytes, 4096);
        Arrays.fill(maximum, bytes.length, maximum.length, (byte) ' ');
        assertNotNull(read(family, maximum));
        rejected(family, Arrays.copyOf(maximum, 4097), ProtocolException.Reason.INPUT_TOO_LARGE);
        rejected(family, null, ProtocolException.Reason.INVALID_MESSAGE);
    }

    @Test
    void rejectsMissingReferencesAndNullWrites() {
        assertThrows(ProtocolException.class, () -> new BootstrapRequest(1, null, ATTEMPT, POD));
        assertThrows(ProtocolException.class, () -> new BootstrapRequest(1, RUN, null, POD));
        assertThrows(ProtocolException.class, () -> new BootstrapRequest(1, RUN, ATTEMPT, null));
        assertThrows(ProtocolException.class, () -> new BootstrapClaimedReply(1, null, LEASE));
        var binding = binding();
        assertThrows(ProtocolException.class, () -> new BootstrapClaimedReply(1, binding, null));
        safe(assertThrows(ProtocolException.class, () -> codec.writeBootstrapRequest(null)),
                ProtocolException.Reason.INVALID_MESSAGE);
        safe(assertThrows(ProtocolException.class, () -> codec.writeBootstrapReply(null)),
                ProtocolException.Reason.INVALID_MESSAGE);
    }

    private void rejected(String family, byte[] wire, ProtocolException.Reason reason) {
        safe(assertThrows(ProtocolException.class, () -> read(family, wire)), reason);
    }

    private Object read(String family, byte[] wire) {
        return family.equals("request") ? codec.readBootstrapRequest(wire) : codec.readBootstrapReply(wire);
    }

    private static void safe(ProtocolException exception, ProtocolException.Reason reason) {
        assertEquals(reason, exception.reason());
        assertEquals(reason.name(), exception.getMessage());
        assertNull(exception.getCause());
        assertEquals(0, exception.getSuppressed().length);
    }

    private static ClaimBinding binding() {
        return new ClaimBinding(RUN, ATTEMPT, POD, CLAIM, 7);
    }

    private static byte[] fixture(String family) throws IOException {
        try (var resource = BootstrapCodecTest.class
                .getResourceAsStream("/protocol/v1/bootstrap-" + family + ".json")) {
            assertNotNull(resource);
            return resource.readAllBytes();
        }
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
