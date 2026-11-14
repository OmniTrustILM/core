package com.otilm.core.model.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ExactPayload;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

// Structural/ownership tests only. No grant, native identity, current-time or modelUSE authority is supplied here.
class AiModelDispatchStateTest {
    private final UUID run = UUID.randomUUID();
    private final UUID attempt = UUID.randomUUID();
    private final Expected expected = new Expected(run, attempt, 3, 7);
    private final ClaimBinding claim = new ClaimBinding(run, attempt,
            new WorkloadRef("cluster", UUID.randomUUID().toString()), UUID.randomUUID(), 7);
    private final ConnectionVersion model = new ConnectionVersion(UUID.randomUUID(), 1, 2, 3, "lab");

    @Test
    void preparationOwnsBytesBeforeCallerCanChangeThem() {
        byte[] source = new byte[]{1, 2, 3};
        var payload = new ExactPayload(source);
        source[0] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, payload.bytes());
    }

    @Test
    void independentOwnedPayloadsCompareByImmutableByteContent() {
        byte[] input = {1, 2, 3};
        var first = new ExactPayload(input);
        var independent = new ExactPayload(new byte[]{1, 2, 3});
        assertEquals(first, independent);
        assertEquals(first.hashCode(), independent.hashCode());
        assertTrue(Set.of(first).contains(independent));
        input[0] = 9;
        first.bytes()[1] = 8;
        assertEquals(independent, first);
        assertNotEquals(first, new ExactPayload(new byte[]{1, 2, 4}));
        Object absent = null;
        Object differentType = "different type";
        assertNotEquals(first, absent);
        assertNotEquals(first, differentType);
    }

    @Test
    void returnedBytesCannotChangePreparedRequest() {
        var payload = new ExactPayload(new byte[]{1, 2, 3});
        payload.bytes()[0] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, payload.bytes());
    }

    @Test
    void digestRemainsBoundToTheOwnedBytes() {
        var payload = new ExactPayload(new byte[]{1, 2, 3});
        String digest = payload.sha256();
        payload.bytes()[1] = 8;
        assertEquals(digest, payload.sha256());
        assertEquals(PayloadFingerprint.sha256(new byte[]{1, 2, 3}), payload.sha256());
    }

    @Test
    void emptyAndOversizedPayloadsCannotEnterAnIntent() {
        assertThrows(IllegalArgumentException.class, () -> new ExactPayload(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new ExactPayload(new byte[1048577]));
        assertThrows(NullPointerException.class, () -> new ExactPayload(null));
        assertEquals(1048576, new ExactPayload(new byte[1048576]).bytes().length);
    }

    @Test
    void runAndClaimCannotReferToDifferentAuthority() {
        var otherRun = new Expected(UUID.randomUUID(), attempt, 3, 7);
        var otherAttempt = new Expected(run, UUID.randomUUID(), 3, 7);
        var otherFence = new Expected(run, attempt, 3, 8);
        for (Expected mismatch : java.util.List.of(otherRun, otherAttempt, otherFence)) {
            assertThrows(IllegalArgumentException.class, () -> prepare(mismatch, 32));
        }
        assertEquals(Instant.EPOCH, prepare(expected, 32).expiresAt());
    }

    @Test
    void missingConnectionRevisionCannotBindPreparedBytes() {
        UUID connectionId = model.id();
        assertThrows(IllegalArgumentException.class, () -> new ConnectionVersion(connectionId, 0, 2, 3, "lab"));
        assertThrows(IllegalArgumentException.class, () -> new ConnectionVersion(connectionId, 1, 0, 3, "lab"));
        assertThrows(IllegalArgumentException.class, () -> new ConnectionVersion(connectionId, 1, 2, 0, "lab"));
    }

    @Test
    void reservationMustHavePositiveOutputAllowance() {
        assertThrows(IllegalArgumentException.class, () -> prepare(expected, 0));
        assertThrows(IllegalArgumentException.class, () -> prepare(expected, -1));
    }

    @Test
    void redemptionCannotNormalizeOrReplaceTheStoredDigest() {
        String uppercaseDigest = "A".repeat(64);
        String shortDigest = "a".repeat(63);
        assertThrows(IllegalArgumentException.class, () -> redeem(uppercaseDigest));
        assertThrows(IllegalArgumentException.class, () -> redeem(shortDigest));
        assertThrows(NullPointerException.class, () -> redeem(null));
        assertEquals("a".repeat(64), redeem("a".repeat(64)).payloadSha256());
    }

    @Test
    void resolvedDispatchCarriesTheSameReservedOutputCap() {
        var dispatch = new AiModelDispatchState.ResolvedDispatch(UUID.randomUUID(), model, validPayload(), 32,
                URI.create("https://provider.invalid"), "lab-ref", Instant.EPOCH, UUID.randomUUID());
        assertEquals(32, dispatch.outputTokens());
    }

    @Test
    void resolvedDispatchCannotDisagreeWithItsExactBodyCap() {
        var payload = new ExactPayload(
                "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}],\"max_tokens\":100000,\"stream\":false}"
                        .getBytes(StandardCharsets.UTF_8));
        UUID intentId = UUID.randomUUID();
        java.net.URI origin = URI.create("https://provider.invalid");
        UUID correlation = UUID.randomUUID();
        assertThrows(IllegalArgumentException.class, () -> new AiModelDispatchState.ResolvedDispatch(intentId, model,
                payload, 32, origin, "lab-ref", Instant.EPOCH, correlation));
    }

    @Test
    void resolvedDispatchRejectsSecretUrlComponentsAndMissingHost() {
        for (String origin : java.util.List
                .of("https://user:canary@provider.invalid", "https://provider.invalid/?key=canary",
                        "https://provider.invalid/#canary", "https:///missing")) {
            assertThrows(IllegalArgumentException.class, () -> resolved(origin, "lab-ref", 32));
        }
        assertEquals("provider.invalid", resolved("https://provider.invalid:8443/", "lab-ref", 32).origin().getHost());
    }

    @Test
    void invalidReferenceAndZeroOutputCapCannotEscapeAsDispatch() {
        for (String ref : java.util.List.of("Upper", "a".repeat(65), "1starts-with-digit")) {
            assertThrows(IllegalArgumentException.class, () -> resolved("https://provider.invalid", ref, 32));
        }
        assertThrows(IllegalArgumentException.class, () -> resolved("https://provider.invalid", "lab-ref", 0));
    }

    @Test
    void rawPayloadAndPreparationCannotPrintCanaryContent() {
        var payload = new ExactPayload("sensitive-fixture-canary".getBytes(StandardCharsets.UTF_8));
        var preparation = new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected, claim, model, payload, 32,
                Instant.EPOCH);
        assertFalse(payload.toString().contains("sensitive-fixture-canary"));
        assertFalse(preparation.toString().contains("sensitive-fixture-canary"));
    }

    private AiModelDispatchState.ResolvedDispatch resolved(String origin, String ref, int tokens) {
        return new AiModelDispatchState.ResolvedDispatch(UUID.randomUUID(), model, validPayload(), tokens,
                URI.create(origin), ref, Instant.EPOCH, UUID.randomUUID());
    }

    @Test
    void ordinaryUrlTextRemainsExactAndCannotSelectTheProviderOrigin() {
        String json = new String(validPayload().bytes(), StandardCharsets.UTF_8)
                .replace("\"content\":\"x\"", "\"content\":\"Certificate SAN https://certificate.invalid/path\"");
        var payload = new ExactPayload(json.getBytes(StandardCharsets.UTF_8));
        assertTrue(AiModelDispatchPayload.hasOutputLimit(payload, 32));
        var dispatch = new AiModelDispatchState.ResolvedDispatch(UUID.randomUUID(), model, payload, 32,
                URI.create("https://provider.invalid"), "lab-ref", Instant.EPOCH, UUID.randomUUID());
        assertEquals("provider.invalid", dispatch.origin().getHost());
        assertArrayEquals(payload.bytes(), dispatch.payload().bytes());
    }

    @Test
    void structuredMediaDoesNotEnterTheTextOnlyRequest() {
        String base = new String(validPayload().bytes(), StandardCharsets.UTF_8);
        for (String media : java.util.List
                .of("[{\"type\":\"image_url\",\"image_url\":{\"url\":\"https://image.invalid\"}}]",
                        "{\"audio\":\"fixture\"}", "{\"attachment\":\"fixture\"}")) {
            var payload = new ExactPayload(
                    base.replace("\"content\":\"x\"", "\"content\":" + media).getBytes(StandardCharsets.UTF_8));
            assertFalse(AiModelDispatchPayload.hasOutputLimit(payload, 32));
        }
        assertTrue(AiModelDispatchPayload.hasOutputLimit(validPayload(), 32));
    }

    @Test
    void requestFieldsCannotOverrideRoutingHeadersOrCredentials() {
        String base = new String(validPayload().bytes(), StandardCharsets.UTF_8);
        for (String key : java.util.List.of("destination", "base_url", "headers", "api_key")) {
            String changed = base.substring(0, base.length() - 1) + ",\"" + key + "\":\"fixture\"}";
            org.junit.jupiter.api.Assertions
                    .assertFalse(AiModelDispatchPayload
                            .hasOutputLimit(new ExactPayload(changed.getBytes(StandardCharsets.UTF_8)), 32));
        }
        assertTrue(AiModelDispatchPayload.hasOutputLimit(validPayload(), 32));
    }

    @Test
    void textAndMessageCountLimitsHavePositiveBoundaryControls() {
        String base = new String(validPayload().bytes(), StandardCharsets.UTF_8);
        String entry = "{\"role\":\"user\",\"content\":\"x\"}";
        for (int count : new int[]{64, 65}) {
            String json = base.replace(entry, String.join(",", java.util.Collections.nCopies(count, entry)));
            assertEquals(count == 64,
                    AiModelDispatchPayload.hasOutputLimit(new ExactPayload(json.getBytes(StandardCharsets.UTF_8)), 32));
        }
        for (int length : new int[]{65536, 65537}) {
            String json = base.replace("\"content\":\"x\"", "\"content\":\"" + "a".repeat(length) + "\"");
            assertEquals(length == 65536,
                    AiModelDispatchPayload.hasOutputLimit(new ExactPayload(json.getBytes(StandardCharsets.UTF_8)), 32));
        }
    }

    @Test
    void malformedUtf16ModelIdentifiersAreRejectedBeforeSqlBinding() {
        UUID connectionId = UUID.randomUUID();
        for (String malformed : new String[]{"\uD800", "\uDC00", "prefix\uD800suffix", "\uD800x\uDC00"}) {
            assertThrows(IllegalArgumentException.class, () -> new ConnectionVersion(connectionId, 1, 1, 1, malformed));
        }
    }

    @Test
    void decodedPayloadModelMustContainOnlyUnicodeScalarValues() {
        String base = new String(validPayload().bytes(), StandardCharsets.UTF_8);
        for (String escaped : new String[]{"\\ud800", "\\udc00", "prefix\\ud800suffix", "\\ud800x\\udc00"}) {
            var payload = new ExactPayload(base
                    .replace("\"model\":\"lab\"", "\"model\":\"" + escaped + "\"")
                    .getBytes(StandardCharsets.UTF_8));
            assertFalse(AiModelDispatchPayload.hasOutputLimit(payload, 32));
        }
        String scalar = "\uD83D\uDE00";
        var valid = new ExactPayload(
                base.replace("\"model\":\"lab\"", "\"model\":\"" + scalar + "\"").getBytes(StandardCharsets.UTF_8));
        assertTrue(AiModelDispatchPayload.hasModelAndOutputLimit(valid, 32, scalar));
    }

    @Test
    void canonicalIdentifierComparisonDoesNotFoldCaseTrimOrNormalizeUnicode() throws Exception {
        for (String other : new String[]{"Lab", " lab", "lab ", "other"}) {
            assertFalse(AiModelDispatchPayload.hasModelAndOutputLimit(payloadWithModel(other), 32, "lab"));
        }
        assertFalse(AiModelDispatchPayload.hasModelAndOutputLimit(payloadWithModel("\u00e9"), 32, "e\u0301"));
        assertTrue(AiModelDispatchPayload.hasModelAndOutputLimit(payloadWithModel("e\u0301"), 32, "e\u0301"));
        String escaped = new String(validPayload().bytes(), StandardCharsets.UTF_8)
                .replace("\"model\":\"lab\"", "\"model\":\"\\u006c\\u0061\\u0062\"");
        var payload = new ExactPayload(escaped.getBytes(StandardCharsets.UTF_8));
        byte[] original = payload.bytes();
        assertTrue(AiModelDispatchPayload.hasModelAndOutputLimit(payload, 32, "lab"));
        assertArrayEquals(original, payload.bytes());
    }

    @Test
    void identifierLimitCounts255UnicodeScalarsAndRejectsBlankOr256WithoutNormalization() throws Exception {
        UUID connectionId = UUID.randomUUID();
        String maximum = "\uD83D\uDE00".repeat(255);
        assertEquals(maximum, new ConnectionVersion(connectionId, 1, 1, 1, maximum).modelIdentifier());
        assertTrue(AiModelDispatchPayload.hasModelAndOutputLimit(payloadWithModel(maximum), 32, maximum));
        String tooLong = maximum + "\uD83D\uDE00";
        assertThrows(IllegalArgumentException.class, () -> new ConnectionVersion(connectionId, 1, 1, 1, tooLong));
        assertFalse(AiModelDispatchPayload.hasOutputLimit(payloadWithModel(tooLong), 32));
        for (String missing : new String[]{null, "", " ", "\u2003"}) {
            assertThrows(IllegalArgumentException.class, () -> new ConnectionVersion(connectionId, 1, 1, 1, missing));
            assertFalse(AiModelDispatchPayload.hasModelAndOutputLimit(validPayload(), 32, missing));
        }
    }

    @Test
    void resolvedDispatchRequiresTheExactPinnedModelIdentifier() {
        UUID id = UUID.randomUUID();
        UUID correlation = UUID.randomUUID();
        var selected = new ConnectionVersion(id, 1, 1, 1, "other");
        var payload = validPayload();
        var origin = URI.create("https://provider.invalid");
        assertThrows(IllegalArgumentException.class, () -> new AiModelDispatchState.ResolvedDispatch(id, selected,
                payload, 32, origin, "lab-ref", Instant.EPOCH, correlation));
    }

    @Test
    void overlongUtf8CannotAliasThePinnedModelIdentifier() {
        for (byte[] encodedL : new byte[][]{
                {(byte) 0xc1, (byte) 0xac},
                {(byte) 0xe0, (byte) 0x81, (byte) 0xac},
                {(byte) 0xf0, (byte) 0x80, (byte) 0x81, (byte) 0xac}}) {
            byte[] name = java.util.Arrays.copyOf(encodedL, encodedL.length + 2);
            name[name.length - 2] = 'a';
            name[name.length - 1] = 'b';
            var payload = replacePayloadBytes("lab", name);
            assertFalse(AiModelDispatchPayload.hasModelAndOutputLimit(payload, 32, "lab"),
                    HexFormat.of().formatHex(name));
        }
    }

    @Test
    void malformedUtf8InMessageContentIsRejectedBeforeDispatch() {
        for (byte[] invalid : new byte[][]{
                {(byte) 0xc1, (byte) 0xb8},
                {(byte) 0xc0, (byte) 0x80},
                {(byte) 0x80},
                {(byte) 0xc2},
                {(byte) 0xe2, 0x28, (byte) 0xa1},
                {(byte) 0xed, (byte) 0xa0, (byte) 0x80},
                {(byte) 0xf4, (byte) 0x90, (byte) 0x80, (byte) 0x80}}) {
            var payload = replacePayloadBytes("x", invalid);
            assertFalse(AiModelDispatchPayload.hasOutputLimit(payload, 32), HexFormat.of().formatHex(invalid));
        }
    }

    @Test
    void utf8ByteOrderMarkIsNotAcceptedAsPartOfTheWireFormat() {
        byte[] original = validPayload().bytes();
        byte[] marked = new byte[original.length + 3];
        marked[0] = (byte) 0xef;
        marked[1] = (byte) 0xbb;
        marked[2] = (byte) 0xbf;
        System.arraycopy(original, 0, marked, 3, original.length);
        assertFalse(AiModelDispatchPayload.hasOutputLimit(new ExactPayload(marked), 32));
        assertTrue(AiModelDispatchPayload.hasOutputLimit(validPayload(), 32));
    }

    @Test
    void jsonEncodingAutodetectionCannotAdmitUtf16OrUtf32() {
        String json = new String(validPayload().bytes(), StandardCharsets.UTF_8);
        for (var charset : new java.nio.charset.Charset[]{
                StandardCharsets.UTF_16LE,
                StandardCharsets.UTF_16BE,
                java.nio.charset.Charset.forName("UTF-32LE"),
                java.nio.charset.Charset.forName("UTF-32BE")}) {
            var payload = new ExactPayload(json.getBytes(charset));
            assertFalse(AiModelDispatchPayload.hasOutputLimit(payload, 32), charset.name());
        }
    }

    @Test
    void validUtf8AndInteriorBomRemainExactWithoutFilteringOrdinaryText() throws Exception {
        String identifier = "\uD83D\uDE00\u00e9";
        String json = new String(payloadWithModel(identifier).bytes(), StandardCharsets.UTF_8)
                .replace("\"content\":\"x\"", "\"content\":\"\uD83D\uDE00\uFEFF\\u0000 https://example.invalid\"");
        byte[] original = json.getBytes(StandardCharsets.UTF_8);
        var payload = new ExactPayload(original);
        assertTrue(AiModelDispatchPayload.hasModelAndOutputLimit(payload, 32, identifier));
        assertArrayEquals(original, payload.bytes());
    }

    @Test
    void nulCannotEnterAConnectionPinOrDecodedModelIdentifier() throws Exception {
        String identifier = "lab" + (char) 0;
        UUID connectionId = model.id();
        assertThrows(IllegalArgumentException.class, () -> new ConnectionVersion(connectionId, 1, 2, 3, identifier));
        assertFalse(AiModelDispatchPayload.hasOutputLimit(payloadWithModel(identifier), 32));
    }

    private static ExactPayload replacePayloadBytes(String originalText, byte[] replacement) {
        byte[] original = validPayload().bytes();
        int index = new String(original, StandardCharsets.UTF_8).indexOf(originalText);
        assertTrue(index >= 0);
        byte[] changed = new byte[original.length - originalText.length() + replacement.length];
        System.arraycopy(original, 0, changed, 0, index);
        System.arraycopy(replacement, 0, changed, index, replacement.length);
        System
                .arraycopy(original, index + originalText.length(), changed, index + replacement.length,
                        original.length - index - originalText.length());
        return new ExactPayload(changed);
    }

    private static ExactPayload payloadWithModel(String modelIdentifier) throws Exception {
        String name = new ObjectMapper().writeValueAsString(modelIdentifier);
        String json = new String(validPayload().bytes(), StandardCharsets.UTF_8)
                .replace("\"model\":\"lab\"", "\"model\":" + name);
        return new ExactPayload(json.getBytes(StandardCharsets.UTF_8));
    }

    private static ExactPayload validPayload() {
        return new ExactPayload(
                "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}],\"max_tokens\":32,\"stream\":false}"
                        .getBytes(StandardCharsets.UTF_8));
    }

    private RunPreparation prepare(Expected selected, int outputTokens) {
        return new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), selected, claim, model,
                new ExactPayload(new byte[]{1}), outputTokens, Instant.EPOCH);
    }

    private RunRedemption redeem(String digest) {
        return new RunRedemption(UUID.randomUUID(), expected, claim, model, digest, Instant.EPOCH, UUID.randomUUID());
    }
}
