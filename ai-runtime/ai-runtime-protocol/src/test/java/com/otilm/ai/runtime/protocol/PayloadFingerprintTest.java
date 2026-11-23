package com.otilm.ai.runtime.protocol;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

class PayloadFingerprintTest {
    private static final int MAX_INPUT_BYTES = 1_048_576;

    @ParameterizedTest
    @MethodSource("knownSha256Vectors")
    void returnsKnownDigest_whenHashingStandardVector(byte[] input, String expectedDigest) {
        // given — a payload with a published SHA-256 digest

        // when
        String digest = PayloadFingerprint.sha256(input);

        // then
        assertThat(digest).isEqualTo(expectedDigest);
    }

    @Test
    void returnsDifferentDigest_whenWhitespaceIsAdded() {
        // given
        byte[] compact = bytes("{}");
        byte[] spaced = bytes("{ }");

        // when
        String compactDigest = PayloadFingerprint.sha256(compact);
        String spacedDigest = PayloadFingerprint.sha256(spaced);

        // then
        assertThat(compactDigest).isNotEqualTo(spacedDigest);
    }

    @Test
    void returnsDifferentDigest_whenOneByteChanges() {
        // given
        byte[] original = bytes("abc");
        byte[] changed = bytes("abd");

        // when
        String originalDigest = PayloadFingerprint.sha256(original);
        String changedDigest = PayloadFingerprint.sha256(changed);

        // then
        assertThat(originalDigest).isNotEqualTo(changedDigest);
    }

    @Test
    void doesNotRetainBuffer_whenCallerMutatesInputAfterwards() {
        // given
        byte[] input = new byte[MAX_INPUT_BYTES];
        String original = PayloadFingerprint.sha256(input);

        // when
        input[0] = 1;
        String afterMutation = PayloadFingerprint.sha256(input);
        String freshBuffer = PayloadFingerprint.sha256(new byte[MAX_INPUT_BYTES]);

        // then
        assertThat(afterMutation).isNotEqualTo(original);
        assertThat(freshBuffer).isEqualTo(original);
    }

    @Test
    void acceptsInput_whenSizeIsAtTheLimit() {
        // given
        byte[] atLimit = new byte[MAX_INPUT_BYTES];

        // when
        String digest = PayloadFingerprint.sha256(atLimit);

        // then
        assertThat(digest).hasSize(64);
    }

    @Test
    void rejectsInput_whenSizeExceedsTheLimit() {
        // given
        byte[] oversize = new byte[MAX_INPUT_BYTES + 1];

        // when
        ThrowingCallable fingerprintOversize = () -> PayloadFingerprint.sha256(oversize);

        // then
        assertThatThrownBy(fingerprintOversize)
                .isInstanceOfSatisfying(ProtocolException.class,
                        e -> assertThat(e.reason()).isEqualTo(ProtocolException.Reason.INPUT_TOO_LARGE));
    }

    @Test
    void rejectsInput_whenPayloadIsNull() {
        // given — no payload
        byte[] absent = null;

        // when
        ThrowingCallable fingerprintNull = () -> PayloadFingerprint.sha256(absent);

        // then
        assertThatThrownBy(fingerprintNull)
                .isInstanceOfSatisfying(ProtocolException.class,
                        e -> assertThat(e.reason()).isEqualTo(ProtocolException.Reason.INVALID_DISPATCH));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Arguments> knownSha256Vectors() {
        return Stream
                .of(Arguments
                        .of(named("empty input", new byte[0]),
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                        Arguments
                                .of(named("abc", bytes("abc")),
                                        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                        Arguments
                                .of(named("one million a", bytes("a".repeat(1_000_000))),
                                        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
