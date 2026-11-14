package com.otilm.core.util.ai;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.handler.StoredCertificateHealthProjector;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateReadProofAdapterTest {
    private static final String VALID_INPUT = "{\"tool\":\"certificate.search\",\"arguments\":{\"page\":1,\"pageSize\":1}}";

    @Test
    void asciiByteCeilingRejectsOtherwiseValidPaddedEnvelope() throws Exception {
        String atLimit = VALID_INPUT + " ".repeat(1048576 - VALID_INPUT.length());
        assertThat(CertificateReadProofAdapter.parseInput(atLimit).path("tool").textValue())
                .isEqualTo("certificate.search");
        String overLimit = atLimit + " ";
        assertThatThrownBy(() -> CertificateReadProofAdapter.parseInput(overLimit))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void multibyteCeilingCannotBeMaskedByTheCharacterFastPath() throws Exception {
        String entry = "\"" + "€".repeat(60000) + "\"";
        String underLimit = "[" + String.join(",", java.util.Collections.nCopies(5, entry)) + "]";
        String overLimit = "[" + String.join(",", java.util.Collections.nCopies(6, entry)) + "]";
        assertThat(overLimit.length()).isLessThan(1048576);
        int overLimitUtf8ByteCount = overLimit.getBytes(StandardCharsets.UTF_8).length;
        assertThat(overLimitUtf8ByteCount).isGreaterThan(1048576);
        assertThat(CertificateReadProofAdapter.parseInput(underLimit).size()).isEqualTo(5);
        assertThatThrownBy(() -> CertificateReadProofAdapter.parseInput(overLimit))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void stringConstraintFailsAtTheParserBeforeAnySchemaValidation() throws Exception {
        String atLimit = "{\"value\":\"" + "x".repeat(65536) + "\"}";
        String overLimit = "{\"value\":\"" + "x".repeat(65537) + "\"}";
        int parsedStringLength = CertificateReadProofAdapter.parseInput(atLimit).path("value").textValue().length();
        assertThat(parsedStringLength).isEqualTo(65536);
        assertThatThrownBy(() -> CertificateReadProofAdapter.parseInput(overLimit))
                .isInstanceOf(StreamConstraintsException.class);
    }

    @Test
    void numberConstraintFailsAtTheParserBeforeIntegerCoercion() throws Exception {
        String atLimit = "1".repeat(64);
        String overLimit = "1".repeat(65);
        assertThat(CertificateReadProofAdapter.parseInput(atLimit).isIntegralNumber()).isTrue();
        assertThatThrownBy(() -> CertificateReadProofAdapter.parseInput(overLimit))
                .isInstanceOf(StreamConstraintsException.class);
    }

    @Test
    void depthConstraintFailsAtTheParserBeforeRootShapeValidation() throws Exception {
        String atLimit = "[".repeat(32) + "0" + "]".repeat(32);
        String overLimit = "[".repeat(33) + "0" + "]".repeat(33);
        assertThat(CertificateReadProofAdapter.parseInput(atLimit).isArray()).isTrue();
        assertThatThrownBy(() -> CertificateReadProofAdapter.parseInput(overLimit))
                .isInstanceOf(StreamConstraintsException.class);
    }

    @Test
    void propertyNameConstraintFailsAtTheParserBeforeUnknownFieldValidation() throws Exception {
        String atLimit = "{\"" + "n".repeat(128) + "\":0}";
        String overLimit = "{\"" + "n".repeat(129) + "\":0}";
        assertThat(CertificateReadProofAdapter.parseInput(atLimit).size()).isEqualTo(1);
        assertThatThrownBy(() -> CertificateReadProofAdapter.parseInput(overLimit))
                .isInstanceOf(StreamConstraintsException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "2026-10-27T00:00:00.000000001Z",
            "2026-10-27T00:00:00.123456789Z",
            "0000-01-01T00:00:00Z",
            "-0001-01-01T00:00:00Z",
            "+10000-01-01T00:00:00Z"})
    void rejectsExpiryValuesThatWouldLosePrecisionOrEra(String text) {
        Instant expiry = Instant.parse(text);
        assertThatThrownBy(() -> new CertificateReadProofAdapter.SearchArguments(1, 1, null, null, expiry))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999Z", "2026-10-27T00:00:00.123Z"})
    void supportsExactMillisecondsAcrossThePositiveUtcYearRange(String text) {
        Instant expiry = Instant.parse(text);
        var args = new CertificateReadProofAdapter.SearchArguments(1, 1, null, null, expiry);
        assertThat(args.expiresBefore()).isEqualTo(expiry);
    }

    @Test
    void parserInitializationKeepsIndependentStorageFactoriesUnchanged() throws Exception {
        var before = ObjectMapperFactory.storage();
        var independent = ObjectMapperFactory.storage();
        assertThat(before).isNotSameAs(independent);
        assertThat(before.getFactory()).isNotSameAs(independent.getFactory());
        var original = before.getFactory().streamReadConstraints();
        CertificateReadProofAdapter.parseInput(VALID_INPUT);
        StoredCertificateHealthProjector
                .project(new StoredCertificateHealthProjector.Snapshot(UUID.randomUUID(), UUID.randomUUID(), null, null,
                        null, null, null, null, CertificateState.ISSUED, CertificateValidationStatus.VALID, null,
                        "{}"));
        assertThat(before.getFactory().streamReadConstraints()).isSameAs(original);
        var after = ObjectMapperFactory.storage().getFactory().streamReadConstraints();
        assertThat(after.getMaxStringLength())
                .isEqualTo(original.getMaxStringLength())
                .isEqualTo(StreamReadConstraints.DEFAULT_MAX_STRING_LEN);
        assertThat(after.getMaxNumberLength())
                .isEqualTo(original.getMaxNumberLength())
                .isEqualTo(StreamReadConstraints.DEFAULT_MAX_NUM_LEN);
        assertThat(after.getMaxNestingDepth())
                .isEqualTo(original.getMaxNestingDepth())
                .isEqualTo(StreamReadConstraints.DEFAULT_MAX_DEPTH);
        assertThat(after.getMaxNameLength())
                .isEqualTo(original.getMaxNameLength())
                .isEqualTo(StreamReadConstraints.DEFAULT_MAX_NAME_LEN);
    }
}
