package com.otilm.core.service.handler;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationCheck;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StoredCertificateHealthProjectorTest {
    private static final UUID CERTIFICATE = UUID.randomUUID();
    private static final UUID PROFILE = UUID.randomUUID();
    private static final OffsetDateTime TIME = OffsetDateTime.parse("2026-10-01T12:00:00+02:00");

    @Test
    void keepsStoredScalarsAndOnlyCheckStatuses() {
        var result = StoredCertificateHealthProjector
                .project(snapshot(
                        "{\"signature\":{\"validationCheck\":\"signature\",\"status\":\"valid\",\"message\":\"STORED_MESSAGE_CANARY\"}}"));
        assertThat(result).isNotNull();
        assertThat(result.certificateUuid()).isEqualTo(CERTIFICATE);
        assertThat(result.raProfileUuid()).isEqualTo(PROFILE);
        assertThat(result.validationTimestamp()).isEqualTo(TIME);
        assertThat(result.validationStatus()).isEqualTo(CertificateValidationStatus.EXPIRED);
        assertThat(result.notBefore()).isEqualTo(new Date(1000).toInstant());
        assertThat(result.checks()).containsOnlyKeys(CertificateValidationCheck.SIGNATURE_VERIFICATION);
        assertThat(result.checks())
                .containsEntry(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.VALID);
        assertThat(result.evidence()).isEqualTo(StoredCertificateHealth.Evidence.PRESENT);
        var checks = result.checks();
        assertThatThrownBy(checks::clear).isInstanceOf(UnsupportedOperationException.class);
        assertThat(StoredCertificateHealth.class.getRecordComponents()).hasSize(13);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "{}"})
    void missingEvidencePreservesStoredStatusAndTimestamp(String raw) {
        var result = StoredCertificateHealthProjector.project(snapshot(raw));
        assertThat(result).isNotNull();
        assertThat(result.evidence()).isEqualTo(StoredCertificateHealth.Evidence.MISSING);
        assertThat(result.checks()).isEmpty();
        assertThat(result.validationTimestamp()).isEqualTo(TIME);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "null",
            "[]",
            "broken",
            "{\"unknown\":{}}",
            "{\"signature\":null}",
            "{\"signature\":{\"status\":null}}",
            "{\"signature\":{\"status\":\"unknown\"}}",
            "{\"signature\":{\"status\":\"valid\",\"validationCheck\":\"key_usage\"}}",
            "{\"signature\":{\"status\":\"valid\"},\"signature\":{\"status\":\"failed\"}}",
            "{} {}"})
    void malformedEvidenceHasNoPartialChecks(String raw) {
        var result = StoredCertificateHealthProjector.project(snapshot(raw));
        assertThat(result).isNotNull();
        assertThat(result.evidence()).isEqualTo(StoredCertificateHealth.Evidence.MALFORMED);
        assertThat(result.checks()).isEmpty();
    }

    @Test
    void oversizeIsMalformedEvenIfItsPrefixIsValidJson() {
        var result = StoredCertificateHealthProjector.project(snapshot("{}" + " ".repeat(99999)));
        assertThat(result).isNotNull();
        assertThat(result.evidence()).isEqualTo(StoredCertificateHealth.Evidence.MALFORMED);
    }

    @Test
    void missingTimestampDoesNotRewritePresentStoredEvidence() {
        var result = StoredCertificateHealthProjector
                .project(new StoredCertificateHealthProjector.Snapshot(CERTIFICATE, PROFILE, "synthetic", "serial",
                        "issuer", "fingerprint", null, null, CertificateState.ISSUED,
                        CertificateValidationStatus.EXPIRED, null, "{\"signature\":{\"status\":\"valid\"}}"));
        assertThat(result.evidence()).isEqualTo(StoredCertificateHealth.Evidence.PRESENT);
        assertThat(result.validationTimestamp()).isNull();
        assertThat(result.validationStatus()).isEqualTo(CertificateValidationStatus.EXPIRED);
        assertThat(result.notBefore()).isNull();
        assertThat(result.notAfter()).isNull();
    }

    @ParameterizedTest
    @ValueSource(ints = {100000, 100001})
    void supplementaryUnicodeUsesTheDatabaseCharacterCeiling(int characters) {
        String prefix = "{\"signature\":{\"status\":\"valid\",\"message\":\"";
        String suffix = "\"}}";
        String raw = prefix + "😀".repeat(characters - prefix.length() - suffix.length()) + suffix;
        assertThat(raw.codePointCount(0, raw.length())).isEqualTo(characters);
        assertThat(raw.length()).isGreaterThan(100000);
        var result = StoredCertificateHealthProjector.project(snapshot(raw));
        assertThat(result.evidence())
                .isEqualTo(characters == 100000
                        ? StoredCertificateHealth.Evidence.PRESENT
                        : StoredCertificateHealth.Evidence.MALFORMED);
        if (characters == 100000) {
            assertThat(result.checks())
                    .containsEntry(CertificateValidationCheck.SIGNATURE_VERIFICATION,
                            CertificateValidationStatus.VALID);
        } else {
            assertThat(result.checks()).isEmpty();
        }
    }

    private static StoredCertificateHealthProjector.Snapshot snapshot(String raw) {
        return new StoredCertificateHealthProjector.Snapshot(CERTIFICATE, PROFILE, "synthetic", "serial", "issuer",
                "fingerprint", new Date(1000), new Date(2000), CertificateState.ISSUED,
                CertificateValidationStatus.EXPIRED, TIME, raw);
    }
}
