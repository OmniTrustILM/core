package com.otilm.core.integration.service.writer;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.RenewalRefreshWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class RenewalRefreshWriterITest extends BaseSpringBootTest {

    private static final Instant DUE = Instant.parse("2026-11-23T10:00:00Z").truncatedTo(ChronoUnit.MILLIS);

    @Autowired
    private RenewalRefreshWriter writer;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private TransactionTemplate transactionTemplate;

    @Test
    void setsRefreshStateOfOnlyTheScheduledRow_whenSchedulingOneCertificate() {
        // given
        UUID certificateUuid = rowFor();
        UUID other = rowFor();

        // when
        writer.schedule(certificateUuid, DUE, 3, true);

        // then
        CertificateRenewalInfo row = renewalInfoRepository.findByCertificateUuid(certificateUuid).orElseThrow();
        assertThat(row.getNextRefreshAt()).isEqualTo(DUE);
        assertThat(row.getRefreshAttempt()).isEqualTo(3);
        assertThat(row.isRefreshUnsupported()).isTrue();
        CertificateRenewalInfo untouched = renewalInfoRepository.findByCertificateUuid(other).orElseThrow();
        assertThat(untouched.getNextRefreshAt()).isNull();
        assertThat(untouched.getRefreshAttempt()).isZero();
        assertThat(untouched.isRefreshUnsupported()).isFalse();
    }

    @Test
    void movesOnlyTheDueTimeOfTheGivenRows_whenPostponingSelectedCertificates() {
        // given
        UUID first = rowFor();
        UUID second = rowFor();
        UUID other = rowFor();
        writer.schedule(first, DUE, 2, false);
        Instant postponedTo = DUE.plusSeconds(600);

        // when
        writer.postpone(List.of(first, second), postponedTo);

        // then
        CertificateRenewalInfo moved = renewalInfoRepository.findByCertificateUuid(first).orElseThrow();
        assertThat(moved.getNextRefreshAt()).isEqualTo(postponedTo);
        assertThat(moved.getRefreshAttempt()).isEqualTo(2);
        assertThat(renewalInfoRepository.findByCertificateUuid(second).orElseThrow().getNextRefreshAt())
                .isEqualTo(postponedTo);
        assertThat(renewalInfoRepository.findByCertificateUuid(other).orElseThrow().getNextRefreshAt()).isNull();
    }

    @Test
    void countsEachFailureAndDerivesTheTimeFromTheNewCount_whenBackingOffRepeatedly() {
        // given
        UUID certificateUuid = rowFor();
        writer.schedule(certificateUuid, DUE, 0, true);

        // when
        writer.backOff(certificateUuid, DUE::plusSeconds);
        writer.backOff(certificateUuid, DUE::plusSeconds);

        // then
        CertificateRenewalInfo row = renewalInfoRepository.findByCertificateUuid(certificateUuid).orElseThrow();
        assertThat(row.getRefreshAttempt()).isEqualTo(2);
        assertThat(row.getNextRefreshAt()).isEqualTo(DUE.plusSeconds(2));
        assertThat(row.isRefreshUnsupported()).isFalse();
    }

    @Test
    void createsNoRow_whenBackingOffACertificateWithoutOne() {
        // given
        UUID existing = rowFor();
        UUID withoutRow = UUID.randomUUID();

        // when
        writer.backOff(withoutRow, attempt -> DUE);

        // then
        assertThat(renewalInfoRepository.findByCertificateUuid(withoutRow)).isEmpty();
        assertThat(renewalInfoRepository.findAll())
                .singleElement()
                .satisfies(row -> assertThat(row.getCertificateUuid()).isEqualTo(existing));
    }

    @Test
    void leavesRowsUntouched_whenPostponingNoCertificates() {
        // given
        UUID existing = rowFor();

        // when
        writer.postpone(List.of(), DUE);

        // then
        assertThat(renewalInfoRepository.findByCertificateUuid(existing).orElseThrow().getNextRefreshAt()).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private UUID rowFor() {
        Certificate certificate = certificateRepository.save(aCertificate().build());
        transactionTemplate
                .executeWithoutResult(
                        status -> renewalInfoRepository.insertIfAbsent(UUID.randomUUID(), certificate.getUuid(), DUE));
        return certificate.getUuid();
    }
}
