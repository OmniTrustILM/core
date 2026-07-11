package com.otilm.core.integration.service.writer.statuspoll;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * SQL-level coverage for {@link CertificateStatusPollWriter#resetAttempt}: the update lowers an
 * attempt counter above the floor and leaves a still-ramping row untouched (the guard in the query,
 * not application logic, enforces this).
 */
class CertificateStatusPollWriterITest extends BaseSpringBootTest {

    @Autowired
    private CertificateStatusPollWriter writer;
    @Autowired
    private CertificateStatusPollRepository pollRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void resetAttempt_lowersARowAboveTheFloor() {
        UUID certUuid = pendingCertWithPollRowAtAttempt(50);

        writer.resetAttempt(certUuid, 6);

        assertThat(pollAttempt(certUuid)).isEqualTo(6);
    }

    @Test
    void resetAttempt_leavesAStillRampingRowUntouched() {
        UUID certUuid = pendingCertWithPollRowAtAttempt(3);

        writer.resetAttempt(certUuid, 6);

        assertThat(pollAttempt(certUuid)).isEqualTo(3);
    }

    private UUID pendingCertWithPollRowAtAttempt(int attempt) {
        Certificate cert = certificateRepository.save(
                aCertificate().withState(CertificateState.PENDING_ISSUE).build());
        writer.schedule(cert.getUuid(), CertificateOperation.ISSUE, OffsetDateTime.now(ZoneOffset.UTC));
        writer.reschedule(cert.getUuid(), attempt, OffsetDateTime.now(ZoneOffset.UTC));
        return cert.getUuid();
    }

    private int pollAttempt(UUID certUuid) {
        return pollRepository.findAll().stream()
                .filter(p -> p.getCertificateUuid().equals(certUuid))
                .findFirst().orElseThrow()
                .getAttempt();
    }
}
