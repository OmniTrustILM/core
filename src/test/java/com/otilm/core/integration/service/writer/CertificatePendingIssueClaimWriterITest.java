package com.otilm.core.integration.service.writer;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.CertificatePendingIssueClaimWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The claim-clear writer runs a guarded update: it clears the stamp only while the certificate is still in
 * PENDING_ISSUE. The stamp is read and written over JDBC so the assertions see the committed column, not an entity.
 */
class CertificatePendingIssueClaimWriterITest extends BaseSpringBootTest {

    @Autowired
    private CertificatePendingIssueClaimWriter claimWriter;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void clearsTheStampOfAPendingIssueCertificate() {
        Certificate cert = certificateRepository.save(aCertificate().withState(CertificateState.PENDING_ISSUE).build());
        stamp(cert.getUuid());

        int rows = claimWriter.clear(cert.getUuid());

        assertThat(rows).isEqualTo(1);
        assertThat(readStamp(cert.getUuid())).isNull();
    }

    @Test
    void leavesACertificateOutsidePendingIssueUntouched() {
        Certificate cert = certificateRepository.save(aCertificate().withState(CertificateState.ISSUED).build());
        stamp(cert.getUuid());

        int rows = claimWriter.clear(cert.getUuid());

        assertThat(rows).isZero();
        assertThat(readStamp(cert.getUuid())).isNotNull();
    }

    @Test
    void clearingAnUnknownCertificateIsANoOp() {
        assertThat(claimWriter.clear(UUID.randomUUID())).isZero();
    }

    private void stamp(UUID uuid) {
        jdbcTemplate
                .update("UPDATE certificate SET pending_issue_claimed_at = ? WHERE uuid = ?",
                        OffsetDateTime.now(ZoneOffset.UTC), uuid);
    }

    private OffsetDateTime readStamp(UUID uuid) {
        return jdbcTemplate
                .queryForObject("SELECT pending_issue_claimed_at FROM certificate WHERE uuid = ?", OffsetDateTime.class,
                        uuid);
    }
}
