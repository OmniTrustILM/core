package com.otilm.core.integration.service.writer;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.CertificatePendingIssueClaimWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration coverage for {@link CertificatePendingIssueClaimWriter}. The stamp is read and written over JDBC so the
 * assertions see the committed column, not an entity.
 */
class CertificatePendingIssueClaimWriterITest extends BaseSpringBootTest {

    @Autowired
    private CertificatePendingIssueClaimWriter claimWriter;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void clearsStamp_whenCertificateIsPendingIssue() {
        // given
        Certificate pending = certificateRepository
                .save(aCertificate().withState(CertificateState.PENDING_ISSUE).build());
        stamp(pending.getUuid());

        // when
        int rows = claimWriter.clear(pending.getUuid());

        // then
        assertThat(rows).isEqualTo(1);
        assertThat(readStamp(pending.getUuid())).isNull();
    }

    @Test
    void leavesStamp_whenCertificateIsNotPendingIssue() {
        // given
        Certificate issued = certificateRepository.save(aCertificate().withState(CertificateState.ISSUED).build());
        stamp(issued.getUuid());

        // when
        int rows = claimWriter.clear(issued.getUuid());

        // then
        assertThat(rows).isZero();
        assertThat(readStamp(issued.getUuid())).isNotNull();
    }

    @Test
    void updatesNothing_whenCertificateDoesNotExist() {
        // given
        UUID unknownCertificate = UUID.randomUUID();

        // when
        int rows = claimWriter.clear(unknownCertificate);

        // then
        assertThat(rows).isZero();
    }

    @Test
    void advancesUpdatedTimestamp_whenClearingTheStamp() {
        // given
        Certificate pending = certificateRepository
                .save(aCertificate().withState(CertificateState.PENDING_ISSUE).build());
        stamp(pending.getUuid());
        OffsetDateTime updatedLongAgo = OffsetDateTime.now(ZoneOffset.UTC).minus(Duration.ofDays(2));
        jdbcTemplate.update("UPDATE certificate SET i_upd = ? WHERE uuid = ?", updatedLongAgo, pending.getUuid());

        // when
        claimWriter.clear(pending.getUuid());

        // then
        assertThat(readUpdated(pending.getUuid())).isAfter(updatedLongAgo);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

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

    private OffsetDateTime readUpdated(UUID uuid) {
        return jdbcTemplate.queryForObject("SELECT i_upd FROM certificate WHERE uuid = ?", OffsetDateTime.class, uuid);
    }
}
