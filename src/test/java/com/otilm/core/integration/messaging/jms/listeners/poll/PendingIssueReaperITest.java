package com.otilm.core.integration.messaging.jms.listeners.poll;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateStatusPoll;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.messaging.jms.listeners.poll.PendingIssueReaper;
import com.otilm.core.service.handler.authority.CertificateOperation;
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
 * Integration coverage for {@link PendingIssueReaper}: only a certificate whose synchronous connector call never
 * returned - still in PENDING_ISSUE with a stale claim stamp and no status-poll row - is failed. Certificates the
 * authority answered (no stamp), fresh claims, claims owned by the poller, and other states are left alone. The stamp
 * and {@code i_upd} are written directly, since {@code @UpdateTimestamp} would otherwise stamp {@code i_upd} to now.
 */
class PendingIssueReaperITest extends BaseSpringBootTest {

    @Autowired
    private PendingIssueReaper reaper;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private CertificateStatusPollRepository pollRepository;
    @Autowired
    private CertificateEventHistoryRepository eventHistoryRepository;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    // Comfortably beyond the default reap-stale-after so these certificates are always candidates.
    private static final Duration STALE = Duration.ofDays(2);

    @Test
    void reapsStaleClaimedPendingIssue_toFailedWithAuditAndClearsTheClaim() {
        Certificate cert = certificateRepository.save(aCertificate().withState(CertificateState.PENDING_ISSUE).build());
        claim(cert.getUuid(), STALE);

        reaper.reapStaleOrphans();

        Certificate reaped = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertThat(reaped.getState()).isEqualTo(CertificateState.FAILED);
        assertThat(reaped.getPendingIssueClaimedAt()).as("leaving PENDING_ISSUE clears the claim").isNull();
        assertThat(eventHistoryRepository.findByCertificateOrderByCreatedDesc(reaped))
                .as("reaping must write an ISSUE/FAILED audit-history row")
                .anyMatch(
                        h -> h.getEvent() == CertificateEvent.ISSUE && h.getStatus() == CertificateEventStatus.FAILED);
    }

    @Test
    void leavesStaleUnclaimedPendingIssueUntouched() {
        // No stamp: the authority answered (out-of-band 202, or parked after a local failure), or the certificate was
        // already waiting before this column existed. An old i_upd must not make it a candidate.
        Certificate cert = certificateRepository.save(aCertificate().withState(CertificateState.PENDING_ISSUE).build());
        backdateUpdated(cert.getUuid(), STALE);

        reaper.reapStaleOrphans();

        assertThat(certificateRepository.findByUuid(cert.getUuid()).orElseThrow().getState())
                .isEqualTo(CertificateState.PENDING_ISSUE);
    }

    @Test
    void leavesFreshClaimedPendingIssueUntouched() {
        // A synchronous call still within reap-stale-after
        Certificate cert = certificateRepository.save(aCertificate().withState(CertificateState.PENDING_ISSUE).build());
        claim(cert.getUuid(), Duration.ZERO);

        reaper.reapStaleOrphans();

        assertThat(certificateRepository.findByUuid(cert.getUuid()).orElseThrow().getState())
                .isEqualTo(CertificateState.PENDING_ISSUE);
    }

    @Test
    void leavesStaleClaimedPendingIssueWithPollRowUntouched() {
        // A pollable 202 whose best-effort claim clear failed: the poller owns it.
        Certificate cert = certificateRepository.save(aCertificate().withState(CertificateState.PENDING_ISSUE).build());
        claim(cert.getUuid(), STALE);
        savePollRow(cert.getUuid());

        reaper.reapStaleOrphans();

        assertThat(certificateRepository.findByUuid(cert.getUuid()).orElseThrow().getState())
                .isEqualTo(CertificateState.PENDING_ISSUE);
    }

    @Test
    void leavesStaleClaimedNonPendingIssueUntouched() {
        Certificate cert = certificateRepository.save(aCertificate().withState(CertificateState.ISSUED).build());
        claim(cert.getUuid(), STALE);

        reaper.reapStaleOrphans();

        assertThat(certificateRepository.findByUuid(cert.getUuid()).orElseThrow().getState())
                .isEqualTo(CertificateState.ISSUED);
    }

    @Test
    void reapingRenewRekeyOrphanDeletesDanglingPredecessorRelation() {
        // A synchronous renew/rekey crash leaves an ISSUED predecessor linked to a stale claimed PENDING_ISSUE
        // successor by a PENDING relation (created in an earlier committed step). Reaping the successor
        // must drop that relation so the predecessor is not left linked to a now-FAILED certificate.
        Certificate predecessor = certificateRepository.save(aCertificate().withState(CertificateState.ISSUED).build());
        Certificate successor = certificateRepository
                .save(aCertificate().withState(CertificateState.PENDING_ISSUE).build());
        claim(successor.getUuid(), STALE);
        savePendingRelation(predecessor, successor);

        reaper.reapStaleOrphans();

        assertThat(certificateRepository.findByUuid(successor.getUuid()).orElseThrow().getState())
                .as("the orphaned successor is failed")
                .isEqualTo(CertificateState.FAILED);
        assertThat(certificateRelationRepository
                .findFirstByIdSuccessorCertificateUuidAndRelationTypeOrderByCreatedAtAsc(successor.getUuid(),
                        CertificateRelationType.PENDING))
                .as("the dangling PENDING predecessor relation is deleted")
                .isEmpty();
        assertThat(certificateRepository.findByUuid(predecessor.getUuid()).orElseThrow().getState())
                .as("the predecessor is left untouched")
                .isEqualTo(CertificateState.ISSUED);
    }

    private void savePendingRelation(Certificate predecessor, Certificate successor) {
        CertificateRelation relation = new CertificateRelation();
        relation.setPredecessorCertificate(predecessor);
        relation.setSuccessorCertificate(successor);
        relation.setRelationType(CertificateRelationType.PENDING);
        certificateRelationRepository.save(relation);
    }

    private void savePollRow(UUID certificateUuid) {
        CertificateStatusPoll poll = new CertificateStatusPoll();
        poll.setCertificateUuid(certificateUuid);
        poll.setOperation(CertificateOperation.ISSUE);
        poll.setAttempt(0);
        poll.setNextPollAt(OffsetDateTime.now(ZoneOffset.UTC));
        pollRepository.save(poll);
    }

    private void claim(UUID uuid, Duration age) {
        jdbcTemplate
                .update("UPDATE certificate SET pending_issue_claimed_at = ? WHERE uuid = ?",
                        OffsetDateTime.now(ZoneOffset.UTC).minus(age), uuid);
    }

    private void backdateUpdated(UUID uuid, Duration age) {
        jdbcTemplate
                .update("UPDATE certificate SET i_upd = ? WHERE uuid = ?",
                        OffsetDateTime.now(ZoneOffset.UTC).minus(age), uuid);
    }
}
