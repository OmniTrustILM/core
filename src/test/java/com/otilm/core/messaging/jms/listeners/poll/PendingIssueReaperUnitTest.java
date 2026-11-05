package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for {@link PendingIssueReaper#reapStaleOrphans()}'s per-certificate behaviors that a real-DB test
 * cannot exercise deterministically: the under-lock state re-assertion (skip a candidate that is no longer
 * PENDING_ISSUE) and the per-certificate try/catch (one certificate's transition failure must not abort the rest of the
 * batch). Collaborators are mocked; the selection predicates and the FAILED+audit outcome are covered against real
 * Postgres in {@link com.otilm.core.integration.messaging.jms.listeners.poll.PendingIssueReaperITest}.
 */
@ExtendWith(MockitoExtension.class)
class PendingIssueReaperUnitTest {

    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private CertificateRelationRepository certificateRelationRepository;
    @Mock
    private TransactionHandler transactionHandler;
    @Mock
    private ClusterOperationSynchronizer clusterSynchronizer;
    @Mock
    private CertificateStateMachine stateMachine;

    private PendingIssueReaper reaper;

    @SuppressWarnings({"unchecked", "rawtypes"})
    @BeforeEach
    void setUp() {
        reaper = new PendingIssueReaper(certificateRepository, certificateRelationRepository, transactionHandler,
                clusterSynchronizer, stateMachine, Duration.ofMinutes(30), 200);
        // Execute the transactional lambdas inline so the real selection/reap logic runs under the test.
        lenient()
                .when(transactionHandler.runInNewTransaction(any(Supplier.class)))
                .thenAnswer(inv -> ((Supplier<?>) inv.getArgument(0)).get());
        lenient()
                .when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.PROVIDER_STATUS_POLL_SWEEP))
                .thenReturn(true);
    }

    @Test
    void skipsCandidate_whenItLeftPendingIssueBeforeLocking() {
        // given — between selection and locking the certificate completed elsewhere
        UUID uuid = UUID.randomUUID();
        when(certificateRepository.findStaleClaimedPendingIssueWithoutPollRow(any(), any())).thenReturn(List.of(uuid));
        when(certificateRepository.findAndLockWithAssociationsByUuid(uuid))
                .thenReturn(Optional.of(createCertificate(uuid, CertificateState.ISSUED)));

        // when
        reaper.reapStaleOrphans();

        // then
        verify(stateMachine, never()).transition(any(), any(), any(), anyString());
    }

    @Test
    void skipsCandidate_whenItsClaimWasClearedBeforeLocking() {
        // given — between selection and locking the authority's answer was recorded: still PENDING_ISSUE, no claim
        UUID uuid = UUID.randomUUID();
        when(certificateRepository.findStaleClaimedPendingIssueWithoutPollRow(any(), any())).thenReturn(List.of(uuid));
        when(certificateRepository.findAndLockWithAssociationsByUuid(uuid))
                .thenReturn(Optional.of(createCertificate(uuid, CertificateState.PENDING_ISSUE, null)));

        // when
        reaper.reapStaleOrphans();

        // then
        verify(stateMachine, never()).transition(any(), any(), any(), anyString());
    }

    @Test
    void reapsRemainingCandidates_whenOneTransitionFails() {
        // given
        UUID failing = UUID.randomUUID();
        UUID healthy = UUID.randomUUID();
        Certificate failingCert = createCertificate(failing, CertificateState.PENDING_ISSUE);
        Certificate healthyCert = createCertificate(healthy, CertificateState.PENDING_ISSUE);
        when(certificateRepository.findStaleClaimedPendingIssueWithoutPollRow(any(), any()))
                .thenReturn(List.of(failing, healthy));
        when(certificateRepository.findAndLockWithAssociationsByUuid(failing)).thenReturn(Optional.of(failingCert));
        when(certificateRepository.findAndLockWithAssociationsByUuid(healthy)).thenReturn(Optional.of(healthyCert));
        doThrowOnTransition(failingCert);

        // when
        reaper.reapStaleOrphans();

        // then
        verify(stateMachine)
                .transition(eq(healthyCert), eq(CertificateState.FAILED), eq(CertificateEvent.ISSUE), anyString());
    }

    @Test
    void selectsNothing_whenAnotherNodeHoldsTheSweepLock() {
        // given
        when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.PROVIDER_STATUS_POLL_SWEEP))
                .thenReturn(false);

        // when
        reaper.reapStaleOrphans();

        // then
        verify(certificateRepository, never()).findStaleClaimedPendingIssueWithoutPollRow(any(), any());
        verify(stateMachine, never()).transition(any(), any(), any(), anyString());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void doThrowOnTransition(Certificate cert) {
        doThrow(new RuntimeException("lock timeout"))
                .when(stateMachine)
                .transition(eq(cert), eq(CertificateState.FAILED), eq(CertificateEvent.ISSUE), anyString());
    }

    private static Certificate createCertificate(UUID uuid, CertificateState state) {
        return createCertificate(uuid, state, OffsetDateTime.now(ZoneOffset.UTC).minusDays(2));
    }

    private static Certificate createCertificate(UUID uuid, CertificateState state, OffsetDateTime claimedAt) {
        Certificate certificate = aCertificate().withUuid(uuid).withState(state).build();
        certificate.setPendingIssueClaimedAt(claimedAt);
        return certificate;
    }
}
