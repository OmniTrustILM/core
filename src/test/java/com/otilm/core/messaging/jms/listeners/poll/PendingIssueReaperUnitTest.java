package com.otilm.core.messaging.jms.listeners.poll;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for {@link PendingIssueReaper#reapStaleOrphans()}'s per-certificate behaviors that a
 * real-DB test cannot exercise deterministically: the under-lock state re-assertion (skip a candidate
 * that is no longer PENDING_ISSUE) and the per-certificate try/catch (one certificate's transition
 * failure must not abort the rest of the batch). Collaborators are mocked; the selection predicates and
 * the FAILED+audit outcome are covered against real Postgres in {@link PendingIssueReaperTest}.
 */
@ExtendWith(MockitoExtension.class)
class PendingIssueReaperUnitTest {

    @Mock private CertificateRepository certificateRepository;
    @Mock private TransactionHandler transactionHandler;
    @Mock private ClusterOperationSynchronizer clusterSynchronizer;
    @Mock private CertificateStateMachine stateMachine;

    private PendingIssueReaper reaper;

    @SuppressWarnings({"unchecked", "rawtypes"})
    @BeforeEach
    void setUp() {
        reaper = new PendingIssueReaper(certificateRepository, transactionHandler, clusterSynchronizer,
                stateMachine, Duration.ofMinutes(30), 200);
        // Execute the transactional lambdas inline so the real selection/reap logic runs under the test.
        lenient().when(transactionHandler.runInNewTransaction(any(Supplier.class)))
                .thenAnswer(inv -> ((Supplier<?>) inv.getArgument(0)).get());
        lenient().when(clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.PROVIDER_STATUS_POLL_SWEEP))
                .thenReturn(true);
    }

    @Test
    void skipsCandidateNoLongerInPendingIssueUnderLock() {
        UUID uuid = UUID.randomUUID();
        when(certificateRepository.findStalePendingIssueWithoutPollRow(any(), any(), any()))
                .thenReturn(List.of(uuid));
        // Between selection and locking the certificate completed elsewhere: it is now ISSUED.
        when(certificateRepository.findAndLockWithAssociationsByUuid(uuid))
                .thenReturn(Optional.of(cert(uuid, CertificateState.ISSUED)));

        reaper.reapStaleOrphans();

        verify(stateMachine, never()).transition(any(), any(), any(), anyString());
    }

    @Test
    void oneCertificateFailureDoesNotAbortTheBatch() {
        UUID failing = UUID.randomUUID();
        UUID healthy = UUID.randomUUID();
        Certificate failingCert = cert(failing, CertificateState.PENDING_ISSUE);
        Certificate healthyCert = cert(healthy, CertificateState.PENDING_ISSUE);
        when(certificateRepository.findStalePendingIssueWithoutPollRow(any(), any(), any()))
                .thenReturn(List.of(failing, healthy));
        when(certificateRepository.findAndLockWithAssociationsByUuid(failing)).thenReturn(Optional.of(failingCert));
        when(certificateRepository.findAndLockWithAssociationsByUuid(healthy)).thenReturn(Optional.of(healthyCert));
        doThrowOnTransition(failingCert);

        assertThatCode(() -> reaper.reapStaleOrphans()).doesNotThrowAnyException();

        // The healthy certificate is still reaped despite the earlier failure.
        verify(stateMachine).transition(eq(healthyCert), eq(CertificateState.FAILED),
                eq(CertificateEvent.ISSUE), anyString());
    }

    private void doThrowOnTransition(Certificate cert) {
        org.mockito.Mockito.doThrow(new RuntimeException("lock timeout"))
                .when(stateMachine).transition(eq(cert), eq(CertificateState.FAILED),
                        eq(CertificateEvent.ISSUE), anyString());
    }

    private static Certificate cert(UUID uuid, CertificateState state) {
        Certificate c = new Certificate();
        c.setUuid(uuid);
        c.setState(state);
        return c;
    }
}
