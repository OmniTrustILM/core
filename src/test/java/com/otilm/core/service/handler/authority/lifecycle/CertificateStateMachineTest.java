package com.otilm.core.service.handler.authority.lifecycle;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class CertificateStateMachineTest {

    private CertificateRepository certificateRepository;
    private CertificateEventHistoryInternalService eventHistoryService;
    private CertificateStateMachine sm;

    @BeforeEach
    void setUp() {
        certificateRepository = mock(CertificateRepository.class);
        eventHistoryService = mock(CertificateEventHistoryInternalService.class);
        sm = new CertificateStateMachine(certificateRepository, eventHistoryService);
    }

    @Test
    void validTransitionSavesAndWritesAudit() {
        Certificate cert = certWithState(CertificateState.REQUESTED);
        sm.transition(cert, CertificateState.PENDING_ISSUE);

        assertEquals(CertificateState.PENDING_ISSUE, cert.getState());
        verify(certificateRepository).save(cert);
        verify(eventHistoryService).addEventHistory(eq(cert.getUuid()), eq(CertificateEvent.ISSUE),
            eq(CertificateEventStatus.SUCCESS), anyString(), eq(""));
    }

    @Test
    void invalidTransitionThrowsInvalidTransitionException() {
        Certificate cert = certWithState(CertificateState.REVOKED);
        InvalidTransitionException ex = assertThrows(InvalidTransitionException.class,
            () -> sm.transition(cert, CertificateState.ISSUED));

        assertEquals(CertificateState.REVOKED, ex.getFromState());
        assertEquals(CertificateState.ISSUED, ex.getToStateAttempted());
        assertEquals(CertificateState.REVOKED, cert.getState());   // state unchanged after the throw
        verify(certificateRepository, never()).save(any());
        verify(eventHistoryService, never()).addEventHistory(any(), any(), any(), anyString(), anyString());
    }

    @Test
    void failureTransitionIsAuditedAsFailed() {
        Certificate cert = certWithState(CertificateState.PENDING_ISSUE);
        sm.transition(cert, CertificateState.FAILED, null, "Connector error");

        verify(eventHistoryService).addEventHistory(eq(cert.getUuid()), any(),
            eq(CertificateEventStatus.FAILED), anyString(), eq(""));
    }

    @Test
    void revokeFailedRestoreIsAuditedAsFailed() {
        // PENDING_REVOKE -> ISSUED restores the cert but records a FAILED revoke (not SUCCESS).
        Certificate cert = certWithState(CertificateState.PENDING_REVOKE);
        sm.transition(cert, CertificateState.ISSUED, null, "Revoke cancelled by operator");

        assertEquals(CertificateState.ISSUED, cert.getState());
        verify(eventHistoryService).addEventHistory(eq(cert.getUuid()), any(),
            eq(CertificateEventStatus.FAILED), anyString(), eq(""));
    }

    @Test
    void callerProvidedReasonMessagePropagatesToAuditHistory() {
        Certificate cert = certWithState(CertificateState.PENDING_ISSUE);
        sm.transition(cert, CertificateState.FAILED, null, "Cancelled by operator");

        ArgumentCaptor<String> msg = ArgumentCaptor.forClass(String.class);
        verify(eventHistoryService).addEventHistory(any(), any(), any(), msg.capture(), anyString());
        assertEquals("Cancelled by operator", msg.getValue());
    }

    @Test
    void callerProvidedAuditEventOverridesDefault() {
        Certificate cert = certWithState(CertificateState.PENDING_ISSUE);
        sm.transition(cert, CertificateState.ISSUED, CertificateEvent.REKEY, null);

        verify(eventHistoryService).addEventHistory(any(), eq(CertificateEvent.REKEY),
            any(), anyString(), anyString());
    }

    @Test
    void approvedRevokeCompletingSynchronouslyIsAuditedRevokeSuccess() {
        // PENDING_APPROVAL -> REVOKED: an approved revoke the connector completes synchronously (200).
        Certificate cert = certWithState(CertificateState.PENDING_APPROVAL);
        sm.transition(cert, CertificateState.REVOKED, CertificateEvent.REVOKE, "Certificate revoked");

        assertEquals(CertificateState.REVOKED, cert.getState());
        verify(certificateRepository).save(cert);
        verify(eventHistoryService).addEventHistory(eq(cert.getUuid()), eq(CertificateEvent.REVOKE),
            eq(CertificateEventStatus.SUCCESS), anyString(), eq(""));
    }

    @Test
    void registeredCertificateIssueFailureIsAuditedIssueFailed() {
        // REGISTERED -> FAILED: issuing a registered placeholder failed at the connector.
        Certificate cert = certWithState(CertificateState.REGISTERED);
        sm.transition(cert, CertificateState.FAILED, null, "Connector rejected the request");

        assertEquals(CertificateState.FAILED, cert.getState());
        verify(eventHistoryService).addEventHistory(eq(cert.getUuid()), eq(CertificateEvent.ISSUE),
            eq(CertificateEventStatus.FAILED), anyString(), eq(""));
    }

    @Test
    void registeredCertificateEntersPendingApprovalForIssueApproval() {
        // REGISTERED -> PENDING_APPROVAL: issuing a registered placeholder under an issue-approval profile.
        // approvalCreatedAction uses transitionAuditedExternally (the APPROVAL_REQUEST history is owned by
        // the approval event handler), so the state mutates without a (duplicate) audit row.
        Certificate cert = certWithState(CertificateState.REGISTERED);
        sm.transitionAuditedExternally(cert, CertificateState.PENDING_APPROVAL);

        assertEquals(CertificateState.PENDING_APPROVAL, cert.getState());
        verify(certificateRepository).save(cert);
        verify(eventHistoryService, never()).addEventHistory(any(), any(), any(), anyString(), anyString());
    }

    @Test
    void callerProvidedAuditDetailIsStored() {
        // The 5-arg overload carries a detail payload (e.g. serialized additionalInformation)
        // into the audit-history entry instead of the default empty detail.
        Certificate cert = certWithState(CertificateState.PENDING_ISSUE);
        sm.transition(cert, CertificateState.FAILED, CertificateEvent.ISSUE, "boom",
            "{\"New Certificate UUID\":\"x\"}");

        verify(eventHistoryService).addEventHistory(cert.getUuid(), CertificateEvent.ISSUE,
            CertificateEventStatus.FAILED, "boom", "{\"New Certificate UUID\":\"x\"}");
    }

    @Test
    void externallyAuditedTransitionMutatesStateButWritesNoHistory() {
        // approvalCreatedAction uses this: the APPROVAL_REQUEST history is owned by the approval
        // event handler, so the SM gates + mutates the state without writing a (duplicate) entry.
        Certificate cert = certWithState(CertificateState.REQUESTED);
        sm.transitionAuditedExternally(cert, CertificateState.PENDING_APPROVAL);

        assertEquals(CertificateState.PENDING_APPROVAL, cert.getState());
        verify(certificateRepository).save(cert);
        verify(eventHistoryService, never()).addEventHistory(any(), any(), any(), anyString(), anyString());
    }

    @Test
    void externallyAuditedTransitionStillValidates() {
        // Validation is not skipped — only the audit. An illegal (from, to) still throws.
        Certificate cert = certWithState(CertificateState.REVOKED);
        assertThrows(InvalidTransitionException.class,
            () -> sm.transitionAuditedExternally(cert, CertificateState.PENDING_APPROVAL));

        assertEquals(CertificateState.REVOKED, cert.getState());
        verify(certificateRepository, never()).save(any());
    }

    @Test
    void canTransitionReflectsTheTransitionTable() {
        assertTrue(sm.canTransition(CertificateState.REQUESTED, CertificateState.PENDING_ISSUE));
        assertTrue(sm.canTransition(CertificateState.REGISTERED, CertificateState.PENDING_APPROVAL));
        assertFalse(sm.canTransition(CertificateState.REJECTED, CertificateState.REJECTED));
        assertFalse(sm.canTransition(CertificateState.REVOKED, CertificateState.ISSUED));
    }

    private Certificate certWithState(CertificateState state) {
        Certificate cert = new Certificate();
        cert.setUuid(UUID.randomUUID());
        cert.setState(state);
        return cert;
    }
}
