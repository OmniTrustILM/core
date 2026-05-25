package com.czertainly.core.service.handler.authority.lifecycle;

import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.service.CertificateEventHistoryService;
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
    private CertificateEventHistoryService eventHistoryService;
    private CertificateStateMachine sm;

    @BeforeEach
    void setUp() {
        certificateRepository = mock(CertificateRepository.class);
        eventHistoryService = mock(CertificateEventHistoryService.class);
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
        verify(certificateRepository, never()).save(any());
        verify(eventHistoryService, never()).addEventHistory(any(), any(), any(), anyString(), anyString());
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

    private Certificate certWithState(CertificateState state) {
        Certificate cert = new Certificate();
        cert.setUuid(UUID.randomUUID());
        cert.setState(state);
        return cert;
    }
}
