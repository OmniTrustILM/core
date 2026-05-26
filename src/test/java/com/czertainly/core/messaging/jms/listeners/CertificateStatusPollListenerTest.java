package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.MessageHandlingException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.connector.v3.certificate.CertificateOperationStatus;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.messaging.jms.configuration.StatusPollProperties;
import com.czertainly.core.messaging.jms.producers.CertificateStatusPollProducer;
import com.czertainly.core.messaging.model.CertificateStatusPollMessage;
import com.czertainly.core.service.handler.authority.AsyncOperationCapability;
import com.czertainly.core.service.handler.authority.AuthorityProviderAdapter;
import com.czertainly.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.czertainly.core.service.handler.authority.CertificateOperation;
import com.czertainly.core.service.handler.authority.StatusPollResult;
import com.czertainly.core.service.handler.authority.lifecycle.CertificateStateMachine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateStatusPollListenerTest {

    @Mock private CertificateRepository certificateRepository;
    @Mock private AuthorityProviderAdapterFactory adapterFactory;
    @Mock private CertificateStateMachine stateMachine;
    @Mock private CertificateStatusPollProducer pollProducer;
    @Mock private StatusPollProperties statusPollProperties;
    @Mock private AttributeEngine attributeEngine;
    @Mock private com.czertainly.core.events.transaction.TransactionHandler transactionHandler;
    @Mock private com.czertainly.core.service.CertificateService certificateService;
    @Mock private com.czertainly.core.service.CryptographicKeyService keyService;

    /**
     * Combined mock implementing both AuthorityProviderAdapter and AsyncOperationCapability.
     * The listener casts the adapter to AsyncOperationCapability after retrieving it from the factory.
     */
    private AuthorityProviderAdapter adapter;
    private AsyncOperationCapability asyncAdapter;

    private CertificateStatusPollListener listener;

    private static final UUID CERT_UUID = UUID.randomUUID();
    private static final UUID CONNECTOR_UUID = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        adapter = Mockito.mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(AsyncOperationCapability.class));
        asyncAdapter = (AsyncOperationCapability) adapter;

        listener = new CertificateStatusPollListener();
        listener.setCertificateRepository(certificateRepository);
        listener.setAdapterFactory(adapterFactory);
        listener.setStateMachine(stateMachine);
        listener.setPollProducer(pollProducer);
        listener.setStatusPollProperties(statusPollProperties);
        listener.setAttributeEngine(attributeEngine);
        listener.setTransactionHandler(transactionHandler);
        listener.setCertificateService(certificateService);
        listener.setKeyService(keyService);

        StatusPollProperties.PollSchedule schedule = mock(StatusPollProperties.PollSchedule.class);
        lenient().when(schedule.maxAttempts()).thenReturn(3);
        lenient().when(statusPollProperties.scheduleFor(any())).thenReturn(schedule);

        // Execute the runnable synchronously so the locked-transaction body runs in-test.
        lenient().doAnswer(inv -> { ((Runnable) inv.getArgument(0)).run(); return null; })
                .when(transactionHandler).runInNewTransaction(any(Runnable.class));
        lenient().when(adapterFactory.forAuthority(any())).thenReturn(adapter);
    }

    // -----------------------------------------------------------------------
    // certNotFoundDropsSilently
    // -----------------------------------------------------------------------

    @Test
    void certNotFoundDropsSilently() throws MessageHandlingException {
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.empty());

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verifyNoInteractions(adapterFactory, stateMachine, pollProducer, transactionHandler);
    }

    // -----------------------------------------------------------------------
    // dropOnNonPendingState
    // -----------------------------------------------------------------------

    @Test
    void dropOnNonPendingState() throws MessageHandlingException {
        Certificate cert = certInState(CertificateState.ISSUED);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verifyNoInteractions(adapterFactory, stateMachine, pollProducer, transactionHandler);
    }

    // -----------------------------------------------------------------------
    // inProgressReEnqueues
    // -----------------------------------------------------------------------

    @Test
    void inProgressReEnqueues() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.IN_PROGRESS, null, null, null));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        ArgumentCaptor<CertificateStatusPollMessage> captor =
                ArgumentCaptor.forClass(CertificateStatusPollMessage.class);
        verify(pollProducer).produceMessage(captor.capture());
        assertThat(captor.getValue().attempt()).isEqualTo(1);
        verifyNoInteractions(stateMachine, transactionHandler);
    }

    // -----------------------------------------------------------------------
    // inProgressMaxAttemptsTimesOut
    // -----------------------------------------------------------------------

    @Test
    void inProgressMaxAttemptsTimesOut() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.IN_PROGRESS, null, null, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        // attempt == maxAttempts → timeout path
        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 3));

        verify(stateMachine).transition(eq(cert), eq(CertificateState.FAILED), isNull(), anyString());
        verify(transactionHandler).runInNewTransaction(any(Runnable.class));
        verify(pollProducer, never()).produceMessage(any());
    }

    // -----------------------------------------------------------------------
    // completedTransitionsToTerminalSuccess (ISSUE → ISSUED)
    // -----------------------------------------------------------------------

    @Test
    void completedTransitionsToTerminalSuccess() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, "OK"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(stateMachine).transition(eq(cert), eq(CertificateState.ISSUED), isNull(), anyString());
        verify(transactionHandler).runInNewTransaction(any(Runnable.class));
        verify(pollProducer, never()).produceMessage(any());
    }

    // -----------------------------------------------------------------------
    // completedRegisterTransitionsToRegistered
    // -----------------------------------------------------------------------

    @Test
    void completedRegisterTransitionsToRegistered() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REGISTRATION);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REGISTER))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.REGISTER, 0));

        verify(stateMachine).transition(eq(cert), eq(CertificateState.REGISTERED), isNull(), anyString());
        verify(transactionHandler).runInNewTransaction(any(Runnable.class));
    }

    // -----------------------------------------------------------------------
    // failedTransitionsToTerminalFailure (ISSUE → FAILED)
    // -----------------------------------------------------------------------

    @Test
    void failedTransitionsToTerminalFailure() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.FAILED, null, null, "CA error"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(stateMachine).transition(eq(cert), eq(CertificateState.FAILED), isNull(), anyString());
        verify(transactionHandler).runInNewTransaction(any(Runnable.class));
    }

    // -----------------------------------------------------------------------
    // failedRevokeTransitionsBackToIssued
    // -----------------------------------------------------------------------

    @Test
    void failedRevokeTransitionsBackToIssued() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REVOKE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REVOKE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.FAILED, null, null, "revoke failed"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.REVOKE, 0));

        verify(stateMachine).transition(eq(cert), eq(CertificateState.ISSUED), isNull(), anyString());
        verify(transactionHandler).runInNewTransaction(any(Runnable.class));
    }

    // -----------------------------------------------------------------------
    // metaUpdateExceptionDoesNotBlockTransition
    // -----------------------------------------------------------------------

    @Test
    void metaUpdateExceptionDoesNotBlockTransition() throws MessageHandlingException, ConnectorException, AttributeException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));

        var meta = List.of(mock(com.czertainly.api.model.common.attribute.common.MetadataAttribute.class));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, meta, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));
        doThrow(new AttributeException("meta fail"))
                .when(attributeEngine).updateMetadataAttributes(any(), any(ObjectAttributeContentInfo.class));

        // Should NOT throw — transition committed before meta update, meta failure swallowed.
        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(stateMachine).transition(eq(cert), eq(CertificateState.ISSUED), isNull(), anyString());
        verify(transactionHandler).runInNewTransaction(any(Runnable.class));
        verify(attributeEngine).updateMetadataAttributes(eq(meta), any(ObjectAttributeContentInfo.class));
    }

    // -----------------------------------------------------------------------
    // lostRaceDoesNotTransition
    // -----------------------------------------------------------------------

    @Test
    void lostRaceDoesNotTransition() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, null));

        // Locked re-read shows cert already transitioned away from pending (race lost).
        Certificate raced = certInState(CertificateState.ISSUED);
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(raced));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(stateMachine, never()).transition(any(), any(), any(), any());
        verify(transactionHandler).runInNewTransaction(any(Runnable.class));
    }

    // -----------------------------------------------------------------------
    // connectorExceptionReEnqueues
    // -----------------------------------------------------------------------

    @Test
    void connectorExceptionReEnqueues() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenThrow(new ConnectorException("network error"));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        ArgumentCaptor<CertificateStatusPollMessage> captor =
                ArgumentCaptor.forClass(CertificateStatusPollMessage.class);
        verify(pollProducer).produceMessage(captor.capture());
        assertThat(captor.getValue().attempt()).isEqualTo(1);
        verifyNoInteractions(stateMachine, transactionHandler);
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    private CertificateStatusPollMessage pollMsg(CertificateOperation op, int attempt) {
        return new CertificateStatusPollMessage(Resource.CERTIFICATE, CERT_UUID, op, attempt);
    }

    private Certificate certInState(CertificateState state) {
        AuthorityInstanceReference authority = mock(AuthorityInstanceReference.class);
        lenient().when(authority.getConnectorUuid()).thenReturn(CONNECTOR_UUID);

        RaProfile raProfile = mock(RaProfile.class);
        lenient().when(raProfile.getAuthorityInstanceReference()).thenReturn(authority);

        Certificate cert = mock(Certificate.class);
        lenient().when(cert.getUuid()).thenReturn(CERT_UUID);
        when(cert.getState()).thenReturn(state);
        lenient().when(cert.getRaProfile()).thenReturn(raProfile);

        return cert;
    }
}
