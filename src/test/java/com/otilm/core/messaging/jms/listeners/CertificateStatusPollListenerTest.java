package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.MessageHandlingException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.StatusPollResult;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.TransientDataAccessResourceException;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import com.otilm.api.model.core.other.ResourceEvent;

import static org.junit.jupiter.api.Assertions.assertThrows;
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
    @Mock private CertificateStatusPollWriter pollWriter;
    @Mock private StatusPollProperties statusPollProperties;
    @Mock private AttributeEngine attributeEngine;
    @Mock private com.otilm.core.events.transaction.TransactionHandler transactionHandler;
    @Mock private com.otilm.core.service.CertificateInternalService certificateService;
    @Mock private com.otilm.core.service.handler.authority.lifecycle.CertificateRevocationFinalizer revocationFinalizer;
    @Mock private com.otilm.core.service.writer.registration.CertificateRegistrationWriter registrationWriter;
    @Mock private EventProducer eventProducer;
    @Mock private CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;
    @Mock private com.otilm.core.service.writer.registration.CertificateRegistrationAuthorizationWriter registrationAuthorizationWriter;

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
        adapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(AsyncOperationCapability.class));
        asyncAdapter = (AsyncOperationCapability) adapter;

        listener = new CertificateStatusPollListener();
        listener.setCertificateRepository(certificateRepository);
        listener.setAdapterFactory(adapterFactory);
        listener.setStateMachine(stateMachine);
        listener.setPollWriter(pollWriter);
        listener.setStatusPollProperties(statusPollProperties);
        listener.setAttributeEngine(attributeEngine);
        listener.setTransactionHandler(transactionHandler);
        listener.setCertificateService(certificateService);
        listener.setRevocationFinalizer(revocationFinalizer);
        listener.setRegistrationWriter(registrationWriter);
        listener.setEventProducer(eventProducer);
        listener.setRegistrationAuthorizationRepository(registrationAuthorizationRepository);
        listener.setRegistrationAuthorizationWriter(registrationAuthorizationWriter);

        StatusPollProperties.PollSchedule schedule = mock(StatusPollProperties.PollSchedule.class);
        lenient().when(schedule.maxAttempts()).thenReturn(3);
        lenient().when(schedule.ceilingAttempt()).thenReturn(2);
        lenient().when(statusPollProperties.scheduleFor(any())).thenReturn(schedule);

        // Execute the transaction body synchronously so the locked-transaction logic runs in-test —
        // both the Runnable form (applyFailure) and the Supplier form (applyTerminalTransition).
        lenient().doAnswer(inv -> { ((Runnable) inv.getArgument(0)).run(); return null; })
                .when(transactionHandler).runInNewTransaction(any(Runnable.class));
        lenient().doAnswer(inv -> ((Supplier<?>) inv.getArgument(0)).get())
                .when(transactionHandler).runInNewTransaction(any(Supplier.class));
        lenient().when(adapterFactory.forAuthority(any())).thenReturn(adapter);
        // Default: no registration authorization, so the register-completion event does not fire in the
        // binding/transition tests. The dedicated fire tests below re-stub this to true.
        lenient().when(registrationAuthorizationRepository.existsByCertificateUuid(any())).thenReturn(false);
    }

    // -----------------------------------------------------------------------
    // certNotFoundDeletesPollRow
    // -----------------------------------------------------------------------

    @Test
    void certNotFoundDeletesPollRow() throws MessageHandlingException {
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.empty());

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(pollWriter).delete(CERT_UUID);
        verifyNoInteractions(adapterFactory, stateMachine, transactionHandler);
    }

    // -----------------------------------------------------------------------
    // nonPendingStateDeletesPollRow
    // -----------------------------------------------------------------------

    @Test
    void nonPendingStateDeletesPollRow() throws MessageHandlingException {
        Certificate cert = certInState(CertificateState.ISSUED);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(pollWriter).delete(CERT_UUID);
        verifyNoInteractions(adapterFactory, stateMachine, transactionHandler);
    }

    // -----------------------------------------------------------------------
    // inProgressLeavesPollRowForSweep
    // -----------------------------------------------------------------------

    @Test
    void inProgressLeavesPollRowForSweep() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.IN_PROGRESS, null, null, null));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        // Still in progress: the sweep already advanced next_poll_at, so the listener neither transitions
        // nor deletes the row.
        verify(pollWriter).resetAttempt(CERT_UUID, 2);
        verify(pollWriter, never()).delete(any());
        verifyNoInteractions(stateMachine, transactionHandler);
    }

    // -----------------------------------------------------------------------
    // inProgressLastAttemptKeepsPolling
    // -----------------------------------------------------------------------

    @Test
    void inProgressLastAttemptKeepsPolling() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.IN_PROGRESS, null, null, null));

        // attempt+1 >= maxAttempts(3), but the CA still reports: "I am still working."
        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 2));

        verify(pollWriter).resetAttempt(CERT_UUID, 2);
        verify(pollWriter, never()).delete(any());
        verifyNoInteractions(stateMachine, transactionHandler);
    }

    // -----------------------------------------------------------------------
    // completedIssueWithDataPersistsCertificate (ISSUE + cert data → issueRequestedCertificate)
    // -----------------------------------------------------------------------

    @Test
    void completedIssueWithDataPersistsCertificate() throws Exception {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, "PEMDATA", null, "OK"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        // Issue success persists content via issueRequestedCertificate (sets state itself); the
        // state machine is NOT used for this transition.
        verify(certificateService).issueRequestedCertificate(CERT_UUID, "PEMDATA", List.of());
        verify(stateMachine, never()).transition(any(), any(), any(), any());
        verify(pollWriter).delete(CERT_UUID);
    }

    // -----------------------------------------------------------------------
    // completedIssueDeterministicPersistFailureFailsFast
    // -----------------------------------------------------------------------

    @Test
    void completedIssueDeterministicPersistFailureFailsFast() throws Exception {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, "PEMDATA", null, "OK"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));
        // Deterministic persist failure (e.g. parse error / already-exists on redelivery).
        doThrow(new AttributeException("cannot parse"))
                .when(certificateService).issueRequestedCertificate(CERT_UUID, "PEMDATA", List.of());

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        // Does not loop to timeout: resolves straight to FAILED and stops polling.
        verify(stateMachine).transition(eq(cert), eq(CertificateState.FAILED), isNull(), anyString());
        verify(pollWriter).delete(CERT_UUID);
    }

    // -----------------------------------------------------------------------
    // completedIssueTransientPersistFailurePropagatesForRetry
    // -----------------------------------------------------------------------

    @Test
    void completedIssueTransientPersistFailurePropagatesForRetry() throws Exception {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, "PEMDATA", null, "OK"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));
        // Transient persist failure must NOT become a terminal FAILED. It propagates — rolling back the locked
        // transition and leaving the poll row in place — so the sweep re-enqueues and retries on its next tick.
        doThrow(new TransientDataAccessResourceException("db blip"))
                .when(certificateService).issueRequestedCertificate(CERT_UUID, "PEMDATA", List.of());

        CertificateStatusPollMessage msg = pollMsg(CertificateOperation.ISSUE, 0);
        assertThrows(RuntimeException.class, () -> listener.processMessage(msg));

        verify(stateMachine, never()).transition(any(), any(), any(), any());
        verify(pollWriter, never()).delete(any());
    }

    // -----------------------------------------------------------------------
    // completedIssueTransientPersistFailureLastAttemptFailsFast
    // -----------------------------------------------------------------------

    @Test
    void completedIssueTransientPersistFailureLastAttemptFailsFast() throws Exception {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, "PEMDATA", null, "OK"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));
        doThrow(new TransientDataAccessResourceException("db blip"))
                .when(certificateService).issueRequestedCertificate(CERT_UUID, "PEMDATA", List.of());

        // attempt+1 >= maxAttempts(3): retries are exhausted
        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 2));

        verify(stateMachine).transition(eq(cert), eq(CertificateState.FAILED), isNull(), anyString());
        verify(pollWriter).delete(CERT_UUID);
    }

    // -----------------------------------------------------------------------
    // unexpectedTransitionErrorRetainsPollRowAndPropagates
    // -----------------------------------------------------------------------

    @Test
    void unexpectedTransitionErrorRetainsPollRowAndPropagates() throws ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REVOKE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REVOKE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.FAILED, null, null, "revoke failed"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));
        // A should-not-happen invalid transition (anything other than the deterministic-persist case) must not
        // silently delete the poll row: it propagates so the sweep retries, and is logged with cert/op context
        // rather than only surfacing in the listener adapter's generic endpoint-level log.
        doThrow(new IllegalStateException("unexpected invalid transition"))
                .when(stateMachine).transition(eq(cert), eq(CertificateState.ISSUED), isNull(), anyString());

        CertificateStatusPollMessage msg = pollMsg(CertificateOperation.REVOKE, 0);
        assertThrows(RuntimeException.class, () -> listener.processMessage(msg));

        // Not resolved — the poll row stays so the sweep re-enqueues it.
        verify(pollWriter, never()).delete(any());
    }

    // -----------------------------------------------------------------------
    // completedIssueWithoutDataFailsTransition (COMPLETED but no cert content → FAILED)
    // -----------------------------------------------------------------------

    @Test
    void completedIssueWithoutDataFailsTransition() throws Exception {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, "OK"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        // COMPLETED with no certificate data must NOT reach ISSUED — treated as a failed operation.
        verify(stateMachine).transition(eq(cert), eq(CertificateState.FAILED), isNull(), anyString());
        verify(certificateService, never()).issueRequestedCertificate(any(), any(), any());
        verify(pollWriter).delete(CERT_UUID);
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
        verify(pollWriter).delete(CERT_UUID);    }

    // -----------------------------------------------------------------------
    // completedRegisterRefreshesBindingWithFinalMeta
    // -----------------------------------------------------------------------

    @Test
    void completedRegisterRefreshesBindingWithFinalMeta() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REGISTRATION);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        var finalMeta = List.of(mock(com.otilm.api.model.common.attribute.common.MetadataAttribute.class));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REGISTER))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, finalMeta, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.REGISTER, 0));

        // The completed REGISTER supersedes the 202 handle: the binding meta is refreshed with the final CA handle.
        verify(registrationWriter).upsert(CERT_UUID, finalMeta);
        verify(stateMachine).transition(eq(cert), eq(CertificateState.REGISTERED), isNull(), anyString());
        verify(pollWriter).delete(CERT_UUID);
    }

    @Test
    void completedRegisterFiresRegistrationEventWhenAuthorizationPresent() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REGISTRATION);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REGISTER))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(registrationAuthorizationRepository.existsByCertificateUuid(CERT_UUID)).thenReturn(true);

        listener.processMessage(pollMsg(CertificateOperation.REGISTER, 0));

        verify(eventProducer).produceMessage(Mockito.argThat(m -> m.getEvent() == ResourceEvent.CERTIFICATE_REGISTERED));
    }

    @Test
    void registerEventProduceFailureDoesNotAbortPollCleanup() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REGISTRATION);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REGISTER))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(registrationAuthorizationRepository.existsByCertificateUuid(CERT_UUID)).thenReturn(true);
        doThrow(new RuntimeException("broker down")).when(eventProducer).produceMessage(Mockito.any());

        // Best-effort fire: a produce failure must not propagate or abort poll-row cleanup.
        listener.processMessage(pollMsg(CertificateOperation.REGISTER, 0));

        verify(pollWriter).delete(CERT_UUID);
    }

    @Test
    void completedRegisterDoesNotFireEventWhenNoAuthorization() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REGISTRATION);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REGISTER))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        // existsByCertificateUuid defaults to false (setUp)

        listener.processMessage(pollMsg(CertificateOperation.REGISTER, 0));

        verify(eventProducer, never()).produceMessage(any());
    }

    @Test
    void completedIssueDoesNotFireRegistrationEvent() throws Exception {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, "PEMDATA", null, "OK"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        lenient().when(registrationAuthorizationRepository.existsByCertificateUuid(CERT_UUID)).thenReturn(true);

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(eventProducer, never()).produceMessage(any());
    }

    // -----------------------------------------------------------------------
    // bindingRefreshExceptionDoesNotBlockRegisterCompletion
    // -----------------------------------------------------------------------

    @Test
    void bindingRefreshExceptionDoesNotBlockRegisterCompletion() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REGISTRATION);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        var finalMeta = List.of(mock(com.otilm.api.model.common.attribute.common.MetadataAttribute.class));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REGISTER))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, finalMeta, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));
        doThrow(new IllegalStateException("db down")).when(registrationWriter).upsert(CERT_UUID, finalMeta);

        // Best-effort refresh: the transition already committed, so a failed binding refresh must not throw.
        listener.processMessage(pollMsg(CertificateOperation.REGISTER, 0));

        verify(registrationWriter).upsert(CERT_UUID, finalMeta);
        verify(stateMachine).transition(eq(cert), eq(CertificateState.REGISTERED), isNull(), anyString());
        verify(pollWriter).delete(CERT_UUID);
    }

    // -----------------------------------------------------------------------
    // failedRegisterWithMetaDoesNotRefreshBinding
    // -----------------------------------------------------------------------

    @Test
    void failedRegisterWithMetaDoesNotRefreshBinding() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REGISTRATION);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        var finalMeta = List.of(mock(com.otilm.api.model.common.attribute.common.MetadataAttribute.class));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REGISTER))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.FAILED, null, finalMeta, "CA rejected"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        listener.processMessage(pollMsg(CertificateOperation.REGISTER, 0));

        // A FAILED register must not upsert a binding row (the cert will never replay it) even though meta is present.
        verify(registrationWriter, never()).upsert(any(), any());
        verify(stateMachine).transition(eq(cert), eq(CertificateState.FAILED), isNull(), anyString());
        verify(pollWriter).delete(CERT_UUID);
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
        verify(pollWriter).delete(CERT_UUID);    }

    @Test
    void terminalIssueFailureClosesRegistrationAuthorizationWhenPresent() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.FAILED, null, null, "CA error"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(registrationAuthorizationRepository.existsByCertificateUuid(CERT_UUID)).thenReturn(true);

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        // A pre-registered placeholder that fails issuance no longer has a live registration.
        verify(registrationAuthorizationWriter).close(CERT_UUID);
    }

    @Test
    void completedIssueWithoutDataClosesRegistrationAuthorizationWhenPresent() throws Exception {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, "OK"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(registrationAuthorizationRepository.existsByCertificateUuid(CERT_UUID)).thenReturn(true);

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        // COMPLETED with no certificate data fails the issue; a pre-registered placeholder's authorization is retired.
        verify(registrationAuthorizationWriter).close(CERT_UUID);
    }

    @Test
    void terminalIssueFailureDoesNotCloseWhenNoRegistrationAuthorization() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.FAILED, null, null, "CA error"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        // existsByCertificateUuid defaults to false (setUp) — a non-self-service cert carries no authorization.

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(registrationAuthorizationWriter, never()).close(any());
    }

    @Test
    void failedRevokeDoesNotCloseRegistrationAuthorization() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REVOKE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REVOKE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.FAILED, null, null, "revoke failed"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        lenient().when(registrationAuthorizationRepository.existsByCertificateUuid(CERT_UUID)).thenReturn(true);

        listener.processMessage(pollMsg(CertificateOperation.REVOKE, 0));

        // A failed revoke returns to ISSUED, not FAILED — the registration must survive for renew/rekey reuse.
        verify(stateMachine).transition(eq(cert), eq(CertificateState.ISSUED), isNull(), anyString());
        verify(registrationAuthorizationWriter, never()).close(any());
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
        // A failed revoke must clear the pending-revoke params so the cert (back in ISSUED) does
        // not look like a revoke is still in flight.
        verify(revocationFinalizer).clearPendingRevokeFields(cert);
        verify(pollWriter).delete(CERT_UUID);    }

    // -----------------------------------------------------------------------
    // completedRevokeTransitionsToRevokedAndDestroysKey
    // -----------------------------------------------------------------------

    @Test
    void completedRevokeTransitionsToRevokedAndDestroysKey() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REVOKE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REVOKE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));
        var cleanup = new com.otilm.core.service.handler.authority.lifecycle.CertificateRevocationFinalizer.KeyCleanup(
                true, UUID.randomUUID());
        when(revocationFinalizer.prepareRevokeFinalization(cert)).thenReturn(cleanup);

        listener.processMessage(pollMsg(CertificateOperation.REVOKE, 0));

        verify(revocationFinalizer).prepareRevokeFinalization(cert);
        verify(stateMachine).transition(eq(cert), eq(CertificateState.REVOKED), isNull(), anyString());
        // Key destruction runs post-commit, outside the lock, from the captured cleanup decision.
        verify(revocationFinalizer).destroyKeyIfRequested(cleanup, CERT_UUID);
        verify(pollWriter).delete(CERT_UUID);
    }

    // -----------------------------------------------------------------------
    // completedRevokeApplyFailureLastAttemptNeverReturnsToIssued
    // -----------------------------------------------------------------------

    @Test
    void completedRevokeApplyFailureLastAttemptNeverReturnsToIssued() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REVOKE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REVOKE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, null, null, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));
        // The REVOKED transition keeps failing locally, right up to the last poll attempt.
        doThrow(new IllegalStateException("cannot apply revoked"))
                .when(stateMachine).transition(eq(cert), eq(CertificateState.REVOKED), isNull(), anyString());

        listener.processMessage(pollMsg(CertificateOperation.REVOKE, 2));

        // The CA has revoked the cert: it must never fall back to ISSUED, its pending-revoke fields must
        // not be cleared, and its key must not be treated as retained-and-valid.
        verify(stateMachine, never()).transition(eq(cert), eq(CertificateState.ISSUED), isNull(), anyString());
        verify(revocationFinalizer, never()).clearPendingRevokeFields(cert);
        verify(revocationFinalizer, never()).destroyKeyIfRequested(any(), any());
        // Capped for manual reconciliation: polling stops, cert left in PENDING_REVOKE.
        verify(pollWriter).delete(CERT_UUID);
    }

    // -----------------------------------------------------------------------
    // revokeTimeoutClearsPendingFields
    // -----------------------------------------------------------------------

    @Test
    void revokeTimeoutClearsPendingFields() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_REVOKE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.REVOKE))
                .thenThrow(new ConnectorException("network error"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        // No CA answer and no attempts left → time out; the revoke returns to ISSUED with pending fields cleared.
        listener.processMessage(pollMsg(CertificateOperation.REVOKE, 2));

        verify(stateMachine).transition(eq(cert), eq(CertificateState.ISSUED), isNull(), anyString());
        verify(revocationFinalizer).clearPendingRevokeFields(cert);
        verify(pollWriter).delete(CERT_UUID);
    }

    // -----------------------------------------------------------------------
    // metaUpdateExceptionDoesNotBlockTransition
    // -----------------------------------------------------------------------

    @Test
    void metaUpdateExceptionDoesNotBlockTransition() throws Exception {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));

        var meta = List.of(mock(com.otilm.api.model.common.attribute.common.MetadataAttribute.class));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, "PEMDATA", meta, null));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));
        doThrow(new AttributeException("meta fail"))
                .when(attributeEngine).updateMetadataAttributes(any(), any(ObjectAttributeContentInfo.class));

        // Should NOT throw — cert persisted/committed before the meta update, meta failure swallowed.
        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(certificateService).issueRequestedCertificate(CERT_UUID, "PEMDATA", List.of());
        verify(pollWriter).delete(CERT_UUID);
        verify(attributeEngine).updateMetadataAttributes(eq(meta), any(ObjectAttributeContentInfo.class));
    }

    // -----------------------------------------------------------------------
    // lostRaceDeletesPollRowWithoutTransition
    // -----------------------------------------------------------------------

    @Test
    void lostRaceDeletesPollRowWithoutTransition() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenReturn(new StatusPollResult(CertificateOperationStatus.COMPLETED, "PEMDATA", null, null));

        // Locked re-read shows cert already transitioned away from pending (race lost).
        Certificate raced = certInState(CertificateState.ISSUED);
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(raced));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        verify(stateMachine, never()).transition(any(), any(), any(), any());
        // Resolved by the racing actor — still stop polling.
        verify(pollWriter).delete(CERT_UUID);    }

    // -----------------------------------------------------------------------
    // connectorExceptionTransientLeavesPollRow
    // -----------------------------------------------------------------------

    @Test
    void connectorExceptionTransientLeavesPollRow() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenThrow(new ConnectorException("network error"));

        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 0));

        // Transient connector error with attempts remaining: leave the poll row; the sweep retries.
        verify(pollWriter, never()).delete(any());
        verifyNoInteractions(stateMachine, transactionHandler);
    }

    // -----------------------------------------------------------------------
    // connectorExceptionLastAttemptTimesOut
    // -----------------------------------------------------------------------

    @Test
    void connectorExceptionLastAttemptTimesOut() throws MessageHandlingException, ConnectorException {
        Certificate cert = certInState(CertificateState.PENDING_ISSUE);
        when(certificateRepository.findForPollingByUuid(CERT_UUID)).thenReturn(Optional.of(cert));
        when(asyncAdapter.pollStatus(cert, CertificateOperation.ISSUE))
                .thenThrow(new ConnectorException("network error"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(CERT_UUID))
                .thenReturn(Optional.of(cert));

        // Transient error but no attempts left → time out and stop polling.
        listener.processMessage(pollMsg(CertificateOperation.ISSUE, 2));

        verify(stateMachine).transition(eq(cert), eq(CertificateState.FAILED), isNull(), anyString());
        verify(pollWriter).delete(CERT_UUID);
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
