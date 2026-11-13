package com.otilm.core.service.v2.impl;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.certificate.type.AuthorityCertificateTypes;
import com.otilm.core.certificate.type.CertificateTypeHandler;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.certificate.type.RequestFormatResolver;
import com.otilm.core.certificate.type.UnsupportedCertificateTypeException;
import com.otilm.core.certificate.type.X509CertificateTypeHandler;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRegistrationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.writer.CertificatePendingIssueClaimWriter;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit coverage for plain (non-register) issuance dispatched through {@link AuthorityProviderAdapterFactory}. */
class ClientOperationServiceImplIssueDispatchTest {

    private ClientOperationServiceImpl service;
    private CertificateRepository certificateRepository;
    private CertificateRegistrationRepository certificateRegistrationRepository;
    private AuthorityProviderAdapterFactory adapterFactory;
    private CertificateInternalService certificateService;
    private PlatformTransactionManager transactionManager;
    private CertificateStateMachine stateMachine;
    private CertificateStatusPollWriter pollWriter;
    private ConnectorCapabilityService capabilityService;
    private CertificateEventHistoryInternalService certificateEventHistoryService;
    private EventProducer eventProducer;
    private CertificateLocationRepository certificateLocationRepository;
    private CertificatePendingIssueClaimWriter claimWriter;
    private RaProfileRepository raProfileRepository;

    private UUID certUuid;
    private Certificate certificate;
    private AuthorityProviderAdapter adapter;

    @BeforeEach
    void createServiceWithMockedCollaborators() throws NoSuchAlgorithmException {
        certificateRepository = mock(CertificateRepository.class);
        certificateRegistrationRepository = mock(CertificateRegistrationRepository.class);
        adapterFactory = mock(AuthorityProviderAdapterFactory.class);
        certificateService = mock(CertificateInternalService.class);
        transactionManager = mock(PlatformTransactionManager.class);
        stateMachine = mock(CertificateStateMachine.class);
        pollWriter = mock(CertificateStatusPollWriter.class);
        capabilityService = mock(ConnectorCapabilityService.class);
        certificateEventHistoryService = mock(CertificateEventHistoryInternalService.class);
        eventProducer = mock(EventProducer.class);
        certificateLocationRepository = mock(CertificateLocationRepository.class);

        service = new ClientOperationServiceImpl();
        service.setCertificateRepository(certificateRepository);
        raProfileRepository = mock(RaProfileRepository.class);
        service.setRaProfileRepository(raProfileRepository);
        var typeHandlerRegistry = new CertificateTypeHandlerRegistry(List.of(new X509CertificateTypeHandler()));
        service.setRequestFormatResolver(new RequestFormatResolver(typeHandlerRegistry));
        service.setTypeHandlerRegistry(typeHandlerRegistry);
        service.setAuthorityCertificateTypes(new AuthorityCertificateTypes());
        service.setCertificateRegistrationRepository(certificateRegistrationRepository);
        service.setCertificateLocationRepository(certificateLocationRepository);
        service.setAdapterFactory(adapterFactory);
        service.setCertificateService(certificateService);
        service.setTransactionManager(transactionManager);
        service.setStateMachine(stateMachine);
        service.setPollWriter(pollWriter);
        service.setCapabilityService(capabilityService);
        service.setCertificateEventHistoryService(certificateEventHistoryService);
        service.setEventProducer(eventProducer);
        claimWriter = mock(CertificatePendingIssueClaimWriter.class);
        service.setPendingIssueClaimWriter(claimWriter);

        when(transactionManager.getTransaction(ArgumentMatchers.any())).thenReturn(mock(TransactionStatus.class));

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        authority.setConnectorUuid(UUID.randomUUID());

        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);

        X509CertificateRequestEntity request = aCertificateRequest()
                .withContent(Base64.getEncoder().encodeToString("csr".getBytes()))
                .build();

        certUuid = UUID.randomUUID();
        certificate = aCertificate().build();
        certificate.setUuid(certUuid);
        certificate.setState(CertificateState.REQUESTED);
        certificate.setRaProfile(raProfile);
        certificate.setCertificateRequest(request);

        adapter = mock(AuthorityProviderAdapter.class);
        when(adapterFactory.forAuthority(ArgumentMatchers.any())).thenReturn(adapter);
        when(certificateRegistrationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.empty());
        when(certificateRepository.findAndLockWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));
        when(certificateRepository.findAndLockFreshByUuid(certUuid)).thenReturn(Optional.of(certificate));
        when(certificateRepository.findWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));
    }

    @Test
    void throwsUnsupportedNamingTheType_whenIssuingForATypeWithoutAHandlerThatNamesAFormat() {
        // given — the request names pkcs10, so only the type can refuse it
        ClientCertificateIssueRequestDto request = new ClientCertificateIssueRequestDto();
        request.setCertificateType(CertificateType.SSH);
        request.setFormat(CertificateRequestFormat.PKCS10);
        SecuredParentUUID authorityUuid = SecuredParentUUID.fromUUID(UUID.randomUUID());
        SecuredUUID raProfileUuid = SecuredUUID.fromUUID(UUID.randomUUID());

        // when
        ThrowingCallable issue = () -> service.issueCertificate(authorityUuid, raProfileUuid, request, null);

        // then
        assertThatThrownBy(issue)
                .isInstanceOf(UnsupportedCertificateTypeException.class)
                .hasMessageContaining(CertificateType.SSH.getCode());
        verifyNoInteractions(raProfileRepository);
    }

    @Test
    void refusesTheTypeBeforeSubmitting_whenItHasAHandlerButTheAuthorityDoesNotIssueIt() {
        // given
        CertificateType notIssued = CertificateType.SSH;
        CertificateTypeHandler sshHandler = mock(CertificateTypeHandler.class);
        when(sshHandler.typeCode()).thenReturn(notIssued.getCode());
        service
                .setRequestFormatResolver(new RequestFormatResolver(
                        new CertificateTypeHandlerRegistry(List.of(new X509CertificateTypeHandler(), sshHandler))));
        UUID authorityUuid = UUID.randomUUID();
        RaProfile raProfile = new RaProfile();
        raProfile.setName("x509-only-profile");
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReferenceUuid(authorityUuid);
        UUID raProfileUuid = UUID.randomUUID();
        when(raProfileRepository.findByUuid(raProfileUuid)).thenReturn(Optional.of(raProfile));
        ClientCertificateIssueRequestDto request = new ClientCertificateIssueRequestDto();
        request.setCertificateType(notIssued);
        request.setFormat(CertificateRequestFormat.PKCS10);

        // when
        ThrowingCallable issue = () -> service
                .issueCertificate(SecuredParentUUID.fromUUID(authorityUuid), SecuredUUID.fromUUID(raProfileUuid),
                        request, null);

        // then
        assertThatThrownBy(issue)
                .isInstanceOf(UnsupportedCertificateTypeException.class)
                .hasMessageContaining(notIssued.getCode())
                .hasMessageContaining(raProfile.getName());
        verifyNoInteractions(certificateService, adapterFactory);
    }

    @Test
    void skipsRegisterBindingLookup_whenNoBindingExists() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        // when
        service.issueCertificateAction(certUuid, true);

        // then — no binding present, so the register-bound locked read must never run
        verify(certificateRegistrationRepository, never()).findAndLockByCertificateUuid(ArgumentMatchers.any());
        verify(adapter).issue(ArgumentMatchers.eq(certificate), ArgumentMatchers.any());
    }

    @Test
    void completesIssuance_whenAdapterReturnsSyncOk() throws Exception {
        // given
        var certificateData = "cert-data";
        when(adapter.issue(ArgumentMatchers.eq(certificate), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk(certificateData, List.of(), CertificateType.X509));

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        verify(adapter).issue(ArgumentMatchers.eq(certificate), ArgumentMatchers.any());
        verify(certificateService)
                .issueRequestedCertificate(certUuid, certificateData, List.of(), CertificateType.X509);
    }

    @Test
    void issuesTheRequest_whenTheCertificateStillHoldsTheRequestItsIssueWasQueuedFor() throws Exception {
        // given
        UUID queuedFor = UUID.randomUUID();
        certificate.setCertificateRequestUuid(queuedFor);
        when(adapter.issue(ArgumentMatchers.eq(certificate), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        // when
        service.issueCertificateAction(certUuid, queuedFor, true);

        // then
        verify(adapter).issue(ArgumentMatchers.eq(certificate), ArgumentMatchers.any());
    }

    @Test
    void issuesNothing_whenTheCertificateHoldsAnotherRequestThanItsIssueWasQueuedFor() throws Exception {
        // given — a late issue queued for a request the certificate no longer holds
        certificate.setCertificateRequestUuid(UUID.randomUUID());
        UUID replacedRequestUuid = UUID.randomUUID();

        // when
        service.issueCertificateAction(certUuid, replacedRequestUuid, true);

        // then
        Mockito.verifyNoInteractions(adapter);
        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.PENDING_ISSUE),
                        ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void stillRaisesTheActionEvent_whenTheLocationLookupFailsAfterIssuance() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.eq(certificate), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        when(certificateLocationRepository.findByCertificateUuid(certUuid))
                .thenThrow(new IllegalStateException("db down"));

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        verify(eventProducer).produceMessage(ArgumentMatchers.any());
    }

    @Test
    void parksCertificateForPollAndSchedulesPoll_whenAdapterReturnsSyncNoContent() throws Exception {
        // given — a defensive branch: no live v2/v3 adapter emits 204 for issue today, but finalizeIssuance treats
        // SYNC_NO_CONTENT the same as an async acceptance. Use a pollable adapter so the async path actually
        // schedules a poll (an AsyncOperationCapability authority that advertises CERTIFICATE_STATUS_POLLING).
        AuthorityProviderAdapter asyncAdapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(AsyncOperationCapability.class));
        when(adapterFactory.forAuthority(ArgumentMatchers.any())).thenReturn(asyncAdapter);
        when(asyncAdapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncNoContent());
        // Poll scheduling reloads the cert with the polling graph and re-checks pollability against the adapter.
        when(certificateRepository.findForPollingByUuid(certUuid)).thenReturn(Optional.of(certificate));
        when(capabilityService
                .supports(ArgumentMatchers.any(AuthorityInstanceReference.class),
                        ArgumentMatchers.eq(FeatureFlag.CERTIFICATE_STATUS_POLLING)))
                .thenReturn(true);

        // when
        service.issueCertificateAction(certUuid, true);

        // then — the async-acceptance path was taken: no synchronous completion, a poll IS scheduled exactly once,
        // the action event is raised, and the certificate is not failed
        verify(certificateService, never())
                .issueRequestedCertificate(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(),
                        ArgumentMatchers.any());
        verify(pollWriter, times(1))
                .schedule(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateOperation.ISSUE),
                        ArgumentMatchers.any());
        verify(eventProducer).produceMessage(ArgumentMatchers.any());
        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void failsCertificate_whenAdapterThrowsConnectorException() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorException("upstream refused"));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED)))
                .thenReturn(true);

        // when / then
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class);

        verify(stateMachine)
                .transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void rollsBackFailTransaction_whenReReadUnderLockFailsDuringFailureHandling() throws Exception {
        // given — the connector call fails, and the re-read under lock while failing the certificate fails too
        TransactionStatus claimTx = mock(TransactionStatus.class);
        TransactionStatus failTx = mock(TransactionStatus.class);
        when(transactionManager.getTransaction(ArgumentMatchers.any())).thenReturn(claimTx, failTx);
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorException("upstream refused"));
        when(certificateRepository.findAndLockFreshByUuid(certUuid))
                .thenThrow(new IllegalStateException("certificate row vanished"));

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        verify(transactionManager).rollback(failTx);
        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void leavesCertificateClaimedForReconciliation_whenSyncResultHasNoCertificateData() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, List.of(), null));

        // when / then
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageContaining("did not contain certificate data");

        assertNoFailTransitionAndReconcileEventRecorded();
    }

    @Test
    void leavesCertificateClaimedForReconciliation_whenSyncResultHasEmptyCertificateData() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("", List.of(), null));

        // when / then
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageContaining("did not contain certificate data");

        assertNoFailTransitionAndReconcileEventRecorded();
    }

    private void assertNoFailTransitionAndReconcileEventRecorded() throws Exception {
        verify(certificateService, never())
                .issueRequestedCertificate(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(),
                        ArgumentMatchers.any());
        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        verify(certificateEventHistoryService)
                .addEventHistory(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED),
                        ArgumentMatchers.contains("reconcile manually"), ArgumentMatchers.eq(""));
    }

    @Test
    void leavesCertificateUnfailed_whenPostAcceptanceLocalFailureOccurs() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorAcceptedButLocalFailureException("accepted, local failed",
                        new RuntimeException("boom")));

        // when / then
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class);

        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void nonDomainExceptionMessageIsNotForwardedToTheCaller() throws Exception {
        // given — a pre-acceptance failure carrying a leaky, non-domain exception message
        String leakySecret = "jdbc://internal-host:5432/secret-schema constraint violation";
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new IllegalStateException(leakySecret));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED)))
                .thenReturn(true);

        // when / then — safeMessage gates exposure, so the raw message reaches neither the caller nor the audit reason
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageNotContaining(leakySecret);

        verify(stateMachine)
                .transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.eq("issuance failed"),
                        ArgumentMatchers.any());
    }

    @Test
    void doesNotLogConnectorText_whenIssueFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        stubIssueFailingWithConnectorText(connectorEcho);
        ListAppender<ILoggingEvent> logged = captureServiceLogs();

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        assertThat(collectLoggedText(logged))
                .isNotEmpty()
                .noneSatisfy(line -> assertThat(line).contains(connectorEcho));
    }

    @Test
    void throwsWithoutConnectorText_whenIssueFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        stubIssueFailingWithConnectorText(connectorEcho);

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageContaining(certUuid.toString())
                .hasMessageNotContaining(connectorEcho);
    }

    @Test
    void keepsConnectorTextInFailedReason_whenIssueFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        stubIssueFailingWithConnectorText(connectorEcho);

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        verify(stateMachine)
                .transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.contains(connectorEcho),
                        ArgumentMatchers.any());
    }

    @Test
    void recordsEventHistoryButDoesNotFail_whenPostAcceptanceCompletionFails() throws Exception {
        // given — the connector delivered a real certificate synchronously (post-acceptance), but the local
        // completion step then throws with a leaky message
        var certificateData = "cert-data";
        String leakySecret = "jdbc://internal-host:5432/secret-schema constraint violation";
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk(certificateData, List.of(), CertificateType.X509));
        doThrow(new IllegalStateException(leakySecret))
                .when(certificateService)
                .issueRequestedCertificate(certUuid, certificateData, List.of(), CertificateType.X509);

        // when / then — state-divergence rule: surface a shaped error but do NOT roll the cert back to FAILED
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageNotContaining(leakySecret);

        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        // the divergence is recorded to event history for the operator, with the leaky text scrubbed
        verify(certificateEventHistoryService)
                .addEventHistory(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED),
                        ArgumentMatchers
                                .argThat(msg -> msg.contains("completing local state failed")
                                        && !msg.contains(leakySecret)),
                        ArgumentMatchers.eq(""));
    }

    @Test
    void keepsConnectorTextInHistory_whenCompletingTheIssuanceFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        stubSynchronousIssueFailingToCompleteWithConnectorText(connectorEcho);

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        verify(certificateEventHistoryService)
                .addEventHistory(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED),
                        ArgumentMatchers.contains("completing local state failed"), ArgumentMatchers.eq(""));
        verify(certificateEventHistoryService)
                .addEventHistory(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED), ArgumentMatchers.contains(connectorEcho),
                        ArgumentMatchers.eq(""));
    }

    @Test
    void throwsWithoutConnectorText_whenCompletingTheIssuanceFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        stubSynchronousIssueFailingToCompleteWithConnectorText(connectorEcho);

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageContaining("completing local state failed")
                .hasMessageNotContaining(connectorEcho);
    }

    @Test
    void stampsClaim_whenClaimingTheCertificateForIssue() throws Exception {
        // given — the mocked state machine records the stamp the certificate carries at the moment it is claimed
        AtomicReference<OffsetDateTime> stampAtClaim = new AtomicReference<>();
        Mockito.doAnswer(inv -> {
            stampAtClaim.set(inv.<Certificate>getArgument(0).getPendingIssueClaimedAt());
            return null;
        })
                .when(stateMachine)
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.PENDING_ISSUE),
                        ArgumentMatchers.any(), ArgumentMatchers.anyString());
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        assertThat(stampAtClaim.get()).isNotNull().isBetween(before, OffsetDateTime.now(ZoneOffset.UTC));
    }

    @Test
    void clearsClaim_whenNonPollableAuthorityAcceptsAsynchronously() throws Exception {
        // given — no poll row is written: the out-of-band manual-completion case
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        assertClaimCleared();
    }

    @Test
    void clearsClaim_whenAuthorityAnswersWithNoContent() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncNoContent());

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        assertClaimCleared();
    }

    @Test
    void clearsClaim_whenConnectorAcceptsButALocalAdapterStepFails() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorAcceptedButLocalFailureException("accepted, local failed",
                        new RuntimeException("boom")));

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        assertClaimCleared();
    }

    @Test
    void clearsClaim_whenSyncResultHasNoCertificateData() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, List.of(), null));

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        assertClaimCleared();
    }

    @Test
    void clearsClaim_whenCompletingTheIssuedCertificateFails() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        doThrow(new IllegalStateException("persist failed"))
                .when(certificateService)
                .issueRequestedCertificate(certUuid, "cert-data", List.of(), CertificateType.X509);

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        assertClaimCleared();
    }

    @Test
    void leavesClaimToTheStateMachine_whenConnectorRejectsTheRequest() throws Exception {
        // given — the exit to FAILED goes through the state machine, which clears the stamp itself
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorException("upstream refused"));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED)))
                .thenReturn(true);

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        verify(claimWriter, never()).clear(ArgumentMatchers.any());
    }

    @Test
    void honoursTheAcceptance_whenClearingTheClaimFails() throws Exception {
        // given — a pollable authority accepts asynchronously, but clearing the claim fails (best-effort)
        stubPollableAuthorityAcceptingAsynchronously();
        when(claimWriter.clear(certUuid)).thenThrow(new IllegalStateException("db down"));

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        verify(pollWriter)
                .schedule(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateOperation.ISSUE),
                        ArgumentMatchers.any());
        assertThat(certificate.getPendingIssueClaimedAt()).isNull();
    }

    @Test
    void clearsClaimOnlyAfterSchedulingThePoll_whenPollableAuthorityAcceptsAsynchronously() throws Exception {
        // given — were Core to stop between the two writes, the claim must still be set (claim + poll row: the
        // poller owns it), never already cleared with no poll row behind it
        stubPollableAuthorityAcceptingAsynchronously();

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        var inOrder = Mockito.inOrder(pollWriter, claimWriter);
        inOrder
                .verify(pollWriter)
                .schedule(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateOperation.ISSUE),
                        ArgumentMatchers.any());
        inOrder.verify(claimWriter).clear(certUuid);
    }

    @Test
    void warnsOfTheDivergence_whenCertificateLeftPendingIssueBeforeTheClaimWasCleared() throws Exception {
        // given — the authority accepted, but by the time Core records it the certificate has already left
        // PENDING_ISSUE (reaped or cancelled during a slow call), so the guarded clear updates nothing
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));
        when(claimWriter.clear(certUuid)).thenReturn(0);
        when(certificateRepository.findStateByUuid(certUuid)).thenReturn(Optional.of(CertificateState.FAILED));
        ListAppender<ILoggingEvent> logged = captureServiceLogs();

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        assertThat(collectWarnings(logged)).anySatisfy(message -> assertThat(message).contains(certUuid.toString()));
    }

    @Test
    void logsNoClaimWarning_whenTheClaimIsCleared() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));
        when(claimWriter.clear(certUuid)).thenReturn(1);
        ListAppender<ILoggingEvent> logged = captureServiceLogs();

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        assertThat(collectWarnings(logged)).noneSatisfy(message -> assertThat(message).contains("claim"));
    }

    @Test
    void retriesClear_whenItHitsATransientDatabaseError() throws Exception {
        // given — a non-pollable authority accepts; the first clear meets a database blip, and without a retry the
        // stale claim would leave the accepted request to the reaper
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));
        when(claimWriter.clear(certUuid))
                .thenThrow(new TransientDataAccessResourceException("connection reset"))
                .thenReturn(1);

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        verify(claimWriter, times(2)).clear(certUuid);
    }

    @Test
    void givesUpOnClear_whenThreeAttemptsHitTransientErrors() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));
        when(claimWriter.clear(certUuid)).thenThrow(new TransientDataAccessResourceException("database down"));

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        verify(claimWriter, times(3)).clear(certUuid);
    }

    @Test
    void triesClearOnce_whenItFailsForANonTransientReason() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));
        when(claimWriter.clear(certUuid)).thenThrow(new IllegalStateException("not a database blip"));

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        verify(claimWriter, times(1)).clear(certUuid);
    }

    @Test
    void clearsClaim_whenRecordingAMetadataFailureFailsToo() throws Exception {
        // given — the authority accepts with metadata; storing it fails (no attribute engine is wired here) and
        // recording that failure in the history fails as well
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of(mock(MetadataAttribute.class))));
        doThrow(new IllegalStateException("history unavailable"))
                .when(certificateEventHistoryService)
                .addEventHistory(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(),
                        ArgumentMatchers.anyString(), ArgumentMatchers.anyString());

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        verify(claimWriter).clear(certUuid);
    }

    @Test
    void writesNoReconcileEntry_whenRaisingTheEventFailsAfterIssue() throws Exception {
        // given — the certificate is issued and recorded; only the action event after it fails (broker down)
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        IllegalStateException brokerDown = new IllegalStateException("broker down");
        doThrow(brokerDown).when(eventProducer).produceMessage(ArgumentMatchers.any());

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, true);

        // then
        assertThatThrownBy(issue).isSameAs(brokerDown);
        verify(certificateEventHistoryService, never())
                .addEventHistory(ArgumentMatchers.any(), ArgumentMatchers.any(),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED), ArgumentMatchers.anyString(),
                        ArgumentMatchers.anyString());
        verify(claimWriter, never()).clear(ArgumentMatchers.any());
    }

    @Test
    void logsNoDivergence_whenTheCertificateIsAlreadyIssued() throws Exception {
        // given — the guarded clear updates nothing because the certificate already completed
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));
        when(claimWriter.clear(certUuid)).thenReturn(0);
        when(certificateRepository.findStateByUuid(certUuid)).thenReturn(Optional.of(CertificateState.ISSUED));
        ListAppender<ILoggingEvent> logged = captureServiceLogs();

        // when
        service.issueCertificateAction(certUuid, true);

        // then
        assertThat(collectWarnings(logged)).noneSatisfy(message -> assertThat(message).contains("no longer"));
    }

    @AfterEach
    void releaseTheServiceLogger() {
        ((Logger) LoggerFactory.getLogger(ClientOperationServiceImpl.class)).detachAndStopAllAppenders();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubPollableAuthorityAcceptingAsynchronously() throws Exception {
        AuthorityProviderAdapter asyncAdapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(AsyncOperationCapability.class));
        when(adapterFactory.forAuthority(ArgumentMatchers.any())).thenReturn(asyncAdapter);
        when(asyncAdapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));
        when(certificateRepository.findForPollingByUuid(certUuid)).thenReturn(Optional.of(certificate));
        when(capabilityService
                .supports(ArgumentMatchers.any(AuthorityInstanceReference.class),
                        ArgumentMatchers.eq(FeatureFlag.CERTIFICATE_STATUS_POLLING)))
                .thenReturn(true);
    }

    private void stubSynchronousIssueFailingToCompleteWithConnectorText(String connectorText) throws Exception {
        var certificateData = "cert-data";
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk(certificateData, List.of(), CertificateType.X509));
        doAnswer(invocation -> {
            throw new ConnectorException("authority refused: " + connectorText);
        })
                .when(certificateService)
                .issueRequestedCertificate(certUuid, certificateData, List.of(), CertificateType.X509);
    }

    private void stubIssueFailingWithConnectorText(String connectorText) throws Exception {
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorException("authority refused: " + connectorText));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED)))
                .thenReturn(true);
    }

    private static List<String> collectLoggedText(ListAppender<ILoggingEvent> logged) {
        return logged.list
                .stream()
                .map(event -> event.getFormattedMessage() + (event.getThrowableProxy() == null
                        ? ""
                        : ThrowableProxyUtil.asString(event.getThrowableProxy())))
                .toList();
    }

    private static ListAppender<ILoggingEvent> captureServiceLogs() {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        ((Logger) LoggerFactory.getLogger(ClientOperationServiceImpl.class)).addAppender(appender);
        return appender;
    }

    private static List<String> collectWarnings(ListAppender<ILoggingEvent> logged) {
        return logged.list
                .stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    /** The claim was cleared both in the database and on the instance the caller holds. */
    private void assertClaimCleared() {
        verify(claimWriter).clear(certUuid);
        assertThat(certificate.getPendingIssueClaimedAt()).isNull();
    }
}
