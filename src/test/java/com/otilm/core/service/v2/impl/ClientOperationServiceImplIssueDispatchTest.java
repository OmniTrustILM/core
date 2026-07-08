package com.otilm.core.service.v2.impl;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRegistrationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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

        service = new ClientOperationServiceImpl();
        service.setCertificateRepository(certificateRepository);
        service.setCertificateRegistrationRepository(certificateRegistrationRepository);
        service.setAdapterFactory(adapterFactory);
        service.setCertificateService(certificateService);
        service.setTransactionManager(transactionManager);
        service.setStateMachine(stateMachine);
        service.setPollWriter(pollWriter);
        service.setCapabilityService(capabilityService);
        service.setCertificateEventHistoryService(certificateEventHistoryService);
        service.setEventProducer(eventProducer);

        when(transactionManager.getTransaction(ArgumentMatchers.any())).thenReturn(mock(TransactionStatus.class));

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        authority.setConnectorUuid(UUID.randomUUID());

        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);

        CertificateRequestEntity request = new CertificateRequestEntity();
        request.setContent(Base64.getEncoder().encodeToString("csr".getBytes()));

        certUuid = UUID.randomUUID();
        certificate = new Certificate();
        certificate.setUuid(certUuid);
        certificate.setState(CertificateState.REQUESTED);
        certificate.setRaProfile(raProfile);
        certificate.setCertificateRequest(request);

        adapter = mock(AuthorityProviderAdapter.class);
        when(adapterFactory.forAuthority(ArgumentMatchers.any())).thenReturn(adapter);
        when(certificateRegistrationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.empty());
        when(certificateRepository.findAndLockWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));
        when(certificateRepository.findWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));
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
        verify(certificateService).issueRequestedCertificate(certUuid, certificateData, List.of());
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
        when(capabilityService.supports(ArgumentMatchers.any(), ArgumentMatchers.eq(FeatureFlag.CERTIFICATE_STATUS_POLLING)))
                .thenReturn(true);

        // when
        service.issueCertificateAction(certUuid, true);

        // then — the async-acceptance path was taken: no synchronous completion, a poll IS scheduled exactly once,
        // the action event is raised, and the certificate is not failed
        verify(certificateService, never()).issueRequestedCertificate(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        verify(pollWriter, times(1)).schedule(ArgumentMatchers.eq(certUuid),
                ArgumentMatchers.eq(CertificateOperation.ISSUE), ArgumentMatchers.any());
        verify(eventProducer).produceMessage(ArgumentMatchers.any());
        verify(stateMachine, never()).transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void failsCertificate_whenAdapterThrowsConnectorException() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorException("upstream refused"));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED))).thenReturn(true);

        // when / then
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class);

        verify(stateMachine).transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void rollsBackFailTransaction_whenReReadUnderLockFailsDuringFailureHandling() throws Exception {
        // given — the connector call fails, and the subsequent re-read under lock inside
        // failClaimedCertificate itself fails (e.g. the row vanished); the failure-handling
        // transaction must roll back rather than leaving a half-applied FAILED transition
        TransactionStatus claimTx = mock(TransactionStatus.class);
        TransactionStatus failTx = mock(TransactionStatus.class);
        when(transactionManager.getTransaction(ArgumentMatchers.any())).thenReturn(claimTx, failTx);
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorException("upstream refused"));
        when(certificateRepository.findAndLockWithAssociationsByUuid(certUuid))
                .thenReturn(Optional.of(certificate))
                .thenThrow(new IllegalStateException("certificate row vanished"));

        // when / then
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class);

        verify(transactionManager).rollback(failTx);
        verify(stateMachine, never()).transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void rejectsIssuance_whenSyncResultHasNoCertificateData() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, List.of(), null));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED))).thenReturn(true);

        // when / then
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageContaining("did not contain certificate data");

        verify(stateMachine).transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void rejectsIssuance_whenSyncResultHasEmptyCertificateData() throws Exception {
        // given — an empty (non-null) body is the same connector-error shape as a null body
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("", List.of(), null));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED))).thenReturn(true);

        // when / then
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageContaining("did not contain certificate data");

        verify(stateMachine).transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void leavesCertificateUnfailed_whenPostAcceptanceLocalFailureOccurs() throws Exception {
        // given
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorAcceptedButLocalFailureException("accepted, local failed", new RuntimeException("boom")));

        // when / then
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class);

        verify(stateMachine, never()).transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void nonDomainExceptionMessageIsNotForwardedToTheCaller() throws Exception {
        // given — a pre-acceptance failure carrying a leaky, non-domain exception message
        String leakySecret = "jdbc://internal-host:5432/secret-schema constraint violation";
        when(adapter.issue(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new IllegalStateException(leakySecret));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED))).thenReturn(true);

        // when / then — safeMessage gates exposure, so the raw message reaches neither the caller nor the audit reason
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageNotContaining(leakySecret);

        verify(stateMachine).transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.eq("issuance failed"), ArgumentMatchers.any());
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
                .when(certificateService).issueRequestedCertificate(certUuid, certificateData, List.of());

        // when / then — state-divergence rule: surface a shaped error but do NOT roll the cert back to FAILED
        assertThatThrownBy(() -> service.issueCertificateAction(certUuid, true))
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageNotContaining(leakySecret);

        verify(stateMachine, never()).transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        // the divergence is recorded to event history for the operator, with the leaky text scrubbed
        verify(certificateEventHistoryService).addEventHistory(
                ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE),
                ArgumentMatchers.eq(CertificateEventStatus.FAILED),
                ArgumentMatchers.argThat(msg -> msg.contains("completing local state failed") && !msg.contains(leakySecret)),
                ArgumentMatchers.eq(""));
    }
}
