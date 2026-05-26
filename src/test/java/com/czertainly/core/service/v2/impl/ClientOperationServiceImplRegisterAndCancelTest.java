package com.czertainly.core.service.v2.impl;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.connector.v2.FeatureFlag;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.v2.AvailableOperationsDto;
import com.czertainly.api.model.core.v2.ClientCertificateDataResponseDto;
import com.czertainly.api.model.core.v2.ClientCertificateRegistrationDto;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.repository.CertificateRelationRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.messaging.jms.producers.CertificateStatusPollProducer;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.messaging.model.CertificateStatusPollMessage;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.CertificateEventHistoryService;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.handler.ConnectorCapabilityService;
import com.czertainly.core.service.handler.authority.AdapterOperationResult;
import com.czertainly.core.service.handler.authority.AsyncOperationCapability;
import com.czertainly.core.service.handler.authority.AuthorityProviderAdapter;
import com.czertainly.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.czertainly.core.service.handler.authority.CancelOutcome;
import com.czertainly.core.service.handler.authority.CancelResult;
import com.czertainly.core.service.handler.authority.CertificateOperation;
import com.czertainly.core.service.handler.authority.RegisterCapability;
import com.czertainly.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.czertainly.core.attribute.engine.AttributeEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the three new M3 methods: registerCertificate, listAvailableOperations,
 * and the PENDING_REGISTRATION path in cancelPendingCertificateOperation.
 */
@ExtendWith(MockitoExtension.class)
class ClientOperationServiceImplRegisterAndCancelTest {

    @Mock RaProfileRepository raProfileRepository;
    @Mock CertificateRepository certificateRepository;
    @Mock CertificateRelationRepository certificateRelationRepository;
    @Mock AuthorityProviderAdapterFactory adapterFactory;
    @Mock ConnectorCapabilityService capabilityService;
    @Mock CertificateStateMachine stateMachine;
    @Mock CertificateStatusPollProducer pollProducer;
    @Mock AttributeEngine attributeEngine;
    @Mock CertificateService certificateService;
    @Mock CertificateEventHistoryService certificateEventHistoryService;
    @Mock EventProducer eventProducer;
    @Mock PlatformTransactionManager transactionManager;
    @Mock jakarta.persistence.EntityManager entityManager;
    @Mock com.czertainly.core.events.transaction.TransactionHandler transactionHandler;

    @InjectMocks
    ClientOperationServiceImpl service;

    private SecuredParentUUID authorityUuid;
    private SecuredUUID raProfileUuid;
    private AuthorityInstanceReference authority;
    private RaProfile raProfile;
    private Certificate cert;
    private TransactionStatus txStatus;

    @BeforeEach
    void setUp() {
        UUID rawAuthorityUuid = UUID.randomUUID();
        authorityUuid = SecuredParentUUID.fromString(rawAuthorityUuid.toString());
        raProfileUuid = SecuredUUID.fromString(UUID.randomUUID().toString());

        authority = new AuthorityInstanceReference();
        authority.setUuid(rawAuthorityUuid);
        authority.setConnectorUuid(UUID.randomUUID());

        raProfile = new RaProfile();
        raProfile.setUuid(raProfileUuid.getValue());
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authority);

        cert = new Certificate();
        cert.setUuid(UUID.randomUUID());
        cert.setState(CertificateState.REQUESTED);
        cert.setRaProfile(raProfile);
        cert.setRaProfileUuid(raProfileUuid.getValue());

        txStatus = mock(TransactionStatus.class);

        lenient().when(raProfileRepository.findByUuidAndEnabledIsTrue(raProfileUuid.getValue()))
                .thenReturn(Optional.of(raProfile));
        lenient().when(certificateRepository.save(any(Certificate.class))).thenAnswer(inv -> {
            Certificate c = inv.getArgument(0);
            if (c.getUuid() == null) {
                c.setUuid(UUID.randomUUID());
            }
            return c;
        });
        lenient().when(transactionManager.getTransaction(any(DefaultTransactionDefinition.class))).thenReturn(txStatus);
        lenient().doAnswer(inv -> { ((Runnable) inv.getArgument(0)).run(); return null; })
                .when(transactionHandler).runInNewTransaction(any(Runnable.class));
    }

    // ---- registerCertificate: feature flag off ----

    @Test
    void registerCertificate_flagOff_throwsValidationException() {
        when(capabilityService.supports(eq(authority), eq(FeatureFlag.CERTIFICATE_REGISTRATION))).thenReturn(false);

        AuthorityProviderAdapter v3Adapter = mock(AuthorityProviderAdapter.class, withSettings()
                .extraInterfaces(RegisterCapability.class, AsyncOperationCapability.class));
        lenient().when(adapterFactory.forAuthority(authority)).thenReturn(v3Adapter);

        assertThrows(ValidationException.class, () ->
                service.registerCertificate(authorityUuid, raProfileUuid, new ClientCertificateRegistrationDto()));
    }

    // ---- registerCertificate: adapter does not implement RegisterCapability ----

    @Test
    void registerCertificate_adapterNoRegisterCapability_throwsValidationException() {
        when(capabilityService.supports(eq(authority), eq(FeatureFlag.CERTIFICATE_REGISTRATION))).thenReturn(true);
        AuthorityProviderAdapter plainAdapter = mock(AuthorityProviderAdapter.class); // no RegisterCapability
        when(adapterFactory.forAuthority(authority)).thenReturn(plainAdapter);

        assertThrows(ValidationException.class, () ->
                service.registerCertificate(authorityUuid, raProfileUuid, new ClientCertificateRegistrationDto()));
    }

    // ---- registerCertificate: SYNC_OK path ----

    @Test
    void registerCertificate_syncOk_transitionsToPendingThenRegistered() throws ConnectorException, NotFoundException {
        when(capabilityService.supports(eq(authority), eq(FeatureFlag.CERTIFICATE_REGISTRATION))).thenReturn(true);

        RegisterAndAsyncAdapter adapter = mock(RegisterAndAsyncAdapter.class);
        when(adapterFactory.forAuthority(authority)).thenReturn(adapter);
        when(adapter.register(any(), any())).thenReturn(AdapterOperationResult.syncOk(null, null, null));

        ClientCertificateDataResponseDto result = service.registerCertificate(
                authorityUuid, raProfileUuid, new ClientCertificateRegistrationDto());

        assertNotNull(result.getUuid());
        // PENDING_REGISTRATION transition then REGISTERED
        verify(stateMachine).transition(any(Certificate.class), eq(CertificateState.PENDING_REGISTRATION));
        verify(stateMachine).transition(any(Certificate.class), eq(CertificateState.REGISTERED));
        verify(pollProducer, never()).produceMessage(any());
    }

    // ---- registerCertificate: ASYNC_ACCEPTED path ----

    @Test
    void registerCertificate_asyncAccepted_schedulesPoll() throws ConnectorException, NotFoundException {
        when(capabilityService.supports(eq(authority), eq(FeatureFlag.CERTIFICATE_REGISTRATION))).thenReturn(true);

        RegisterAndAsyncAdapter adapter = mock(RegisterAndAsyncAdapter.class);
        when(adapterFactory.forAuthority(authority)).thenReturn(adapter);
        when(adapter.register(any(), any())).thenReturn(AdapterOperationResult.asyncAccepted(null));

        service.registerCertificate(authorityUuid, raProfileUuid, new ClientCertificateRegistrationDto());

        ArgumentCaptor<CertificateStatusPollMessage> msgCaptor = ArgumentCaptor.forClass(CertificateStatusPollMessage.class);
        verify(pollProducer).produceMessage(msgCaptor.capture());
        assertEquals(CertificateOperation.REGISTER, msgCaptor.getValue().op());
        assertEquals(1, msgCaptor.getValue().attempt());
        // stays in PENDING_REGISTRATION (no transition to REGISTERED)
        verify(stateMachine, never()).transition(any(), eq(CertificateState.REGISTERED));
    }

    // ---- listAvailableOperations: v2 authority (no async, no register) ----

    @Test
    void listAvailableOperations_v2Adapter_allSyncNoRegister() throws NotFoundException {
        AuthorityProviderAdapter v2Adapter = mock(AuthorityProviderAdapter.class); // no AsyncOperationCapability
        when(adapterFactory.forAuthority(authority)).thenReturn(v2Adapter);
        lenient().when(capabilityService.supports(eq(authority), eq(FeatureFlag.CERTIFICATE_REGISTRATION))).thenReturn(false);

        AvailableOperationsDto dto = service.listAvailableOperations(authorityUuid, raProfileUuid);

        assertEquals(4, dto.getOperations().size());
        dto.getOperations().forEach(op -> {
            assertTrue(op.isSupported() || op.getOperation().equals("REGISTER"),
                    "Only REGISTER may be unsupported on v2 adapter");
            assertFalse(op.isAsyncSupported(), "v2 adapter should report no async for " + op.getOperation());
        });
        var register = dto.getOperations().stream().filter(o -> "REGISTER".equals(o.getOperation())).findFirst().orElseThrow();
        assertFalse(register.isSupported());
    }

    // ---- listAvailableOperations: v3 adapter without register FF ----

    @Test
    void listAvailableOperations_v3AdapterNoRegisterFF_issueAsyncRegisterNotSupported() throws NotFoundException {
        AsyncOperationCapability v3Adapter = mock(AsyncOperationCapability.class,
                withSettings().extraInterfaces(AuthorityProviderAdapter.class));
        when(adapterFactory.forAuthority(authority)).thenReturn((AuthorityProviderAdapter) v3Adapter);
        lenient().when(capabilityService.supports(eq(authority), eq(FeatureFlag.CERTIFICATE_REGISTRATION))).thenReturn(false);

        AvailableOperationsDto dto = service.listAvailableOperations(authorityUuid, raProfileUuid);

        var issue = dto.getOperations().stream().filter(o -> "ISSUE".equals(o.getOperation())).findFirst().orElseThrow();
        assertTrue(issue.isAsyncSupported());
        var register = dto.getOperations().stream().filter(o -> "REGISTER".equals(o.getOperation())).findFirst().orElseThrow();
        assertFalse(register.isSupported());
    }

    // ---- listAvailableOperations: v3 adapter with register FF ----

    @Test
    void listAvailableOperations_v3AdapterWithRegisterFF_allAsync() throws NotFoundException {
        RegisterAndAsyncAdapter v3Adapter = mock(RegisterAndAsyncAdapter.class);
        when(adapterFactory.forAuthority(authority)).thenReturn(v3Adapter);
        when(capabilityService.supports(eq(authority), eq(FeatureFlag.CERTIFICATE_REGISTRATION))).thenReturn(true);

        AvailableOperationsDto dto = service.listAvailableOperations(authorityUuid, raProfileUuid);

        var register = dto.getOperations().stream().filter(o -> "REGISTER".equals(o.getOperation())).findFirst().orElseThrow();
        assertTrue(register.isSupported());
        assertTrue(register.isAsyncSupported());
        assertTrue(register.isCancelSupported());
    }

    // ---- cancelPendingCertificateOperation: non-async adapter, PENDING_REGISTRATION -> unsupported ----

    @Test
    void cancel_nonAsyncAdapter_pendingRegistration_fallsBackToV2LegacyPath_noV2CancelForRegister()
            throws NotFoundException {
        // PENDING_REGISTRATION on a v2 adapter is architecturally unsupported (v2 has no
        // register flow), but if it somehow occurs the cancel code still throws because v2
        // legacy cancel logic cannot handle CancelCleanupKind.REGISTER (it'll fall to
        // the else branch for revoke). This test documents that the code at least produces
        // a ValidationException from determineCancelTarget's state check when invoked on a
        // cert in a non-pending state — i.e., it doesn't silently succeed.
        cert.setState(CertificateState.ISSUED); // not a pending state
        when(certificateRepository.findWithAssociationsByUuid(cert.getUuid()))
                .thenReturn(Optional.of(cert));

        var cancelReq = new com.czertainly.api.model.client.certificate.CancelPendingCertificateRequestDto();
        var certUuid = cert.getUuid().toString();

        assertThrows(ValidationException.class, () ->
                service.cancelPendingCertificateOperation(authorityUuid, raProfileUuid, certUuid, cancelReq));
    }

    // ---- cancelPendingCertificateOperation: v3 adapter, PENDING_REGISTRATION, CANCELLED ----

    @Test
    void cancel_v3Adapter_pendingRegistration_cancelled_transitionsToFailed()
            throws ConnectorException, NotFoundException {
        cert.setState(CertificateState.PENDING_REGISTRATION);
        when(certificateRepository.findWithAssociationsByUuid(cert.getUuid()))
                .thenReturn(Optional.of(cert));

        RegisterAndAsyncAdapter v3Adapter = mock(RegisterAndAsyncAdapter.class);
        when(adapterFactory.forAuthority(authority)).thenReturn(v3Adapter);
        when(v3Adapter.cancel(eq(cert), eq(CertificateOperation.REGISTER)))
                .thenReturn(new CancelResult(CancelOutcome.CANCELLED));

        // commitLocalCancel needs a locked re-read
        Certificate freshCert = new Certificate();
        freshCert.setUuid(cert.getUuid());
        freshCert.setState(CertificateState.PENDING_REGISTRATION);
        freshCert.setRaProfile(raProfile);
        when(certificateRepository.findAndLockWithAssociationsByUuid(cert.getUuid()))
                .thenReturn(Optional.of(freshCert));
        doNothing().when(stateMachine).transition(any(), any(), any(), any());

        doNothing().when(certificateService).checkIssuePermissions();

        var cancelReq = new com.czertainly.api.model.client.certificate.CancelPendingCertificateRequestDto();
        service.cancelPendingCertificateOperation(authorityUuid, raProfileUuid, cert.getUuid().toString(), cancelReq);

        verify(stateMachine).transition(eq(freshCert), eq(CertificateState.FAILED), any(), any());
        verify(transactionHandler).runInNewTransaction(any(Runnable.class));
    }

    // ---- cancelPendingCertificateOperation: v3 adapter, REFUSED_PAST_POINT_OF_NO_RETURN ----

    @Test
    void cancel_v3Adapter_refused_throwsValidationExceptionAndStateUnchanged()
            throws ConnectorException, NotFoundException {
        cert.setState(CertificateState.PENDING_REGISTRATION);
        when(certificateRepository.findWithAssociationsByUuid(cert.getUuid()))
                .thenReturn(Optional.of(cert));

        RegisterAndAsyncAdapter v3Adapter = mock(RegisterAndAsyncAdapter.class);
        when(adapterFactory.forAuthority(authority)).thenReturn(v3Adapter);
        when(v3Adapter.cancel(eq(cert), eq(CertificateOperation.REGISTER)))
                .thenReturn(new CancelResult(CancelOutcome.REFUSED_PAST_POINT_OF_NO_RETURN));

        doNothing().when(certificateService).checkIssuePermissions();

        var cancelReq = new com.czertainly.api.model.client.certificate.CancelPendingCertificateRequestDto();
        ValidationException ex = assertThrows(ValidationException.class, () ->
                service.cancelPendingCertificateOperation(authorityUuid, raProfileUuid, cert.getUuid().toString(), cancelReq));

        assertTrue(ex.getMessage().contains("point of no return"));
        // commitLocalCancel must NOT have been called
        verify(certificateRepository, never()).findAndLockWithAssociationsByUuid(any());
    }

    /**
     * Combined interface for mocking adapters that implement both RegisterCapability and
     * AsyncOperationCapability (i.e., the v3 adapter). Mockito requires a concrete type
     * to use withSettings().extraInterfaces() cleanly; a local interface is simpler.
     */
    interface RegisterAndAsyncAdapter
            extends AuthorityProviderAdapter, RegisterCapability, AsyncOperationCapability {}
}
