package com.otilm.core.service.v2.impl;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.certificate.type.AuthorityCertificateTypes;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.certificate.type.RequestFormatResolver;
import com.otilm.core.certificate.type.X509CertificateTypeHandler;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistration;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRegistrationRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.logging.RedactedFailure;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.RegisterCapability;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.writer.CertificatePendingIssueClaimWriter;
import com.otilm.core.service.writer.registration.CertificateRegistrationWriter;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentMatchers;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
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
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the register-bound issuance branch: a placeholder carrying a registration binding issues its
 * attached CSR through {@link RegisterCapability#issueRegistered} rather than the v2 client.
 */
class ClientOperationServiceImplRegisterBoundIssueTest {

    private ClientOperationServiceImpl service;

    private CertificateRepository certificateRepository;
    private CertificateRegistrationRepository certificateRegistrationRepository;
    private CertificateRegistrationWriter certificateRegistrationWriter;
    private AuthorityProviderAdapterFactory adapterFactory;
    private ConnectorCapabilityService capabilityService;
    private CertificateInternalService certificateService;
    private PlatformTransactionManager transactionManager;
    private CertificateStateMachine stateMachine;
    private AttributeEngine attributeEngine;
    private CertificateEventHistoryInternalService certificateEventHistoryService;
    private CertificateStatusPollWriter pollWriter;
    private CertificateRelationRepository certificateRelationRepository;
    private EventProducer eventProducer;
    private CertificatePendingIssueClaimWriter claimWriter;

    private RaProfile raProfile;
    private AuthorityInstanceReference authority;
    private UUID certUuid;
    private X509CertificateEntity certificate;
    private CertificateRegistration binding;

    private static Map<String, OidRecord> savedRdnCache;

    // Rendering the subject DN reads the global RDN OID cache; seed it so the identity-override tests don't
    // depend on the Spring context that normally populates it.
    @BeforeAll
    static void seedRdnOidCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);

        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.10",
                        OidRecord.builder().displayName("Organization").code("O").build());
    }

    @AfterAll
    static void restoreRdnOidCache() {
        OidHandler
                .cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                        savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    @AfterEach
    void releaseTheServiceLogger() {
        ((Logger) LoggerFactory.getLogger(ClientOperationServiceImpl.class)).detachAndStopAllAppenders();
    }

    @BeforeEach
    void createServiceWithMockedCollaborators() throws Exception {
        certificateRepository = mock(CertificateRepository.class);
        certificateRegistrationRepository = mock(CertificateRegistrationRepository.class);
        certificateRegistrationWriter = mock(CertificateRegistrationWriter.class);
        adapterFactory = mock(AuthorityProviderAdapterFactory.class);
        capabilityService = mock(ConnectorCapabilityService.class);
        certificateService = mock(CertificateInternalService.class);
        transactionManager = mock(PlatformTransactionManager.class);
        stateMachine = mock(CertificateStateMachine.class);
        attributeEngine = mock(AttributeEngine.class);
        certificateEventHistoryService = mock(CertificateEventHistoryInternalService.class);
        pollWriter = mock(CertificateStatusPollWriter.class);
        certificateRelationRepository = mock(CertificateRelationRepository.class);
        eventProducer = mock(EventProducer.class);

        service = new ClientOperationServiceImpl();
        service.setCertificateRepository(certificateRepository);
        var typeHandlerRegistry = new CertificateTypeHandlerRegistry(List.of(new X509CertificateTypeHandler()));
        service.setRequestFormatResolver(new RequestFormatResolver(typeHandlerRegistry));
        service.setTypeHandlerRegistry(typeHandlerRegistry);
        service.setAuthorityCertificateTypes(new AuthorityCertificateTypes());
        service.setCertificateRegistrationRepository(certificateRegistrationRepository);
        service.setCertificateLocationRepository(mock(CertificateLocationRepository.class));
        service.setCertificateRegistrationWriter(certificateRegistrationWriter);
        service.setRegistrationAuthorizationRepository(mock(CertificateRegistrationAuthorizationRepository.class));
        service.setAdapterFactory(adapterFactory);
        service.setCapabilityService(capabilityService);
        service.setCertificateService(certificateService);
        service.setTransactionManager(transactionManager);
        service.setStateMachine(stateMachine);
        service.setAttributeEngine(attributeEngine);
        service.setCertificateEventHistoryService(certificateEventHistoryService);
        service.setPollWriter(pollWriter);
        service.setCertificateRelationRepository(certificateRelationRepository);
        service.setEventProducer(eventProducer);
        claimWriter = mock(CertificatePendingIssueClaimWriter.class);
        service.setPendingIssueClaimWriter(claimWriter);

        TransactionStatus tx = mock(TransactionStatus.class);
        when(transactionManager.getTransaction(ArgumentMatchers.any())).thenReturn(tx);

        authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        authority.setConnectorUuid(UUID.randomUUID());

        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);

        X509CertificateRequestEntity request = aCertificateRequest()
                .withContent(Base64.getEncoder().encodeToString("csr-content".getBytes()))
                .build();

        certUuid = UUID.randomUUID();
        certificate = aCertificate().build();
        certificate.setUuid(certUuid);
        certificate.setState(CertificateState.REGISTERED);
        certificate.setRaProfile(raProfile);
        certificate.setCertificateRequest(request);
        certificate.setSubjectDn("CN=device-1,O=Acme");

        binding = new CertificateRegistration();
        binding.setCertificateUuid(certUuid);

        when(certificateRepository.findWithAuthorityAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));
        when(certificateRepository.findAndLockWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));
        when(certificateRepository.findAndLockFreshByUuid(certUuid)).thenReturn(Optional.of(certificate));
        // The dispatch discriminator (non-locking) and the locked read in the register-bound path both resolve the
        // binding by certificate UUID — a pre-registered placeholder has one.
        when(certificateRegistrationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.of(binding));
        when(certificateRegistrationRepository.findAndLockByCertificateUuid(certUuid)).thenReturn(Optional.of(binding));
        when(capabilityService.supports(ArgumentMatchers.any(AuthorityInstanceReference.class), ArgumentMatchers.any()))
                .thenReturn(false);
        when(capabilityService
                .supports(ArgumentMatchers.any(AuthorityInstanceReference.class),
                        ArgumentMatchers.eq(FeatureFlag.CERTIFICATE_REGISTRATION)))
                .thenReturn(true);
    }

    /** Mocks an adapter that supports the register-bound issue path and wires the factory to return it. */
    private RegisterCapability registerCapableAdapter() {
        AuthorityProviderAdapter adapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class, AsyncOperationCapability.class));
        when(adapterFactory.forAuthority(ArgumentMatchers.any())).thenReturn(adapter);
        return (RegisterCapability) adapter;
    }

    private void issue() throws Exception {
        service.issueCertificateAction(certUuid, true);
    }

    @Test
    void dispatchesToTheAdapter_whenARegisteredPlaceholderIsIssuedOnARegisterCapableAuthority() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        // when
        issue();

        // then
        verify(adapter)
                .issueRegistered(ArgumentMatchers.eq(certificate), ArgumentMatchers.any(), ArgumentMatchers.any());
        verify(certificateService).issueRequestedCertificate(certUuid, "cert-data", List.of(), CertificateType.X509);
    }

    @Test
    void registeredPlaceholderOnNonRegisterCapableAuthorityFallsThroughToV2Path() {
        AuthorityProviderAdapter plainAdapter = mock(AuthorityProviderAdapter.class);
        when(adapterFactory.forAuthority(ArgumentMatchers.any())).thenReturn(plainAdapter);

        // A binding exists (see setUp), so dispatch consults it, but a non-register-capable adapter falls through
        // to the v2 path. The register-bound branch is characterized by the locked binding read, so verifying it
        // never runs is the load-bearing assertion that the branch was NOT taken. Absorb the unmocked v2
        // fall-through's failure.
        try {
            issue();
        } catch (Exception expectedFromUnmockedV2Path) {
            // ignored — see above
        }

        verify(certificateRegistrationRepository, never()).findAndLockByCertificateUuid(certUuid);
    }

    @Test
    void missingRegistrationBindingIsRejectedAndRollsBackTransaction() {
        RegisterCapability adapter = registerCapableAdapter();
        when(certificateRegistrationRepository.findAndLockByCertificateUuid(certUuid)).thenReturn(Optional.empty());
        TransactionStatus tx = mock(TransactionStatus.class);
        when(transactionManager.getTransaction(ArgumentMatchers.any())).thenReturn(tx);

        assertThatThrownBy(this::issue).isInstanceOf(CertificateOperationException.class);

        Mockito.verifyNoInteractions(adapter);
        verify(transactionManager).rollback(tx);
        verify(transactionManager, never()).commit(ArgumentMatchers.any());
    }

    // Any non-issuable state observed under the lock is rejected before any connector call.
    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"FAILED", "PENDING_ISSUE"})
    void racedStateIsRejectedWithoutConnectorCall(CertificateState racedState) {
        RegisterCapability adapter = registerCapableAdapter();
        X509CertificateEntity racedRead = aCertificate().withState(racedState).build();
        when(certificateRepository.findAndLockWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(racedRead));

        assertThatThrownBy(this::issue).isInstanceOf(CertificateOperationException.class).hasMessageContaining("raced");

        Mockito.verifyNoInteractions(adapter);
    }

    @Test
    void claimsPendingIssueBeforeCallingConnector() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        issue();

        InOrder inOrder = Mockito.inOrder(stateMachine, adapter);
        inOrder
                .verify(stateMachine)
                .transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.PENDING_ISSUE),
                        ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.any());
        inOrder.verify(adapter).issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void requestStructuredAndIdentityOverrideTogetherBuildRequestContent() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED)).thenReturn(true);
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_IDENTITY_OVERRIDE)).thenReturn(true);
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        issue();

        verify(adapter).issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.isNotNull());
    }

    @Test
    void identityOverrideWithoutRequestStructuredPassesNullRequestContent() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_IDENTITY_OVERRIDE)).thenReturn(true);
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        issue();

        verify(adapter).issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.isNull());
    }

    @Test
    void neitherFlagPassesNullRequestContent() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        // capabilityService.supports defaults to false in setUp().
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        issue();

        verify(adapter).issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.isNull());
    }

    @Test
    void completesTheIssuance_whenTheAdapterReturnsSyncOk() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        List<MetadataAttribute> meta = List.of(caHandle("endEntityName", "device-1"));
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", meta, CertificateType.X509));

        // when
        issue();

        // then — the certificate is stored and the binding it was issued under is cleared
        verify(certificateService).issueRequestedCertificate(certUuid, "cert-data", meta, CertificateType.X509);
        verify(certificateRegistrationWriter).clear(certUuid);
    }

    @Test
    void schedulesOnePoll_whenTheAdapterAcceptsAsynchronously() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));
        // transitionToPendingIssue's internal scheduleStatusPoll reloads the certificate with the polling
        // graph and re-resolves the adapter to evaluate pollability.
        when(certificateRepository.findForPollingByUuid(certUuid)).thenReturn(Optional.of(certificate));
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_STATUS_POLLING)).thenReturn(true);

        // when
        issue();

        // then — the certificate waits in PENDING_ISSUE for the poll, and nothing is stored yet
        verify(stateMachine)
                .transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.PENDING_ISSUE),
                        ArgumentMatchers.any(), ArgumentMatchers.any());
        verify(pollWriter, times(1))
                .schedule(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateOperation.ISSUE),
                        ArgumentMatchers.any());
        verify(certificateRegistrationWriter).clear(certUuid);
        verify(certificateService, never())
                .issueRequestedCertificate(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(),
                        ArgumentMatchers.any());
    }

    @Test
    void connectorAcceptedButLocalFailureDoesNotFailTheCertificate() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorAcceptedButLocalFailureException("accepted upstream, local step failed",
                        new RuntimeException("boom")));

        assertThatThrownBy(this::issue).isInstanceOf(CertificateOperationException.class);

        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        verify(certificateEventHistoryService)
                .addEventHistory(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED),
                        ArgumentMatchers
                                .contains("left " + CertificateState.PENDING_ISSUE.getLabel() + " for reconciliation"),
                        ArgumentMatchers.eq(""));
    }

    @Test
    void preAcceptanceConnectorFailureFailsTheCertificate() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorException("upstream refused"));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED)))
                .thenReturn(true);
        when(certificateRepository.findAndLockWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));

        assertThatThrownBy(this::issue).isInstanceOf(CertificateOperationException.class);

        // handleFailedOrRejectedEvent delegates the FAILED transition and its audit-history write to the (mocked)
        // state machine, so verifying this call is the unit-level proxy for "the certificate was failed".
        verify(stateMachine)
                .transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.any(), ArgumentMatchers.any());
        // Pre-acceptance FAILED is terminal — the binding is dropped.
        verify(certificateRegistrationWriter).clear(certUuid);
    }

    @Test
    void logsRedactedFailureWithoutConnectorText_whenRegisterBoundIssueFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        stubRegisterBoundIssueFailingWith(new ConnectorException("authority refused: " + connectorEcho));
        ListAppender<ILoggingEvent> logged = captureServiceLogs();

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        assertThat(logged.list).anySatisfy(event -> {
            assertThat(event.getFormattedMessage())
                    .contains("failed before the connector accepted it")
                    .contains(certUuid.toString());
            assertThat(event.getThrowableProxy().getMessage()).isEqualTo(ConnectorException.class.getName());
            assertThat(event.getThrowableProxy().getClassName()).isEqualTo(RedactedFailure.class.getName());
        });
        assertThat(collectLoggedText(logged)).noneSatisfy(line -> assertThat(line).contains(connectorEcho));
    }

    @Test
    void doesNotLogConnectorText_whenConnectorAcceptsButALocalAdapterStepFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        stubRegisterBoundIssueFailingWith(new ConnectorAcceptedButLocalFailureException(
                "accepted, then failed: " + connectorEcho, new IllegalStateException("local")));
        ListAppender<ILoggingEvent> logged = captureServiceLogs();

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        assertThat(collectLoggedText(logged))
                .isNotEmpty()
                .noneSatisfy(line -> assertThat(line).contains(connectorEcho));
    }

    @Test
    void keepsConnectorTextInHistory_whenCompletingTheRegisterBoundIssueFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        doAnswer(invocation -> {
            throw new ConnectorException("authority refused: " + connectorEcho);
        }).when(certificateService).issueRequestedCertificate(certUuid, "cert-data", List.of(), CertificateType.X509);

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageNotContaining(connectorEcho);
        verify(certificateEventHistoryService)
                .addEventHistory(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED), ArgumentMatchers.contains(connectorEcho),
                        ArgumentMatchers.eq(""));
    }

    @Test
    void throwsWithoutConnectorText_whenRegisterBoundIssueFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        stubRegisterBoundIssueFailingWith(new ConnectorException("authority refused: " + connectorEcho));

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageContaining(certUuid.toString())
                .hasMessageNotContaining(connectorEcho);
    }

    @Test
    void keepsConnectorTextInFailedReason_whenRegisterBoundIssueFails() throws Exception {
        // given
        var connectorEcho = "connector-echo-7f3a";
        stubRegisterBoundIssueFailingWith(new ConnectorException("authority refused: " + connectorEcho));

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        verify(stateMachine)
                .transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.contains(connectorEcho),
                        ArgumentMatchers.any());
    }

    @Test
    void nonDomainExceptionMessageIsNotForwardedToTheCaller() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        String leakySecret = "jdbc://internal-host:5432/secret-schema constraint violation";
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new IllegalStateException(leakySecret));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED)))
                .thenReturn(true);
        when(certificateRepository.findAndLockWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));

        assertThatThrownBy(this::issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageNotContaining(leakySecret);

        // The audit message handed to the state machine (and therefore to the persisted event history) is
        // the safe placeholder, not the raw IllegalStateException message.
        verify(stateMachine)
                .transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.eq(CertificateEvent.ISSUE),
                        ArgumentMatchers.eq("register-bound issuance failed"), ArgumentMatchers.any());
    }

    // The state-divergence-critical branch the feature exists to protect: connector accepted (SYNC_OK) but local
    // completion throws, so the certificate must NOT be rolled back to FAILED and the binding must be left in place
    // for reconciliation.
    @Test
    void leavesTheCertificateUnfailed_whenLocalCompletionFailsAfterSyncOk() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        String leakySecret = "jdbc://internal-host:5432/secret-schema constraint violation";
        doThrow(new IllegalStateException(leakySecret))
                .when(certificateService)
                .issueRequestedCertificate(certUuid, "cert-data", List.of(), CertificateType.X509);

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageNotContaining(leakySecret);
        // State-divergence rule: no FAILED transition after the connector accepted.
        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        // Divergence recorded to event history; the persisted cause is the safe placeholder, not the leaky text.
        verify(certificateEventHistoryService)
                .addEventHistory(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED),
                        ArgumentMatchers
                                .argThat(msg -> msg.contains("completing local state failed")
                                        && msg.contains("issuance completion failed") && !msg.contains(leakySecret)),
                        ArgumentMatchers.eq(""));
        // Best-effort binding cleanup (step 4) is skipped because completing local state threw.
        verify(certificateRegistrationWriter, never()).clear(ArgumentMatchers.any());
    }

    @Test
    void leavesTheCertificateClaimedForReconciliation_whenSyncOkHasAnEmptyBody() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("", List.of(), CertificateType.X509));

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageContaining("reconcile manually");
        verify(certificateService, never())
                .issueRequestedCertificate(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(),
                        ArgumentMatchers.any());
        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        verify(certificateRegistrationWriter, never()).clear(ArgumentMatchers.any());
        verify(certificateEventHistoryService)
                .addEventHistory(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED),
                        ArgumentMatchers.contains("reconcile manually"), ArgumentMatchers.eq(""));
    }

    // The binding, not the state, is the dispatch discriminator: a placeholder moved to PENDING_APPROVAL still
    // carries its binding, so on approval-close replay it must take the register-bound path, not the v2 client.
    @Test
    void dispatchesToTheRegisterBoundPath_whenAPendingApprovalPlaceholderHasABinding() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        certificate.setState(CertificateState.PENDING_APPROVAL);
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        // when
        issue();

        // then
        verify(adapter)
                .issueRegistered(ArgumentMatchers.eq(certificate), ArgumentMatchers.any(), ArgumentMatchers.any());
        verify(certificateService).issueRequestedCertificate(certUuid, "cert-data", List.of(), CertificateType.X509);
    }

    // A normal PENDING_APPROVAL issue has no binding, so it must NOT route to the register-bound path even on a
    // register-capable authority — proving the binding, not the state, gates dispatch.
    @Test
    void pendingApprovalWithoutBindingDoesNotDispatchToRegisterBoundPath() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        certificate.setState(CertificateState.PENDING_APPROVAL);
        when(certificateRegistrationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.empty());

        // No binding -> register-bound branch skipped -> falls through to the plain path.
        try {
            issue();
        } catch (Exception expectedFromPartiallyStubbedPlainPath) {
            // ignored — see above
        }

        verify(adapter, never())
                .issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        verify(certificateRegistrationRepository, never()).findAndLockByCertificateUuid(ArgumentMatchers.any());
    }

    @Test
    void stampsClaim_whenClaimingTheRegisteredPlaceholder() throws Exception {
        // given — the mocked state machine records the stamp the placeholder carries at the moment it is claimed
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        AtomicReference<OffsetDateTime> stampAtClaim = new AtomicReference<>();
        Mockito.doAnswer(inv -> {
            stampAtClaim.set(inv.<Certificate>getArgument(0).getPendingIssueClaimedAt());
            return null;
        })
                .when(stateMachine)
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.PENDING_ISSUE),
                        ArgumentMatchers.any(), ArgumentMatchers.anyString());

        // when
        issue();

        // then
        assertThat(stampAtClaim.get()).isNotNull();
    }

    @Test
    void clearsClaim_whenAuthorityAcceptsAsynchronously() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));

        // when
        issue();

        // then
        assertClaimCleared();
    }

    @Test
    void clearsClaim_whenConnectorAcceptsButALocalAdapterStepFails() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorAcceptedButLocalFailureException("accepted upstream, local step failed",
                        new RuntimeException("boom")));

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        assertClaimCleared();
    }

    @Test
    void clearsClaim_whenCompletingTheIssuedCertificateFails() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        doThrow(new IllegalStateException("persist failed"))
                .when(certificateService)
                .issueRequestedCertificate(certUuid, "cert-data", List.of(), CertificateType.X509);

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        assertClaimCleared();
    }

    @Test
    void clearsClaim_whenSyncResultHasAnEmptyBody() throws Exception {
        // given
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("", List.of(), CertificateType.X509));

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        assertClaimCleared();
    }

    @Test
    void leavesClaimToTheStateMachine_whenConnectorRejectsTheRequest() throws Exception {
        // given — the exit to FAILED goes through the state machine, which clears the stamp itself
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorException("upstream refused"));
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED)))
                .thenReturn(true);

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        verify(claimWriter, never()).clear(ArgumentMatchers.any());
    }

    @Test
    void writesNoReconcileEntry_whenRaisingTheEventFailsAfterIssue() throws Exception {
        // given — the placeholder is issued and recorded; only the action event after it fails (broker down)
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        IllegalStateException brokerDown = new IllegalStateException("broker down");
        doThrow(brokerDown).when(eventProducer).produceMessage(ArgumentMatchers.any());

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isSameAs(brokerDown);
        verify(certificateEventHistoryService, never())
                .addEventHistory(ArgumentMatchers.any(), ArgumentMatchers.any(),
                        ArgumentMatchers.eq(CertificateEventStatus.FAILED), ArgumentMatchers.anyString(),
                        ArgumentMatchers.anyString());
        verify(claimWriter, never()).clear(ArgumentMatchers.any());
    }

    @Test
    void leavesTheRegistrationUnclaimed_whenItHasNoCertificateRequest() {
        // given — a completion undone after its issue failed to queue, though the issue may have reached the broker
        RegisterCapability adapter = registerCapableAdapter();
        certificate.setCertificateRequest(null);

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.PENDING_ISSUE),
                        ArgumentMatchers.any(), ArgumentMatchers.any());
        Mockito.verifyNoInteractions(adapter);
    }

    @Test
    void leavesTheRegistrationUnclaimed_whenAnotherCompletionAttachedItsRequestSinceTheIssueReadIt() {
        // given — this issue read the registration without a request, and a later completion attached one before the
        // lock
        RegisterCapability adapter = registerCapableAdapter();
        X509CertificateEntity readWithoutRequest = aCertificate().build();
        readWithoutRequest.setUuid(certUuid);
        readWithoutRequest.setState(CertificateState.REGISTERED);
        readWithoutRequest.setRaProfile(raProfile);
        readWithoutRequest.setSubjectDn(certificate.getSubjectDn());
        when(certificateRepository.findWithAuthorityAssociationsByUuid(certUuid))
                .thenReturn(Optional.of(readWithoutRequest));
        certificate.setCertificateRequestUuid(UUID.randomUUID());

        // when
        ThrowingCallable issue = this::issue;

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.PENDING_ISSUE),
                        ArgumentMatchers.any(), ArgumentMatchers.any());
        Mockito.verifyNoInteractions(adapter);
    }

    @Test
    void leavesTheRegistrationUnclaimed_whenItHoldsAnotherRequestThanItsIssueWasQueuedFor() {
        // given — the issue was queued for a completion that was undone before another completion attached its request
        RegisterCapability adapter = registerCapableAdapter();
        certificate.setCertificateRequestUuid(UUID.randomUUID());
        UUID undoneRequestUuid = UUID.randomUUID();

        // when
        ThrowingCallable issue = () -> service.issueCertificateAction(certUuid, undoneRequestUuid, true);

        // then
        assertThatThrownBy(issue).isInstanceOf(CertificateOperationException.class);
        verify(stateMachine, never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.PENDING_ISSUE),
                        ArgumentMatchers.any(), ArgumentMatchers.any());
        Mockito.verifyNoInteractions(adapter);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubRegisterBoundIssueFailingWith(ConnectorException failure) throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(failure);
        when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED)))
                .thenReturn(true);
        when(certificateRepository.findAndLockWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));
    }

    private static ListAppender<ILoggingEvent> captureServiceLogs() {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        ((Logger) LoggerFactory.getLogger(ClientOperationServiceImpl.class)).addAppender(appender);
        return appender;
    }

    private static List<String> collectLoggedText(ListAppender<ILoggingEvent> logged) {
        return logged.list
                .stream()
                .map(event -> event.getFormattedMessage() + (event.getThrowableProxy() == null
                        ? ""
                        : ThrowableProxyUtil.asString(event.getThrowableProxy())))
                .toList();
    }

    private static MetadataAttribute caHandle(String name, String value) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(value)));
        return attribute;
    }

    /** The claim was cleared both in the database and on the instance the caller holds. */
    private void assertClaimCleared() {
        verify(claimWriter).clear(certUuid);
        assertThat(certificate.getPendingIssueClaimedAt()).isNull();
    }
}
