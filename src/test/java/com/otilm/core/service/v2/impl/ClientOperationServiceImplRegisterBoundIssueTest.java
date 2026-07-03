package com.otilm.core.service.v2.impl;

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
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistration;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRegistrationRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateService;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.RegisterCapability;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.writer.registration.CertificateRegistrationWriter;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import com.otilm.core.attribute.engine.AttributeEngine;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit coverage for the register-bound issuance branch: a placeholder carrying a registration binding issues its
 * attached CSR through {@link RegisterCapability#issueRegistered} rather than the v2 client. Wires
 * {@link ClientOperationServiceImpl} directly via setters (no Spring context) so each collaborator can be asserted.
 */
class ClientOperationServiceImplRegisterBoundIssueTest {

    private ClientOperationServiceImpl service;

    private CertificateRepository certificateRepository;
    private CertificateRegistrationRepository certificateRegistrationRepository;
    private CertificateRegistrationWriter certificateRegistrationWriter;
    private AuthorityProviderAdapterFactory adapterFactory;
    private ConnectorCapabilityService capabilityService;
    private CertificateService certificateService;
    private PlatformTransactionManager transactionManager;
    private CertificateStateMachine stateMachine;
    private AttributeEngine attributeEngine;
    private CertificateEventHistoryInternalService certificateEventHistoryService;
    private CertificateStatusPollWriter pollWriter;
    private CertificateRelationRepository certificateRelationRepository;
    private EventProducer eventProducer;

    private RaProfile raProfile;
    private AuthorityInstanceReference authority;
    private UUID certUuid;
    private Certificate certificate;
    private CertificateRegistration binding;

    private static Map<String, OidRecord> savedRdnCache;

    // RegisterWireBuilder.buildIdentityContent renders the subject DN via PlatformX500NameStyle, whose static
    // initializer reads the global RDN OID cache — seed it the same way RegisterWireBuilderTest does so the
    // identity-override tests don't depend on the (unrelated) Spring context that normally populates it.
    @BeforeAll
    static void seedRdnOidCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);

        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                OidRecord.builder().displayName("Common Name").code("CN").build());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.10",
                OidRecord.builder().displayName("Organization").code("O").build());
    }

    @AfterAll
    static void restoreRdnOidCache() {
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    @BeforeEach
    void setUp() throws Exception {
        certificateRepository = Mockito.mock(CertificateRepository.class);
        certificateRegistrationRepository = Mockito.mock(CertificateRegistrationRepository.class);
        certificateRegistrationWriter = Mockito.mock(CertificateRegistrationWriter.class);
        adapterFactory = Mockito.mock(AuthorityProviderAdapterFactory.class);
        capabilityService = Mockito.mock(ConnectorCapabilityService.class);
        certificateService = Mockito.mock(CertificateService.class);
        transactionManager = Mockito.mock(PlatformTransactionManager.class);
        stateMachine = Mockito.mock(CertificateStateMachine.class);
        attributeEngine = Mockito.mock(AttributeEngine.class);
        certificateEventHistoryService = Mockito.mock(CertificateEventHistoryInternalService.class);
        pollWriter = Mockito.mock(CertificateStatusPollWriter.class);
        certificateRelationRepository = Mockito.mock(CertificateRelationRepository.class);
        eventProducer = Mockito.mock(EventProducer.class);

        service = new ClientOperationServiceImpl();
        service.setCertificateRepository(certificateRepository);
        service.setCertificateRegistrationRepository(certificateRegistrationRepository);
        service.setCertificateRegistrationWriter(certificateRegistrationWriter);
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

        TransactionStatus tx = Mockito.mock(TransactionStatus.class);
        Mockito.when(transactionManager.getTransaction(ArgumentMatchers.any())).thenReturn(tx);

        authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        authority.setConnectorUuid(UUID.randomUUID());

        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);

        CertificateRequestEntity request = new CertificateRequestEntity();
        request.setContent(Base64.getEncoder().encodeToString("csr-content".getBytes()));

        certUuid = UUID.randomUUID();
        certificate = new Certificate();
        certificate.setUuid(certUuid);
        certificate.setState(CertificateState.REGISTERED);
        certificate.setRaProfile(raProfile);
        certificate.setCertificateRequest(request);
        certificate.setSubjectDn("CN=device-1,O=Acme");

        binding = new CertificateRegistration();
        binding.setCertificateUuid(certUuid);

        Mockito.when(certificateRepository.findWithAssociationsByUuid(certUuid)).thenReturn(Optional.of(certificate));
        Mockito.when(certificateRepository.findByUuid(certUuid)).thenReturn(Optional.of(certificate));
        // The dispatch discriminator (non-locking) and the locked read in the register-bound path both resolve the
        // binding by certificate UUID — a pre-registered placeholder has one.
        Mockito.when(certificateRegistrationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.of(binding));
        Mockito.when(certificateRegistrationRepository.findAndLockByCertificateUuid(certUuid)).thenReturn(Optional.of(binding));
        Mockito.when(capabilityService.supports(ArgumentMatchers.any(), ArgumentMatchers.any())).thenReturn(false);
    }

    /** Mocks an adapter that supports the register-bound issue path and wires the factory to return it. */
    private RegisterCapability registerCapableAdapter() {
        AuthorityProviderAdapter adapter = Mockito.mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class, AsyncOperationCapability.class));
        Mockito.when(adapterFactory.forAuthority(ArgumentMatchers.any())).thenReturn(adapter);
        return (RegisterCapability) adapter;
    }

    private void issue() throws Exception {
        service.issueCertificateAction(certUuid, true);
    }

    @Test
    void registeredPlaceholderOnRegisterCapableAuthorityDispatchesToAdapter() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        issue();

        Mockito.verify(adapter).issueRegistered(ArgumentMatchers.eq(certificate), ArgumentMatchers.any(), ArgumentMatchers.any());
        Mockito.verify(certificateService).issueRequestedCertificate(certUuid, "cert-data", List.of());
    }

    @Test
    void registeredPlaceholderOnNonRegisterCapableAuthorityFallsThroughToV2Path() {
        AuthorityProviderAdapter plainAdapter = Mockito.mock(AuthorityProviderAdapter.class);
        Mockito.when(adapterFactory.forAuthority(ArgumentMatchers.any())).thenReturn(plainAdapter);

        // The register-bound branch is the only code that touches the registration repository, so the
        // verifyNoInteractions below is the load-bearing assertion that the branch was NOT taken. The v2
        // fall-through is unmocked and fails downstream; absorb that (it is not what this test asserts) so the
        // test pins dispatch rather than the fall-through's happens-to-throw behaviour.
        try {
            issue();
        } catch (Exception expectedFromUnmockedV2Path) {
            // ignored — see above
        }

        Mockito.verifyNoInteractions(certificateRegistrationRepository);
    }

    @Test
    void missingRegistrationBindingIsRejectedAndRollsBackTransaction() {
        RegisterCapability adapter = registerCapableAdapter();
        Mockito.when(certificateRegistrationRepository.findAndLockByCertificateUuid(certUuid)).thenReturn(Optional.empty());
        TransactionStatus tx = Mockito.mock(TransactionStatus.class);
        Mockito.when(transactionManager.getTransaction(ArgumentMatchers.any())).thenReturn(tx);

        assertThatThrownBy(this::issue).isInstanceOf(CertificateOperationException.class);

        Mockito.verifyNoInteractions(adapter);
        Mockito.verify(transactionManager).rollback(tx);
        Mockito.verify(transactionManager, Mockito.never()).commit(ArgumentMatchers.any());
    }

    @Test
    void racedStateIsRejectedWithoutConnectorCall() {
        RegisterCapability adapter = registerCapableAdapter();
        Certificate racedRead = new Certificate();
        racedRead.setState(CertificateState.FAILED);
        Mockito.when(certificateRepository.findByUuid(certUuid)).thenReturn(Optional.of(racedRead));

        assertThatThrownBy(this::issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageContaining("raced");

        Mockito.verifyNoInteractions(adapter);
    }

    @Test
    void identityOverrideGateControlsWhetherRequestContentIsBuilt() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        Mockito.when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_IDENTITY_OVERRIDE)).thenReturn(true);
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        issue();

        Mockito.verify(adapter).issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.isNotNull());
    }

    @Test
    void identityOverrideGateOffPassesNullRequestContent() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        // capabilityService.supports defaults to false in setUp().
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        issue();

        Mockito.verify(adapter).issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.isNull());
    }

    @Test
    void syncOkCompletesIssuanceAndClearsBinding() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        List<MetadataAttribute> meta = List.of(caHandle("endEntityName", "device-1"));
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", meta, CertificateType.X509));

        issue();

        Mockito.verify(certificateService).issueRequestedCertificate(certUuid, "cert-data", meta);
        Mockito.verify(certificateRegistrationWriter).clear(certUuid);
    }

    @Test
    void asyncAcceptedTransitionsToPendingIssueAndSchedulesPollExactlyOnce() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of()));

        // transitionToPendingIssue's internal scheduleStatusPoll reloads the certificate with the polling
        // graph and re-resolves the adapter to evaluate pollability.
        Mockito.when(certificateRepository.findForPollingByUuid(certUuid)).thenReturn(Optional.of(certificate));
        Mockito.when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_STATUS_POLLING)).thenReturn(true);

        issue();

        Mockito.verify(stateMachine).transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.PENDING_ISSUE),
                ArgumentMatchers.any(), ArgumentMatchers.any());
        Mockito.verify(pollWriter, Mockito.times(1))
                .schedule(ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateOperation.ISSUE), ArgumentMatchers.any());
        Mockito.verify(certificateRegistrationWriter).clear(certUuid);
        Mockito.verify(certificateService, Mockito.never()).issueRequestedCertificate(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void connectorAcceptedButLocalFailureDoesNotFailTheCertificate() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorAcceptedButLocalFailureException("accepted upstream, local step failed", new RuntimeException("boom")));

        assertThatThrownBy(this::issue).isInstanceOf(CertificateOperationException.class);

        Mockito.verify(stateMachine, Mockito.never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        // The audit message names the actual entry-state label (here "Registered"), not a hardcoded state, so a
        // PENDING_APPROVAL placeholder taking this same branch would be reported correctly.
        Mockito.verify(certificateEventHistoryService).addEventHistory(
                ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.eq(CertificateEventStatus.FAILED),
                ArgumentMatchers.contains("left " + CertificateState.REGISTERED.getLabel() + " for reconciliation"), ArgumentMatchers.eq(""));
    }

    @Test
    void preAcceptanceConnectorFailureFailsTheCertificate() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorException("upstream refused"));
        Mockito.when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED))).thenReturn(true);

        assertThatThrownBy(this::issue).isInstanceOf(CertificateOperationException.class);

        // handleFailedOrRejectedEvent delegates the FAILED transition and its audit-history write to the (mocked)
        // state machine, so verifying this call is the unit-level proxy for "the certificate was failed".
        Mockito.verify(stateMachine).transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void nonDomainExceptionMessageIsNotForwardedToTheCaller() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        String leakySecret = "jdbc://internal-host:5432/secret-schema constraint violation";
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new IllegalStateException(leakySecret));
        Mockito.when(stateMachine.canTransition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED))).thenReturn(true);

        assertThatThrownBy(this::issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageNotContaining(leakySecret);

        // The audit message handed to the state machine (and therefore to the persisted event history) is
        // the safe placeholder, not the raw IllegalStateException message.
        Mockito.verify(stateMachine).transition(ArgumentMatchers.eq(certificate), ArgumentMatchers.eq(CertificateState.FAILED),
                ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.eq("register-bound issuance failed"), ArgumentMatchers.any());
    }

    // The state-divergence-critical branch the feature exists to protect: connector accepted (SYNC_OK) but local
    // completion throws, so the certificate must NOT be rolled back to FAILED and the binding must be left in place
    // for reconciliation.
    @Test
    void syncOkButLocalCompletionFailureDoesNotFailTheCertificate() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));
        String leakySecret = "jdbc://internal-host:5432/secret-schema constraint violation";
        Mockito.doThrow(new IllegalStateException(leakySecret))
                .when(certificateService).issueRequestedCertificate(certUuid, "cert-data", List.of());

        assertThatThrownBy(this::issue)
                .isInstanceOf(CertificateOperationException.class)
                .hasMessageNotContaining(leakySecret);

        // State-divergence rule: no FAILED transition after the connector accepted.
        Mockito.verify(stateMachine, Mockito.never())
                .transition(ArgumentMatchers.any(), ArgumentMatchers.eq(CertificateState.FAILED),
                        ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
        // Divergence recorded to event history; the persisted cause is the safe placeholder, not the leaky text.
        Mockito.verify(certificateEventHistoryService).addEventHistory(
                ArgumentMatchers.eq(certUuid), ArgumentMatchers.eq(CertificateEvent.ISSUE), ArgumentMatchers.eq(CertificateEventStatus.FAILED),
                ArgumentMatchers.argThat(msg -> msg.contains("completing local state failed")
                        && msg.contains("register-bound issuance failed")
                        && !msg.contains(leakySecret)),
                ArgumentMatchers.eq(""));
        // Best-effort binding cleanup (step 4) is skipped because completing local state threw.
        Mockito.verify(certificateRegistrationWriter, Mockito.never()).clear(ArgumentMatchers.any());
    }

    // The binding, not the state, is the dispatch discriminator: a placeholder moved to PENDING_APPROVAL still
    // carries its binding, so on approval-close replay it must take the register-bound path, not the v2 client.
    @Test
    void pendingApprovalPlaceholderWithBindingDispatchesToRegisterBoundPath() throws Exception {
        RegisterCapability adapter = registerCapableAdapter();
        certificate.setState(CertificateState.PENDING_APPROVAL);
        Mockito.when(adapter.issueRegistered(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenReturn(AdapterOperationResult.syncOk("cert-data", List.of(), CertificateType.X509));

        issue();

        Mockito.verify(adapter).issueRegistered(ArgumentMatchers.eq(certificate), ArgumentMatchers.any(), ArgumentMatchers.any());
        Mockito.verify(certificateService).issueRequestedCertificate(certUuid, "cert-data", List.of());
    }

    // A normal PENDING_APPROVAL issue has no binding, so it must NOT route to the register-bound path even on a
    // register-capable authority — proving the binding, not the state, gates dispatch.
    @Test
    void pendingApprovalWithoutBindingDoesNotDispatchToRegisterBoundPath() {
        RegisterCapability adapter = registerCapableAdapter();
        certificate.setState(CertificateState.PENDING_APPROVAL);
        Mockito.when(certificateRegistrationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.empty());

        // No binding -> register-bound branch skipped -> falls through to the (unmocked) v2 path. Absorb its
        // downstream failure; this test pins that dispatch skipped the register-bound path, not the v2 throw.
        try {
            issue();
        } catch (Exception expectedFromUnmockedV2Path) {
            // ignored — see above
        }

        Mockito.verifyNoInteractions(adapter);
        Mockito.verify(certificateRegistrationRepository, Mockito.never()).findAndLockByCertificateUuid(ArgumentMatchers.any());
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
}
