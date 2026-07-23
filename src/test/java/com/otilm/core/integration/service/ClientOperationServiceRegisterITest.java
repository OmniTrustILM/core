package com.otilm.core.integration.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.SanMappedField;
import com.otilm.api.model.connector.v3.certificate.CertificateExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.v2.AvailableOperationsDto;
import com.otilm.api.model.core.v2.CertificateOperationKind;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.OperationSupport;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.certificate.request.IssuanceDefinitionResolver;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.CertificateRegistration;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.service.writer.registration.CertificateRegistrationAuthorizationWriter;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRegistrationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.RegisterCapability;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.service.writer.registration.CertificateRegistrationWriter;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Service-level coverage for the v3 register flow. The authority adapter is mocked so the test drives
 * each branch (sync 200 / async 202 / connector failure / unsupported authority) and asserts the
 * orchestration the service owns — placeholder creation, state-machine transitions and poll scheduling.
 * The real adapter + v3 wire contract are covered by {@code AuthorityProviderV3AdapterTest}; the full
 * connector round-trip is deferred to the v3 integration suite.
 */
@SpringBootTest
class ClientOperationServiceRegisterITest extends BaseSpringBootTest {

    @Autowired
    private ClientOperationExternalService clientOperationService;
    @Autowired
    private ClientOperationInternalService clientOperationInternalService;
    @Autowired
    private CertificateInternalService certificateService;
    @Autowired
    private CertificateExternalService certificateExternalService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private CertificateRegistrationRepository registrationRepository;
    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizationRepository;
    @Autowired
    private CertificateRegistrationAuthorizationWriter registrationAuthorizationWriter;
    @Autowired
    private SettingsCache settingsCache;
    @Autowired
    private SettingExternalService settingService;
    // Spied so most tests use real encryption/verification while one test stubs store() to drive the
    // local-authorization-failure arc.
    @MockitoSpyBean
    private RegistrationChallengeStore registrationChallengeStore;
    // Spied (not mocked) so the binding really persists; individual tests stub failures to drive the
    // post-acceptance divergence branch.
    @MockitoSpyBean
    private CertificateRegistrationWriter registrationWriter;
    @MockitoBean
    private AuthorityProviderAdapterFactory adapterFactory;

    // Mocked so the test verifies that an async registration schedules a REGISTER poll, without
    // depending on the poll row surviving the background sweep/listener (covered by the v3 integration suite).
    @MockitoBean
    private CertificateStatusPollWriter pollWriter;

    // Mocked so issue enqueue is a deterministic no-op (no async action processing during the test).
    @MockitoBean
    private ActionProducer actionProducer;

    // Mocked so the Certificate Registered event fire is a verifiable no-op (no JMS during the test).
    @MockitoBean
    private EventProducer eventProducer;

    // The service-layer capability gate (layer 2). Mocked here so each test controls advertisement
    // directly; the real flag-resolution logic is covered by ConnectorCapabilityServiceTest.
    @MockitoBean
    private ConnectorCapabilityService capabilityService;

    // Mocked so registerPersistsConnectorMetadata can verify the metadata write rather than relying on the
    // real engine (whose failure persistRegistrationMeta swallows). Only that test passes a non-empty meta,
    // so the other register tests are unaffected.
    @MockitoBean
    private AttributeEngine attributeEngine;

    // Mocked so the structured-register test supplies canned issuance definitions without a connector round-trip;
    // the flat register tests never call resolve(), so the default no-op mock is inert for them.
    @MockitoBean
    private IssuanceDefinitionResolver issuanceDefinitionResolver;

    @Autowired
    private GroupRepository groupRepository;

    // The generic association service is the real bean, so setOwner/setGroups actually persist against the
    // placeholder; getOwner/getGroupUuids are then used to assert what registration stored.
    @Autowired
    private ResourceObjectAssociationService objectAssociationService;

    // Mocked so an explicit owner UUID resolves to a username without a live auth service (setOwner resolves the
    // owner's username through this client). The default-owner path uses the logged profile and never calls it.
    @MockitoBean
    private UserManagementApiClient userManagementApiClient;

    private RaProfile raProfile;
    // Pre-computed secured UUIDs so each assertThrows lambda contains only the call under test.
    private SecuredParentUUID authorityParent;
    private SecuredUUID securedRaProfile;

    @BeforeEach
    void setUpRegistrationFixtures() {
        Connector connector = new Connector();
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setAuthorityInstanceUuid("1");
        authority.setConnector(connector);
        authority = authorityInstanceReferenceRepository.save(authority);

        raProfile = new RaProfile();
        raProfile.setName("registerRaProfile");
        raProfile.setAuthorityInstanceReference(authority);
        raProfile.setAuthorityInstanceReferenceUuid(authority.getUuid());
        raProfile.setEnabled(true);
        raProfile = raProfileRepository.save(raProfile);
        authorityParent = SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid());
        securedRaProfile = raProfile.getSecuredUuid();

        // Default: the authority advertises every flag, so capability-gated paths run. The gating
        // tests below re-stub a specific flag to false to assert the gate is consulted.
        when(capabilityService.supports(Mockito.any(AuthorityInstanceReference.class), Mockito.any()))
                .thenReturn(true);
    }

    private ClientCertificateRegistrationDto registrationRequest() {
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-1,O=Acme");
        return request;
    }

    /** Mocks an adapter that supports registration and makes the factory return it. */
    private RegisterCapability registeringAdapter() {
        // Both capabilities, like the real v3 adapter — so an async-accepted registration actually schedules a poll.
        AuthorityProviderAdapter adapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class, AsyncOperationCapability.class));
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(adapter);
        return (RegisterCapability) adapter;
    }

    private ClientCertificateDataResponseDto register() throws Exception {
        return clientOperationService.registerCertificate(
                authorityParent,
                securedRaProfile,
                registrationRequest());
    }

    @Test
    void syncRegistrationTransitionsToRegistered() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));

        ClientCertificateDataResponseDto response = register();

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
    }

    @Test
    void asyncRegistrationStaysPendingAndSchedulesRegisterPoll() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(null));

        ClientCertificateDataResponseDto response = register();

        UUID certUuid = UUID.fromString(response.getUuid());
        Certificate cert = certificateRepository.findByUuid(certUuid).orElseThrow();
        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, cert.getState());
        verify(pollWriter).schedule(Mockito.eq(certUuid), Mockito.eq(CertificateOperation.REGISTER), Mockito.any());
    }

    @Test
    void unsupportedAuthorityCreatesPlatformLevelRegistration() throws Exception {
        // Adapter without RegisterCapability — i.e. a v2 authority. Pre-registration is still supported at the
        // platform level: the placeholder is created and reaches REGISTERED with no connector /register call.
        when(adapterFactory.forAuthority(Mockito.any()))
                .thenReturn(mock(AuthorityProviderAdapter.class));

        ClientCertificateDataResponseDto response = register();

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
        Assertions.assertEquals(1, certificateRepository.count(), "the platform-level placeholder is persisted");
    }

    @Test
    void platformLevelPlaceholderEnqueuesIssueAction() throws Exception {
        // v2 authority: issuing a platform-level placeholder enqueues an ISSUE action. The async selection of the
        // plain vs register-bound path (on RegisterCapability / the binding row) is covered by the issue-dispatch tests.
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        String certUuid = register().getUuid();

        ClientCertificateIssueRequestDto issueRequest = new ClientCertificateIssueRequestDto();
        issueRequest.setRequest(generateCsrBase64());
        clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, certUuid, issueRequest);

        verify(actionProducer).produceMessage(Mockito.argThat(m -> m.getResourceAction() == ResourceAction.ISSUE));
        Assertions.assertEquals(CertificateState.REGISTERED,
                certificateRepository.findByUuid(UUID.fromString(certUuid)).orElseThrow().getState(),
                "the placeholder stays REGISTERED until the async ISSUE action completes");
    }

    @Test
    void platformLevelRegistrationWithSecretCreatesAuthorizationAndFiresEvent() throws Exception {
        // Platform-level path (v2 authority) with a challenge: the authorization row is created ACTIVE and the
        // Certificate Registered event fires, exactly as on the connector-backed path.
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setAuthorizationSecret(CHALLENGE);

        ClientCertificateDataResponseDto response =
                clientOperationService.registerCertificate(authorityParent, securedRaProfile, request);

        UUID certUuid = UUID.fromString(response.getUuid());
        Assertions.assertEquals(CertificateState.REGISTERED,
                certificateRepository.findByUuid(certUuid).orElseThrow().getState());
        CertificateRegistrationAuthorization auth = authorizationRepository.findByCertificateUuid(certUuid).orElseThrow();
        Assertions.assertEquals(RegistrationState.ACTIVE, auth.getState());
        ArgumentCaptor<EventMessage> captor = ArgumentCaptor.forClass(EventMessage.class);
        verify(eventProducer).produceMessage(captor.capture());
        Assertions.assertEquals(ResourceEvent.CERTIFICATE_REGISTERED, captor.getValue().getEvent(),
                "a challenge-protected platform-level pre-registration fires the Certificate Registered event");
    }

    @Test
    void approvalRejectedRestoresPlatformLevelNoSecretPlaceholder() throws Exception {
        // A platform-level pre-registration with NO secret still carries a register->issue binding, so its issuance
        // approval rejection restores it to REGISTERED, symmetric with the connector-backed and secret cases.
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        UUID certUuid = UUID.fromString(
                clientOperationService.registerCertificate(authorityParent, securedRaProfile, registrationRequest()).getUuid());

        clientOperationInternalService.approvalCreatedAction(certUuid);
        clientOperationInternalService.issueCertificateRejectedAction(certUuid);

        Assertions.assertEquals(CertificateState.REGISTERED,
                certificateRepository.findByUuid(certUuid).orElseThrow().getState(),
                "a no-secret platform-level placeholder restores to REGISTERED on approval rejection");
        Assertions.assertEquals(0, authorizationRepository.count(), "a no-secret flow carries no challenge authorization");
    }

    @Test
    void approvalRejectedRestoresPlatformLevelSecretPlaceholder() throws Exception {
        // A platform-level (no binding) secret-protected pre-registration must restore to REGISTERED on approval
        // rejection — identified by its challenge authorization — keeping the authorization ACTIVE for retry, the
        // same as a connector-backed placeholder (which is identified by its binding).
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setAuthorizationSecret(CHALLENGE);
        UUID certUuid = UUID.fromString(
                clientOperationService.registerCertificate(authorityParent, securedRaProfile, request).getUuid());

        clientOperationInternalService.approvalCreatedAction(certUuid);
        Assertions.assertEquals(CertificateState.PENDING_APPROVAL,
                certificateRepository.findByUuid(certUuid).orElseThrow().getState());

        clientOperationInternalService.issueCertificateRejectedAction(certUuid);

        Assertions.assertEquals(CertificateState.REGISTERED,
                certificateRepository.findByUuid(certUuid).orElseThrow().getState(),
                "a platform-level secret placeholder restores to REGISTERED on approval rejection");
        Assertions.assertEquals(RegistrationState.ACTIVE,
                authorizationRepository.findByCertificateUuid(certUuid).orElseThrow().getState(),
                "its challenge authorization stays ACTIVE for retry");
    }

    @Test
    void platformLevelRegistrationStoreFailureFailsPlaceholder() {
        // Platform-level path (v2 authority): a challenge-store failure must fail the placeholder (FAILED, not left
        // in PENDING_REGISTRATION) and leave no authorization, mirroring connectorFailureLeavesPlaceholderFailed.
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        doThrow(new IllegalStateException("challenge encryption failed"))
                .when(registrationChallengeStore).store(Mockito.any(), Mockito.any());
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setAuthorizationSecret(CHALLENGE);

        Assertions.assertThrows(IllegalStateException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));

        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertEquals(1, certs.size(), "the placeholder is created, then failed (positively covering the catch)");
        Assertions.assertEquals(CertificateState.FAILED, certs.get(0).getState(),
                "a store failure fails the platform-level placeholder");
        Assertions.assertEquals(0, authorizationRepository.count(), "a store failure persists no authorization");
    }

    @Test
    void connectorFailureLeavesPlaceholderFailed() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenThrow(new ConnectorException("upstream refused"));

        Assertions.assertThrows(ConnectorException.class, this::register);

        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertEquals(1, certs.size());
        Assertions.assertEquals(CertificateState.FAILED, certs.get(0).getState());
    }

    @Test
    void registerRuntimeFailureLeavesPlaceholderFailed() throws Exception {
        // A raw RuntimeException from register() is pre-acceptance per the RegisterCapability contract, so
        // the placeholder must be FAILED — not orphaned in PENDING_REGISTRATION with no transition.
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenThrow(new IllegalStateException("pre-acceptance failure"));

        Assertions.assertThrows(IllegalStateException.class, this::register);

        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertEquals(1, certs.size());
        Assertions.assertEquals(CertificateState.FAILED, certs.get(0).getState());
    }

    @Test
    void listAvailableOperationsForV2AuthorityExcludesRegisterAndAsync() throws Exception {
        when(adapterFactory.forAuthority(Mockito.any()))
                .thenReturn(mock(AuthorityProviderAdapter.class)); // v2: neither register nor async

        AvailableOperationsDto ops = listOperations();

        Assertions.assertFalse(operation(ops, CertificateOperationKind.REGISTER).isSupported());
        OperationSupport issue = operation(ops, CertificateOperationKind.ISSUE);
        Assertions.assertTrue(issue.isSupported());
        Assertions.assertFalse(issue.isAsyncSupported());
        Assertions.assertFalse(issue.isCancelSupported());
    }

    @Test
    void listAvailableOperationsForV3AuthoritySupportsRegisterAndAsync() throws Exception {
        AuthorityProviderAdapter adapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class, AsyncOperationCapability.class));
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(adapter);

        OperationSupport register = operation(listOperations(), CertificateOperationKind.REGISTER);
        Assertions.assertTrue(register.isSupported());
        Assertions.assertTrue(register.isAsyncSupported());
        // Register cancel is not advertised — cancelling a PENDING_REGISTRATION cert is not implemented
        // (determineCancelTarget handles only PENDING_ISSUE / PENDING_REVOKE).
        Assertions.assertFalse(register.isCancelSupported());
    }

    @Test
    void registrationWithoutAdvertisedCapabilityCreatesPlatformLevelRegistration() throws Exception {
        // Adapter implements RegisterCapability but the authority does not advertise CERTIFICATE_REGISTRATION.
        // Pre-registration falls back to the platform level: REGISTERED with no connector /register call.
        RegisterCapability adapter = registeringAdapter();
        when(capabilityService.supports(
                        Mockito.any(AuthorityInstanceReference.class), Mockito.eq(FeatureFlag.CERTIFICATE_REGISTRATION)))
                .thenReturn(false);

        ClientCertificateDataResponseDto response = register();

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
        Assertions.assertEquals(1, certificateRepository.count());
        verify(adapter, never()).register(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void asyncRegistrationSkipsPollWhenStatusPollingNotAdvertised() throws Exception {
        // Registration is advertised (proceeds), but status polling is not — the cert is left PENDING
        // with no poll scheduled (manual / out-of-band completion).
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(null));
        when(capabilityService.supports(
                        Mockito.any(AuthorityInstanceReference.class), Mockito.eq(FeatureFlag.CERTIFICATE_STATUS_POLLING)))
                .thenReturn(false);

        ClientCertificateDataResponseDto response = register();

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, cert.getState());
        verify(pollWriter, never()).schedule(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void listAvailableOperationsGatesRegisterAndAsyncOnAdvertisedFlags() throws Exception {
        // Adapter implements both capabilities (layer 1 passes for both), but neither flag is advertised
        // — listAvailableOperations must report REGISTER unsupported and issue async unsupported.
        registeringAdapter();
        when(capabilityService.supports(
                        Mockito.any(AuthorityInstanceReference.class), Mockito.any()))
                .thenReturn(false);

        AvailableOperationsDto ops = listOperations();

        Assertions.assertFalse(operation(ops, CertificateOperationKind.REGISTER).isSupported());
        OperationSupport issue = operation(ops, CertificateOperationKind.ISSUE);
        Assertions.assertTrue(issue.isSupported());
        Assertions.assertFalse(issue.isAsyncSupported());
    }

    private AvailableOperationsDto listOperations() throws Exception {
        return clientOperationService.listAvailableOperations(
                authorityParent,
                securedRaProfile);
    }

    private OperationSupport operation(AvailableOperationsDto dto, CertificateOperationKind kind) {
        return dto.getOperations().stream().filter(o -> o.getOperation() == kind).findFirst().orElseThrow();
    }

    @Test
    void issueRegisteredCertificateWithoutCsrIsRejected() throws Exception {
        String certUuid = registerSyncRegistered();
        ClientCertificateIssueRequestDto noCsr = new ClientCertificateIssueRequestDto(); // request == null

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, noCsr));
    }

    @Test
    void issueRegisteredCertificateWithNullCsrFormatIsRejected() throws Exception {
        // An explicit null format must surface a clear validation error rather than an NPE inside the
        // CSR parser's format-selection logic.
        String certUuid = registerSyncRegistered();
        ClientCertificateIssueRequestDto noFormat = new ClientCertificateIssueRequestDto();
        noFormat.setRequest(generateCsrBase64());
        noFormat.setFormat(null);

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, noFormat));
    }

    @Test
    void issueRequestedCertificateWithSuppliedCsrIsRejected() {
        Certificate requested = new Certificate();
        requested.setState(CertificateState.REQUESTED);
        requested.setRaProfile(raProfile);
        requested = certificateRepository.save(requested);
        String certUuid = requested.getUuid().toString();

        ClientCertificateIssueRequestDto withCsr = new ClientCertificateIssueRequestDto();
        withCsr.setRequest("a-csr-body"); // validation rejects before any parsing

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, withCsr));
    }

    @Test
    void issueRequestedCertificateWithBlankCsrIsNotTreatedAsSuppliedCsr() throws Exception {
        // A blank/whitespace request body must not be read as "a CSR was supplied": a REQUESTED cert
        // carries its own (protocol-attached) CSR, so the issue proceeds rather than being rejected
        // with "already has a signing request".
        Certificate requested = new Certificate();
        requested.setState(CertificateState.REQUESTED);
        requested.setRaProfile(raProfile);
        requested = certificateRepository.save(requested);
        String certUuid = requested.getUuid().toString();

        ClientCertificateIssueRequestDto blank = new ClientCertificateIssueRequestDto();
        blank.setRequest("   ");

        clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, certUuid, blank);

        verify(actionProducer).produceMessage(Mockito.argThat(m -> m.getResourceAction() == ResourceAction.ISSUE));
    }

    @Test
    void issueRegisteredCertificateAttachesOperatorCsr() throws Exception {
        String certUuid = registerSyncRegistered();
        ClientCertificateIssueRequestDto issueRequest = new ClientCertificateIssueRequestDto();
        issueRequest.setRequest(generateCsrBase64());

        clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, issueRequest);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(certUuid)).orElseThrow();
        Assertions.assertNotNull(cert.getCertificateRequest(), "operator CSR should be attached to the registered placeholder");
        verify(actionProducer).produceMessage(Mockito.argThat(m -> m.getResourceAction() == ResourceAction.ISSUE));
    }

    @Test
    void issuingTwoRegisteredCertsWithTheSameCsrSharesOneCertificateRequest() throws Exception {
        // Get-or-create by fingerprint: an identical CSR attached to two registered placeholders must be
        // shared, not duplicated (matching the canonical CSR-attach path).
        String csr = generateCsrBase64();
        UUID first = UUID.fromString(registerSyncRegistered());
        UUID second = UUID.fromString(registerSyncRegistered());

        ClientCertificateIssueRequestDto req1 = new ClientCertificateIssueRequestDto();
        req1.setRequest(csr);
        clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, first.toString(), req1);
        ClientCertificateIssueRequestDto req2 = new ClientCertificateIssueRequestDto();
        req2.setRequest(csr);
        clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, second.toString(), req2);

        UUID firstReq = certificateRepository.findByUuid(first).orElseThrow().getCertificateRequestUuid();
        UUID secondReq = certificateRepository.findByUuid(second).orElseThrow().getCertificateRequestUuid();
        Assertions.assertNotNull(firstReq);
        Assertions.assertEquals(firstReq, secondReq, "an identical CSR must be shared across registered placeholders, not duplicated");
    }

    @Test
    void addCertificateRequestToExistingRejectsNonRegisteredCertificate() throws Exception {
        // Defense-in-depth: the public attach method must refuse a non-REGISTERED certificate.
        Certificate requested = new Certificate();
        requested.setState(CertificateState.REQUESTED);
        requested.setRaProfile(raProfile);
        requested = certificateRepository.save(requested);
        UUID uuid = requested.getUuid();
        ClientCertificateIssueRequestDto req = new ClientCertificateIssueRequestDto();
        req.setRequest(generateCsrBase64());

        Assertions.assertThrows(ValidationException.class, () -> certificateService.addCertificateRequestToExisting(uuid, req));
    }

    @Test
    void approvalCreatedTransitionsRegisteredCertToPendingApproval() throws Exception {
        // A registered placeholder issued under an issue-approval profile must enter PENDING_APPROVAL.
        UUID certUuid = UUID.fromString(registerSyncRegistered());
        clientOperationInternalService.approvalCreatedAction(certUuid);
        Certificate cert = certificateRepository.findByUuid(certUuid).orElseThrow();
        Assertions.assertEquals(CertificateState.PENDING_APPROVAL, cert.getState());
    }

    @Test
    void registerWithNullRequestIsRejected() {
        // A missing registration body must surface a controlled ValidationException, not an NPE.
        Assertions.assertThrows(ValidationException.class,
                () -> clientOperationService.registerCertificate(authorityParent, securedRaProfile, null));
    }

    @Test
    void registerStaysPendingWhenConnectorAcceptedButLocalFailureRaised() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenThrow(new ConnectorAcceptedButLocalFailureException("accepted upstream, local step failed", new RuntimeException("boom")));

        Assertions.assertThrows(ConnectorAcceptedButLocalFailureException.class, this::register);

        // State-divergence rule: the upstream registration was accepted, so the placeholder must NOT be rolled
        // back to FAILED — it stays PENDING_REGISTRATION for the poll or operator to reconcile.
        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertEquals(1, certs.size());
        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, certs.get(0).getState());
    }

    @Test
    void sanOnlyRegistrationReachesRegistered() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectAltName("DNS:device-1.example.com"); // subject carried entirely in the SAN, no subjectDn

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent,
                securedRaProfile, request);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
    }

    @Test
    void issueExistingCertificateRejectsCertFromDifferentRaProfile() throws Exception {
        String certUuid = registerSyncRegistered(); // REGISTERED under raProfile

        RaProfile otherRaProfile = new RaProfile();
        otherRaProfile.setName("otherRaProfile");
        otherRaProfile.setAuthorityInstanceReferenceUuid(raProfile.getAuthorityInstanceReferenceUuid());
        otherRaProfile.setEnabled(true);
        otherRaProfile = raProfileRepository.save(otherRaProfile);

        ClientCertificateIssueRequestDto issueRequest = new ClientCertificateIssueRequestDto();
        issueRequest.setRequest("ignored-rejected-before-parse");
        SecuredParentUUID otherAuthority = SecuredParentUUID.fromUUID(otherRaProfile.getAuthorityInstanceReferenceUuid());
        SecuredUUID otherRa = otherRaProfile.getSecuredUuid();
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                otherAuthority, otherRa, certUuid, issueRequest));
    }

    @Test
    void asyncRegistrationWithoutAsyncCapabilityDoesNotSchedulePoll() throws Exception {
        // Register-capable but NOT async-capable adapter that nonetheless returns async-accepted.
        AuthorityProviderAdapter adapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class));
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(adapter);
        when(((RegisterCapability) adapter).register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(null));

        ClientCertificateDataResponseDto response = register();

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, cert.getState());
        verify(pollWriter, never()).schedule(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void registerRejectsRaProfileNotUnderRequestedAuthority() {
        SecuredParentUUID wrongAuthority = SecuredParentUUID.fromUUID(UUID.randomUUID());
        ClientCertificateRegistrationDto request = registrationRequest();
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.registerCertificate(
                wrongAuthority, securedRaProfile, request));
    }

    @Test
    void registerRejectsDisabledRaProfile() {
        raProfile.setEnabled(false);
        raProfileRepository.save(raProfile);
        ClientCertificateRegistrationDto request = registrationRequest();
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));
    }

    @Test
    void issueRegisteredCertificateRejectsMalformedCsr() throws Exception {
        String certUuid = registerSyncRegistered();
        ClientCertificateIssueRequestDto issueRequest = new ClientCertificateIssueRequestDto();
        issueRequest.setRequest("!!!not-valid-base64!!!");
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, issueRequest));
    }

    @Test
    void registerPersistsConnectorMetadata() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, List.of(caHandle("endEntityName", "device-1")), CertificateType.X509));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent,
                securedRaProfile, registrationRequest());

        // The connector metadata is actually handed to the attribute engine (not merely tolerated), and
        // registration completes.
        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
        verify(attributeEngine).updateMetadataAttributes(Mockito.anyList(), Mockito.any());
    }

    @Test
    void registerValidatesAndPersistsCustomAttributes() throws Exception {
        // Custom attributes on the registration request must be validated up front and actually persisted
        // against the placeholder, the same as the submit/issue flow — not silently dropped.
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        ClientCertificateRegistrationDto request = registrationRequest();
        List<RequestAttribute> customAttributes = List.of(mock(RequestAttribute.class));
        request.setCustomAttributes(customAttributes);

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        UUID certUuid = UUID.fromString(response.getUuid());
        verify(attributeEngine).validateCustomAttributesContent(Resource.CERTIFICATE, customAttributes);
        verify(attributeEngine).updateObjectCustomAttributesContent(Resource.CERTIFICATE, certUuid, customAttributes);
    }

    @Test
    void connectorBackedCustomAttributePersistenceFailureFailsPlaceholder() throws Exception {
        // A custom-attribute persistence failure happens before the connector call (no upstream work in
        // flight), so it must fail the placeholder — not leave it orphaned attribute-less in PENDING_REGISTRATION.
        RegisterCapability adapter = registeringAdapter();
        doThrow(new AttributeException("content item is not part of predefined list")).when(attributeEngine)
                .updateObjectCustomAttributesContent(Mockito.eq(Resource.CERTIFICATE), Mockito.any(), Mockito.any());
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setCustomAttributes(List.of(mock(RequestAttribute.class)));

        Assertions.assertThrows(AttributeException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));

        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertEquals(1, certs.size());
        Assertions.assertEquals(CertificateState.FAILED, certs.get(0).getState(),
                "a custom-attribute persistence failure must fail the placeholder, not leave it PENDING_REGISTRATION");
        verify(adapter, never()).register(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void platformLevelCustomAttributePersistenceFailureFailsPlaceholder() throws Exception {
        // Same failure-handling contract on the platform-level (non-connector-backed) registration path.
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        doThrow(new AttributeException("content item is not part of predefined list")).when(attributeEngine)
                .updateObjectCustomAttributesContent(Mockito.eq(Resource.CERTIFICATE), Mockito.any(), Mockito.any());
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setCustomAttributes(List.of(mock(RequestAttribute.class)));

        Assertions.assertThrows(AttributeException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));

        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertEquals(1, certs.size());
        Assertions.assertEquals(CertificateState.FAILED, certs.get(0).getState(),
                "a custom-attribute persistence failure must fail the platform-level placeholder too");
    }

    /** Swaps the default test-user authentication for a protocol-user one, so {@code AuthHelper.isLoggedProtocolUser()}
     * returns true for the rest of the test — mirroring how ACME/SCEP/CMP call the register endpoint. */
    private void authenticateAsProtocolUser() {
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, UUID.randomUUID().toString(), AuthHelper.ACME_USERNAME, List.of());
        SecurityContextHolder.getContext().setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
    }

    @Test
    void connectorBackedRegistrationAsProtocolUserSkipsCustomAttributes() throws Exception {
        // A protocol user (ACME/SCEP/CMP) registering on behalf of a device must not trip custom-attribute
        // validation/persistence at all — mirrors submitCertificateRequest's createCustomAttributes gate.
        authenticateAsProtocolUser();
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setCustomAttributes(List.of(mock(RequestAttribute.class)));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
        verify(attributeEngine, never()).validateCustomAttributesContent(Mockito.any(), Mockito.any());
        verify(attributeEngine, never()).updateObjectCustomAttributesContent(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void platformLevelRegistrationAsProtocolUserSkipsCustomAttributes() throws Exception {
        // Same skip contract on the platform-level (non-connector-backed) path.
        authenticateAsProtocolUser();
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setCustomAttributes(List.of(mock(RequestAttribute.class)));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
        verify(attributeEngine, never()).validateCustomAttributesContent(Mockito.any(), Mockito.any());
        verify(attributeEngine, never()).updateObjectCustomAttributesContent(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void registerRejectsBothFlatAndStructuredIdentity() {
        // Precedence: the pre-registration identity is either structured (csrAttributes) or flat, never both.
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-1,O=Acme");
        request.setCsrAttributes(List.of(mock(RequestAttribute.class)));

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));
        Assertions.assertEquals(0, certificateRepository.count(), "no placeholder should be persisted on an ambiguous request");
    }

    @Test
    void registerProjectsStructuredCsrAttributesAndForwardsContent() throws Exception {
        // Structured identity: a csrAttribute mapping the CN RDN. The orchestrator resolves definitions, projects
        // the attributes once, derives the placeholder DN from that content, and forwards the content to register().
        UUID cnUuid = UUID.randomUUID();
        DataAttributeV3 cnDef = new DataAttributeV3();
        cnDef.setUuid(cnUuid.toString());
        cnDef.setName("commonName");
        RdnMappedField rdn = new RdnMappedField();
        rdn.setFieldType(FieldType.RDN);
        rdn.setRdn("2.5.4.3");
        FieldMapping fieldMapping = new FieldMapping();
        fieldMapping.setFields(List.of(rdn));
        cnDef.setFieldMapping(fieldMapping);
        when(issuanceDefinitionResolver.resolve(Mockito.any())).thenReturn(List.of(cnDef));

        ArgumentCaptor<X509RequestContent> contentCaptor = ArgumentCaptor.forClass(X509RequestContent.class);
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), contentCaptor.capture()))
                .thenReturn(AdapterOperationResult.syncOk(null, List.of(), CertificateType.X509));

        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setCsrAttributes(List.of(new RequestAttributeV3(cnUuid, "commonName",
                AttributeContentType.STRING, List.<BaseAttributeContentV3<?>>of(new StringAttributeContentV3("device-9")))));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        // The projected structured content (subject from the attribute, not a flat DN) is forwarded to register().
        Assertions.assertEquals("device-9", contentCaptor.getValue().getSubject().get(0).getValue());
        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());

        // The submitted request-attribute values are persisted on the certificate itself, connectorless at
        // operation=null (the key getCertificate reads into registrationRequestAttributes).
        ArgumentCaptor<ObjectAttributeContentInfo> infoCaptor = ArgumentCaptor.forClass(ObjectAttributeContentInfo.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<RequestAttribute>> valuesCaptor = ArgumentCaptor.forClass(List.class);
        verify(attributeEngine).updateObjectDataAttributesContent(infoCaptor.capture(), valuesCaptor.capture());
        Assertions.assertEquals(Resource.CERTIFICATE, infoCaptor.getValue().objectType());
        Assertions.assertEquals(cert.getUuid(), infoCaptor.getValue().objectUuid());
        Assertions.assertNull(infoCaptor.getValue().operation(), "register request values are stored at operation=null");
        Assertions.assertNull(infoCaptor.getValue().connectorUuid(), "register request values are stored connectorless");
        Assertions.assertEquals(1, valuesCaptor.getValue().size());
        Assertions.assertEquals(cnUuid, valuesCaptor.getValue().get(0).getUuid());
    }

    // ── registered identity (SAN / extensions) on the placeholder ────────────

    @Test
    void registerPersistsProjectedSanOnPlaceholder() throws Exception {
        // A csrAttribute mapped to a DNS SAN must be recorded on the placeholder row, not reduced to the
        // subject DN. SAN-only identities are permitted (RFC 5280 §4.1.2.6), so the DN stays empty here.
        UUID sanUuid = UUID.randomUUID();
        DataAttributeV3 sanDef = new DataAttributeV3();
        sanDef.setUuid(sanUuid.toString());
        sanDef.setName("dnsName");
        SanMappedField san = new SanMappedField();
        san.setFieldType(FieldType.SAN);
        san.setGeneralNameType(GeneralNameType.DNS);
        FieldMapping fieldMapping = new FieldMapping();
        fieldMapping.setFields(List.of(san));
        sanDef.setFieldMapping(fieldMapping);
        when(issuanceDefinitionResolver.resolve(Mockito.any())).thenReturn(List.of(sanDef));
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, List.of(), CertificateType.X509));

        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setCsrAttributes(List.of(new RequestAttributeV3(sanUuid, "dnsName",
                AttributeContentType.STRING, List.<BaseAttributeContentV3<?>>of(new StringAttributeContentV3("device-9.example.com")))));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Map<String, List<String>> sans = CertificateUtil.deserializeSans(cert.getSubjectAlternativeNames());
        Assertions.assertEquals(List.of("device-9.example.com"), sans.get("dNSName"),
                "the projected DNS SAN must be persisted on the placeholder row");
    }

    @Test
    void registerPersistsFlatSanOnPlaceholder() throws Exception {
        // The flat subjectAltName string must be recorded on the placeholder row, same as the projected form.
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setSubjectAltName("DNS:device-1.example.com,IP:10.0.0.1");

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Map<String, List<String>> sans = CertificateUtil.deserializeSans(cert.getSubjectAlternativeNames());
        Assertions.assertEquals(List.of("device-1.example.com"), sans.get("dNSName"),
                "the flat DNS SAN must be persisted on the placeholder row");
        Assertions.assertEquals(List.of("10.0.0.1"), sans.get("iPAddress"),
                "the flat IP SAN must be persisted on the placeholder row");
    }

    @Test
    void registerPersistsOtherNameSanOnPlaceholder() throws Exception {
        // otherName rides the flat form as 'otherName:<oid>;UTF8:<value>' and must persist in the same
        // 'oid=value' serialized form used for issued certificates (the shared formatOtherNameSan).
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setSubjectAltName("otherName:1.3.6.1.4.1.311.20.2.3;UTF8:device-9@acme.test");

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Map<String, List<String>> sans = CertificateUtil.deserializeSans(cert.getSubjectAlternativeNames());
        Assertions.assertEquals(List.of("1.3.6.1.4.1.311.20.2.3=device-9@acme.test"), sans.get("otherName"),
                "the otherName SAN must persist on the placeholder in the oid=value serialized form");
    }

    @Test
    void platformLevelRegistrationPersistsSanOnPlaceholder() throws Exception {
        // Platform-level path (no connector-backed registration): the requested SAN must be stored on the
        // placeholder, not silently dropped
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setSubjectAltName("DNS:device-1.example.com");

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
        Map<String, List<String>> sans = CertificateUtil.deserializeSans(cert.getSubjectAlternativeNames());
        Assertions.assertEquals(List.of("device-1.example.com"), sans.get("dNSName"),
                "the platform-level placeholder must record the requested SAN");
        // The certificate detail must expose the SAN for a content-less placeholder too — the detail mapper
        // reads the SAN column unconditionally, not only for certificates that already carry issued content.
        CertificateDetailDto detail = certificateExternalService.getCertificate(SecuredUUID.fromString(response.getUuid()));
        Assertions.assertEquals(List.of("device-1.example.com"), detail.getSubjectAlternativeNames().get("dNSName"),
                "the certificate detail of a placeholder must expose the registered SAN");
    }

    @Test
    void platformLevelRegistrationAcceptsExtensions() throws Exception {
        // Extensions cannot be stored on the placeholder row or forwarded (no connector /register call), but
        // they must not fail a platform-level pre-registration: the request attributes returned for the
        // certificate carry what was requested, and the authoritative extensions arrive with the CSR at issuance.
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        ClientCertificateRegistrationDto request = registrationRequest();
        CertificateExtension extension = new CertificateExtension();
        extension.setOid("1.3.6.1.5.5.7.1.1");
        extension.setValueBase64(Base64.getEncoder().encodeToString(new byte[]{0x30, 0x00}));
        request.setExtensions(List.of(extension));

        ClientCertificateDataResponseDto response =
                clientOperationService.registerCertificate(authorityParent, securedRaProfile, request);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState(),
                "extensions must not fail a platform-level pre-registration");
    }

    @Test
    void registerRejectsMalformedFlatSanBeforePlaceholder() {
        // The flat identity is now projected in the orchestrator, before the placeholder — a malformed SAN
        // rejects with no row, uniform with the sibling register validations.
        registeringAdapter();
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setSubjectAltName("BOGUS:device-1");

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));
        Assertions.assertEquals(0, certificateRepository.count(),
                "a malformed flat SAN must be rejected before the placeholder is created");
    }

    @Test
    void registerRejectsStructuredCsrAttributesThatProjectNoIdentity() throws Exception {
        // Unmapped/extension-only csrAttributes project to no subject and no SAN — reject before placeholder creation.
        // The adapter must be register-capable so the flow passes the capability gate and actually reaches the
        // empty-projection check (otherwise the gate's ValidationException would satisfy the assertion by accident).
        registeringAdapter();
        when(issuanceDefinitionResolver.resolve(Mockito.any())).thenReturn(List.of());
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setCsrAttributes(List.of(new RequestAttributeV3(UUID.randomUUID(), "unmapped",
                AttributeContentType.STRING, List.<BaseAttributeContentV3<?>>of(new StringAttributeContentV3("x")))));

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> clientOperationService.registerCertificate(authorityParent, securedRaProfile, request));
        Assertions.assertTrue(ex.getMessage().contains("did not yield a subject or subjectAltName"),
                "must fail on the empty-projection check, not the upstream capability gate");
        Assertions.assertEquals(0, certificateRepository.count(),
                "no placeholder should be persisted when structured identity projects empty");
    }

    @Test
    void registerRejectsIssuanceWindowWithoutChallenge() {
        // An issuance window is enforced only within the challenge regime (it lives on the authorization, created
        // only with a secret), so a window without an authorizationSecret must be rejected up front rather than
        // silently dropped — before any placeholder is created.
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-nowindow,O=Test");
        request.setExpiresAt(OffsetDateTime.now().plusDays(1));

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> clientOperationService.registerCertificate(authorityParent, securedRaProfile, request));
        Assertions.assertTrue(ex.getMessage().contains("requires an authorization secret"),
                "an issuance window without a challenge must be rejected");
        Assertions.assertEquals(0, certificateRepository.count(),
                "no placeholder should be created when the window-without-challenge combination is rejected");
    }

    @Test
    void registerPersistsConnectorRegisterAttributesUnderTheRegisterOperation() throws Exception {
        // A connector-backed registration carrying connector register attributes stores them on the certificate
        // under the register operation (+ connector), so they surface as registerAttributes on the detail.
        RegisterCapability adapter = registeringAdapter();
        when(adapter.register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        when(adapter.listRegisterAttributes(Mockito.any(), Mockito.any())).thenReturn(List.of());

        RequestAttribute registerAttr = new RequestAttributeV3(UUID.randomUUID(), "registerParam",
                AttributeContentType.STRING, List.<BaseAttributeContentV3<?>>of(new StringAttributeContentV3("v")));
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-conn-attrs,O=Acme");
        request.setAttributes(List.of(registerAttr));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        UUID certUuid = UUID.fromString(response.getUuid());
        ArgumentCaptor<ObjectAttributeContentInfo> infoCaptor = ArgumentCaptor.forClass(ObjectAttributeContentInfo.class);
        verify(attributeEngine).updateObjectDataAttributesContent(infoCaptor.capture(), Mockito.anyList());
        ObjectAttributeContentInfo info = infoCaptor.getValue();
        Assertions.assertEquals(Resource.CERTIFICATE, info.objectType());
        Assertions.assertEquals(certUuid, info.objectUuid());
        Assertions.assertEquals(AttributeOperation.CERTIFICATE_REGISTER, info.operation(),
                "connector register attributes are stored under the register operation");
        Assertions.assertNotNull(info.connectorUuid(), "connector register attributes are connector-scoped");
    }

    @Test
    void clearIssuanceWindowNullsExpiryAndKeepsStateActive() {
        // The window governs only the initial issuance; clearing it leaves the authorization ACTIVE and durable
        // for a later renew/rekey, with no stale deadline a future sweep could flip to EXPIRED.
        Certificate cert = seedIssuedCert();
        activeAuthorizationFor(cert.getUuid());
        Assertions.assertNotNull(authorizationRepository.findByCertificateUuid(cert.getUuid()).orElseThrow().getExpiresAt(),
                "precondition: the authorization starts with an issuance window");

        registrationAuthorizationWriter.clearIssuanceWindow(cert.getUuid());

        CertificateRegistrationAuthorization after = authorizationRepository.findByCertificateUuid(cert.getUuid()).orElseThrow();
        Assertions.assertNull(after.getExpiresAt(), "the issuance window must be cleared on completion");
        Assertions.assertEquals(RegistrationState.ACTIVE, after.getState(), "the authorization stays ACTIVE for renew/rekey");
    }

    @Test
    void registerWrapsCsrAttributeValidationFailure() throws Exception {
        // An AttributeException from the attribute engine's validation must surface as a client-facing
        // ValidationException ("Invalid csrAttributes...") and leave no placeholder behind.
        registeringAdapter();
        when(issuanceDefinitionResolver.resolve(Mockito.any())).thenReturn(List.of());
        doThrow(new AttributeException("content item is not part of predefined list")).when(attributeEngine)
                .validateUpdateDataAttributes(Mockito.any(), Mockito.any(), Mockito.anyList(), Mockito.anyList());
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setCsrAttributes(List.of(new RequestAttributeV3(UUID.randomUUID(), "commonName",
                AttributeContentType.STRING, List.<BaseAttributeContentV3<?>>of(new StringAttributeContentV3("device-9")))));

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> clientOperationService.registerCertificate(authorityParent, securedRaProfile, request));
        Assertions.assertTrue(ex.getMessage().startsWith("Invalid csrAttributes for certificate registration"),
                "the AttributeException must be wrapped as a csrAttributes validation error");
        Assertions.assertEquals(0, certificateRepository.count(),
                "no placeholder should be persisted when csrAttributes validation fails");
    }

    @Test
    void registerRejectsInvalidSubjectDn() {
        registeringAdapter();
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("@@@ not a valid dn @@@");
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.registerCertificate(
                authorityParent,
                securedRaProfile, request));
    }

    @Test
    void issueExistingRejectsDisabledRaProfile() throws Exception {
        String certUuid = registerSyncRegistered();
        raProfile.setEnabled(false);
        raProfileRepository.save(raProfile);
        ClientCertificateIssueRequestDto issueRequest = new ClientCertificateIssueRequestDto();
        issueRequest.setRequest("x");
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, issueRequest));
    }

    @Test
    void issueExistingRejectsCertInNonIssuableState() {
        Certificate issued = new Certificate();
        issued.setState(CertificateState.ISSUED);
        issued.setRaProfile(raProfile);
        issued = certificateRepository.save(issued);
        String certUuid = issued.getUuid().toString();
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, null));
    }

    // ── owner & groups on registration (#1835) ───────────────────────────────

    private Group persistGroup(String name) {
        Group group = new Group();
        group.setName(name);
        return groupRepository.save(group);
    }

    private void stubResolvableOwner(UUID ownerUuid, String username) {
        UserDetailDto userDetail = new UserDetailDto();
        userDetail.setUuid(ownerUuid.toString());
        userDetail.setUsername(username);
        when(userManagementApiClient.getUserDetail(ownerUuid.toString())).thenReturn(userDetail);
    }

    @Test
    void registrationDefaultsOwnerToLoggedUserWhenNoneProvided() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));

        ClientCertificateDataResponseDto response = register();

        NameAndUuidDto owner = objectAssociationService.getOwner(Resource.CERTIFICATE, UUID.fromString(response.getUuid()));
        Assertions.assertNotNull(owner, "an omitted owner defaults to the registering user");
        Assertions.assertEquals("tst-user", owner.getName());
    }

    @Test
    void registrationPersistsExplicitOwnerAndGroups() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        UUID ownerUuid = UUID.randomUUID();
        stubResolvableOwner(ownerUuid, "device-owner");
        Group group = persistGroup("registration-group");

        ClientCertificateRegistrationDto request = registrationRequest();
        request.setOwnerUuid(ownerUuid.toString());
        request.setGroupUuids(Set.of(group.getUuid()));

        ClientCertificateDataResponseDto response =
                clientOperationService.registerCertificate(authorityParent, securedRaProfile, request);

        UUID certUuid = UUID.fromString(response.getUuid());
        Assertions.assertEquals(ownerUuid.toString(),
                objectAssociationService.getOwner(Resource.CERTIFICATE, certUuid).getUuid());
        Assertions.assertEquals(List.of(group.getUuid()),
                objectAssociationService.getGroupUuids(Resource.CERTIFICATE, certUuid));
    }

    @Test
    void platformLevelRegistrationPersistsOwnerAndGroups() throws Exception {
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));
        UUID ownerUuid = UUID.randomUUID();
        stubResolvableOwner(ownerUuid, "device-owner");
        Group group = persistGroup("platform-level-group");

        ClientCertificateRegistrationDto request = registrationRequest();
        request.setOwnerUuid(ownerUuid.toString());
        request.setGroupUuids(Set.of(group.getUuid()));

        ClientCertificateDataResponseDto response =
                clientOperationService.registerCertificate(authorityParent, securedRaProfile, request);

        UUID certUuid = UUID.fromString(response.getUuid());
        Assertions.assertEquals(ownerUuid.toString(),
                objectAssociationService.getOwner(Resource.CERTIFICATE, certUuid).getUuid());
        Assertions.assertEquals(List.of(group.getUuid()),
                objectAssociationService.getGroupUuids(Resource.CERTIFICATE, certUuid));
    }

    @Test
    void registrationWithUnknownGroupFailsPlaceholderPreAcceptance() throws Exception {
        RegisterCapability adapter = registeringAdapter();
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setGroupUuids(Set.of(UUID.randomUUID())); // no such Group exists

        Assertions.assertThrows(NotFoundException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));

        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertEquals(1, certs.size());
        Assertions.assertEquals(CertificateState.FAILED, certs.get(0).getState(),
                "an unknown group must fail the placeholder before the connector call");
        verify(adapter, never()).register(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void issuingRegisteredCertificatePreservesOwnerAndGroups() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        UUID ownerUuid = UUID.randomUUID();
        stubResolvableOwner(ownerUuid, "device-owner");
        Group group = persistGroup("preserved-group");
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setOwnerUuid(ownerUuid.toString());
        request.setGroupUuids(Set.of(group.getUuid()));
        UUID certUuid = UUID.fromString(
                clientOperationService.registerCertificate(authorityParent, securedRaProfile, request).getUuid());

        ClientCertificateIssueRequestDto issueRequest = new ClientCertificateIssueRequestDto();
        issueRequest.setRequest(generateCsrBase64());
        clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, certUuid.toString(), issueRequest);

        Assertions.assertEquals(ownerUuid.toString(),
                objectAssociationService.getOwner(Resource.CERTIFICATE, certUuid).getUuid(),
                "attaching the operator CSR at issuance must not change the registered owner");
        Assertions.assertEquals(List.of(group.getUuid()),
                objectAssociationService.getGroupUuids(Resource.CERTIFICATE, certUuid),
                "attaching the operator CSR at issuance must not change the registered groups");
    }

    // ── register->issue binding persistence ──────────────────────────────────

    private static MetadataAttribute caHandle(String name, String value) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(value)));
        return attribute;
    }

    @Test
    void syncRegistrationPersistsRegisterIssueBinding() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, List.of(caHandle("endEntityName", "device-1")), CertificateType.X509));

        ClientCertificateDataResponseDto response = register();

        CertificateRegistration binding = registrationRepository
                .findByCertificateUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertNotNull(binding.getMeta(), "the CA handle must be persisted on the binding");
        Assertions.assertTrue(binding.getMeta().contains("endEntityName"));
    }

    @Test
    void asyncRegistrationPersistsBindingWithTrackingHandle() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(List.of(caHandle("trackingId", "t-1"))));

        ClientCertificateDataResponseDto response = register();

        CertificateRegistration binding = registrationRepository
                .findByCertificateUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertTrue(binding.getMeta().contains("trackingId"));
    }

    @Test
    void registrationWithoutMetaStillCreatesBinding() throws Exception {
        // The binding row's presence is the register-bound discriminator for the later issue,
        // independent of whether the connector returned a CA handle.
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));

        ClientCertificateDataResponseDto response = register();

        CertificateRegistration binding = registrationRepository
                .findByCertificateUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertNull(binding.getMeta());
    }

    @Test
    void bindingPersistenceFailureKeepsPendingStateAndSurfacesError() throws Exception {
        // Post-acceptance divergence: the connector accepted the registration, so a failed binding
        // write must NOT roll certificate state back — it surfaces a clear error and leaves the cert
        // PENDING_REGISTRATION for reconciliation (the sync REGISTERED transition never runs).
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        doThrow(new IllegalStateException("db down")).when(registrationWriter)
                .upsert(Mockito.any(), Mockito.any());

        Assertions.assertThrows(ConnectorAcceptedButLocalFailureException.class, this::register);

        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertEquals(1, certs.size());
        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, certs.get(0).getState());
    }

    @Test
    void rejectedRegistrationLeavesNoBinding() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenThrow(new ConnectorException("upstream refused"));

        Assertions.assertThrows(ConnectorException.class, this::register);

        Assertions.assertEquals(0, registrationRepository.count(),
                "a rejected registration must not leave a register->issue binding behind");
    }

    // ── registration challenge authorization ────────────────────────────────

    private static final String CHALLENGE = "s3cret-value-1234";
    // The default maximum failed challenge-verification attempts before the authorization locks.
    private static final int MAX_FAILED_ATTEMPTS = 5;

    @Test
    void registerWithSecretCreatesActiveEncryptedAuthorization() throws Exception {
        String certUuid = registerWithSecret(null);

        CertificateRegistrationAuthorization auth = authorizationRepository
                .findByCertificateUuid(UUID.fromString(certUuid)).orElseThrow();
        Assertions.assertEquals(1, authorizationRepository.count(), "exactly one authorization is created");
        Assertions.assertEquals(RegistrationState.ACTIVE, auth.getState());
        Assertions.assertEquals(0, auth.getFailedAttempts());
        Assertions.assertNotEquals(CHALLENGE, auth.getChallenge(), "the challenge must be stored encrypted, not in plaintext");
        Assertions.assertTrue(registrationChallengeStore.verify(auth, CHALLENGE), "the stored challenge must verify");
        Assertions.assertNotNull(auth.getExpiresAt(), "a default issuance window is applied when none is supplied");
        Assertions.assertTrue(auth.getExpiresAt().isAfter(OffsetDateTime.now().plusDays(6)),
                "the default window is ~7 days out");
    }

    @Test
    void registerWithSecretAndExplicitWindowStoresThatWindow() throws Exception {
        OffsetDateTime window = OffsetDateTime.now().plusDays(2).withNano(0);
        String certUuid = registerWithSecret(window);

        CertificateRegistrationAuthorization auth = authorizationRepository
                .findByCertificateUuid(UUID.fromString(certUuid)).orElseThrow();
        Assertions.assertEquals(window.toInstant(), auth.getExpiresAt().toInstant());
    }

    @Test
    void registerWithPastWindowIsRejectedAndLeavesNoRowOrPlaceholder() {
        registeringAdapter();
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-1,O=Acme");
        request.setAuthorizationSecret(CHALLENGE);
        request.setExpiresAt(OffsetDateTime.now().minusMinutes(1));

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));
        Assertions.assertEquals(0, authorizationRepository.count(), "a past window must create no authorization");
        Assertions.assertEquals(0, certificateRepository.count(),
                "a past window is rejected before the placeholder, leaving no orphaned certificate");
    }

    @Test
    void registerWithoutSecretCreatesNoAuthorization() throws Exception {
        registerSyncRegistered();
        Assertions.assertEquals(0, authorizationRepository.count(),
                "the operator register flow (no secret) must create no authorization");
    }

    @Test
    void issueWithCorrectChallengeIsAuthorizedAndEnqueues() throws Exception {
        String certUuid = registerWithSecret(null);
        ClientCertificateIssueRequestDto issueRequest = new ClientCertificateIssueRequestDto();
        issueRequest.setRequest(generateCsrBase64());
        issueRequest.setAuthorizationSecret(CHALLENGE);

        clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, certUuid, issueRequest);

        verify(actionProducer).produceMessage(Mockito.argThat(m -> m.getResourceAction() == ResourceAction.ISSUE));
        CertificateRegistrationAuthorization auth = authorizationRepository
                .findByCertificateUuid(UUID.fromString(certUuid)).orElseThrow();
        Assertions.assertEquals(0, auth.getFailedAttempts(), "a successful challenge keeps the counter at zero");
        Assertions.assertEquals(RegistrationState.ACTIVE, auth.getState());
    }

    @Test
    void issueWithWrongChallengeIsDeniedAndIncrementSurvives() throws Exception {
        String certUuid = registerWithSecret(null);
        ClientCertificateIssueRequestDto issueRequest = new ClientCertificateIssueRequestDto();
        issueRequest.setRequest(generateCsrBase64());
        issueRequest.setAuthorizationSecret("wrong-secret-9999");

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent, securedRaProfile, certUuid, issueRequest));

        // The increment must be committed before the 422 is thrown, so a fresh read sees it.
        CertificateRegistrationAuthorization auth = authorizationRepository
                .findByCertificateUuid(UUID.fromString(certUuid)).orElseThrow();
        Assertions.assertEquals(1, auth.getFailedAttempts(), "the failed-attempt increment must survive the rejection");
        Assertions.assertEquals(RegistrationState.ACTIVE, auth.getState());
        verify(actionProducer, never()).produceMessage(Mockito.any());
        Assertions.assertEquals(CertificateState.REGISTERED,
                certificateRepository.findByUuid(UUID.fromString(certUuid)).orElseThrow().getState(),
                "a denied issue must not consume the placeholder");
    }

    @Test
    void repeatedWrongChallengeLocksTheAuthorization() throws Exception {
        String certUuid = registerWithSecret(null);
        ClientCertificateIssueRequestDto wrong = new ClientCertificateIssueRequestDto();
        wrong.setRequest(generateCsrBase64());
        wrong.setAuthorizationSecret("wrong-secret-9999");

        for (int i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
            Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                    authorityParent, securedRaProfile, certUuid, wrong));
        }
        Assertions.assertEquals(RegistrationState.LOCKED,
                authorizationRepository.findByCertificateUuid(UUID.fromString(certUuid)).orElseThrow().getState());

        // Even the correct challenge is denied once locked.
        ClientCertificateIssueRequestDto correct = new ClientCertificateIssueRequestDto();
        correct.setRequest(generateCsrBase64());
        correct.setAuthorizationSecret(CHALLENGE);
        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, certUuid, correct));
        Assertions.assertTrue(ex.getMessage().toLowerCase().contains("locked"), "the denial must state the lock");
    }

    @Test
    void issueWithExpiredWindowIsDeniedAndFlipsToExpired() throws Exception {
        String certUuid = registerWithSecret(null);
        // Move the window into the past to exercise the lazy expiry check at the gate.
        CertificateRegistrationAuthorization seeded = authorizationRepository
                .findByCertificateUuid(UUID.fromString(certUuid)).orElseThrow();
        seeded.setExpiresAt(OffsetDateTime.now().minusMinutes(1));
        authorizationRepository.save(seeded);

        ClientCertificateIssueRequestDto issueRequest = new ClientCertificateIssueRequestDto();
        issueRequest.setRequest(generateCsrBase64());
        issueRequest.setAuthorizationSecret(CHALLENGE);
        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, certUuid, issueRequest));
        Assertions.assertTrue(ex.getMessage().toLowerCase().contains("expired"), "the denial must state the expiry");
        Assertions.assertEquals(RegistrationState.EXPIRED,
                authorizationRepository.findByCertificateUuid(UUID.fromString(certUuid)).orElseThrow().getState());
    }

    @Test
    void renewOfCertWithActiveAuthorizationIsDenied() {
        Certificate issued = seedIssuedCert();
        activeAuthorizationFor(issued.getUuid());
        ClientCertificateRenewRequestDto request = new ClientCertificateRenewRequestDto();
        String certUuid = issued.getUuid().toString();

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> clientOperationService.renewCertificate(authorityParent, securedRaProfile, certUuid, request));
        Assertions.assertTrue(ex.getMessage().contains("not supported yet"),
                "the fail-closed guard must reject, not some downstream step");
    }

    @Test
    void rekeyOfCertWithActiveAuthorizationIsDenied() {
        Certificate issued = seedIssuedCert();
        activeAuthorizationFor(issued.getUuid());
        ClientCertificateRekeyRequestDto request = new ClientCertificateRekeyRequestDto();
        String certUuid = issued.getUuid().toString();

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> clientOperationService.rekeyCertificate(authorityParent, securedRaProfile, certUuid, request));
        Assertions.assertTrue(ex.getMessage().contains("not supported yet"),
                "the fail-closed guard must reject rekey too (verification comes later)");
    }

    @Test
    void approvalRejectedRestoresRegisteredPlaceholderKeepingAuthorizationActive() throws Exception {
        UUID certUuid = UUID.fromString(registerWithSecret(null)); // REGISTERED placeholder + ACTIVE authorization
        clientOperationInternalService.approvalCreatedAction(certUuid); // issuing it requires approval -> PENDING_APPROVAL
        Assertions.assertEquals(CertificateState.PENDING_APPROVAL,
                certificateRepository.findByUuid(certUuid).orElseThrow().getState());

        clientOperationInternalService.issueCertificateRejectedAction(certUuid);

        Assertions.assertEquals(CertificateState.REGISTERED,
                certificateRepository.findByUuid(certUuid).orElseThrow().getState(),
                "a rejected issuance approval restores the placeholder rather than terminating it REJECTED");
        CertificateRegistrationAuthorization auth = authorizationRepository.findByCertificateUuid(certUuid).orElseThrow();
        Assertions.assertEquals(RegistrationState.ACTIVE, auth.getState(),
                "the authorization stays ACTIVE so the holder can retry the issue");
        Assertions.assertEquals(1, authorizationRepository.count());
    }

    @Test
    void approvalRejectedOfCertWithoutAuthorizationTerminatesRejected() throws Exception {
        // A cert carrying no registration authorization keeps the terminal REJECTED behaviour on approval rejection.
        Certificate cert = new Certificate();
        cert.setState(CertificateState.PENDING_APPROVAL);
        cert.setRaProfile(raProfile);
        cert.setRaProfileUuid(raProfile.getUuid());
        UUID uuid = certificateRepository.save(cert).getUuid();

        clientOperationInternalService.issueCertificateRejectedAction(uuid);

        Assertions.assertEquals(CertificateState.REJECTED,
                certificateRepository.findByUuid(uuid).orElseThrow().getState());
        Assertions.assertEquals(0, authorizationRepository.count());
    }

    @Test
    void approvalRejectedRestoresRegisteredPlaceholderWithBindingButNoSecret() throws Exception {
        UUID certUuid = UUID.fromString(registerSyncRegistered()); // operator register: binding, no challenge authorization
        clientOperationInternalService.approvalCreatedAction(certUuid);
        Assertions.assertEquals(CertificateState.PENDING_APPROVAL,
                certificateRepository.findByUuid(certUuid).orElseThrow().getState());

        clientOperationInternalService.issueCertificateRejectedAction(certUuid);

        Assertions.assertEquals(CertificateState.REGISTERED,
                certificateRepository.findByUuid(certUuid).orElseThrow().getState(),
                "a no-secret pre-registration is restored too — the binding is the discriminator, not the challenge row");
        Assertions.assertTrue(registrationRepository.findByCertificateUuid(certUuid).isPresent(),
                "the register->issue binding is preserved so the holder can retry");
        Assertions.assertEquals(0, authorizationRepository.count(), "a no-secret flow carries no challenge authorization");
    }

    @Test
    void customIssuanceWindowSettingIsAppliedToNewAuthorizations() throws Exception {
        PlatformSettingsDto custom = settingService.getPlatformSettings();
        custom.getCertificates().getRegistration().setDefaultIssuanceWindowDays(30);
        settingsCache.cacheSettings(SettingsSection.PLATFORM, custom);
        try {
            String certUuid = registerWithSecret(null); // no explicit expiry, so the configured default window applies
            CertificateRegistrationAuthorization auth = authorizationRepository
                    .findByCertificateUuid(UUID.fromString(certUuid)).orElseThrow();
            Assertions.assertTrue(auth.getExpiresAt().isAfter(OffsetDateTime.now().plusDays(29)),
                    "the operator-configured 30-day window must be applied, not the 7-day fallback");
        } finally {
            settingsCache.cacheSettings(SettingsSection.PLATFORM, settingService.getPlatformSettings());
        }
    }

    @Test
    void customMaxFailedAttemptsSettingLocksTheAuthorization() throws Exception {
        PlatformSettingsDto custom = settingService.getPlatformSettings();
        custom.getCertificates().getRegistration().setMaxFailedAttempts(2);
        settingsCache.cacheSettings(SettingsSection.PLATFORM, custom);
        try {
            String certUuid = registerWithSecret(null);
            ClientCertificateIssueRequestDto wrong = new ClientCertificateIssueRequestDto();
            wrong.setRequest(generateCsrBase64());
            wrong.setAuthorizationSecret("wrong-secret-9999");
            for (int i = 0; i < 2; i++) {
                Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                        authorityParent, securedRaProfile, certUuid, wrong));
            }
            Assertions.assertEquals(RegistrationState.LOCKED,
                    authorizationRepository.findByCertificateUuid(UUID.fromString(certUuid)).orElseThrow().getState(),
                    "the operator-configured lockout threshold of 2 must be applied, not the 5-attempt fallback");
        } finally {
            settingsCache.cacheSettings(SettingsSection.PLATFORM, settingService.getPlatformSettings());
        }
    }

    @Test
    void registerWithSecretFiresCertificateRegisteredEvent() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setAuthorizationSecret(CHALLENGE);

        clientOperationService.registerCertificate(authorityParent, securedRaProfile, request);

        ArgumentCaptor<EventMessage> captor = ArgumentCaptor.forClass(EventMessage.class);
        verify(eventProducer).produceMessage(captor.capture());
        Assertions.assertEquals(ResourceEvent.CERTIFICATE_REGISTERED, captor.getValue().getEvent(),
                "a challenge-protected pre-registration fires the Certificate Registered event");
    }

    @Test
    void registerWithoutSecretFiresNoRegistrationEvent() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));

        clientOperationService.registerCertificate(authorityParent, securedRaProfile, registrationRequest());

        verify(eventProducer, never()).produceMessage(Mockito.any());
    }

    @Test
    void registerSucceedsWhenRegistrationEventProduceFails() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        doThrow(new RuntimeException("broker down")).when(eventProducer).produceMessage(Mockito.any());
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setAuthorizationSecret(CHALLENGE);

        // Best-effort fire: the cert is already committed REGISTERED, so a produce failure must not fail the caller.
        ClientCertificateDataResponseDto response =
                clientOperationService.registerCertificate(authorityParent, securedRaProfile, request);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
    }

    @Test
    void registrationStoreFailureFailsPlaceholderInsteadOfOrphaning() {
        // A local authorization-store failure (encryption/persistence) must fail the placeholder via the
        // pre-acceptance catch, not leave it stranded in PENDING_REGISTRATION with no authorization.
        registeringAdapter();
        doThrow(new IllegalStateException("challenge encryption failed"))
                .when(registrationChallengeStore).store(Mockito.any(), Mockito.any());
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setAuthorizationSecret(CHALLENGE);

        Assertions.assertThrows(RuntimeException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));

        Assertions.assertEquals(0, authorizationRepository.count(), "a store failure persists no authorization");
        Assertions.assertTrue(
                certificateRepository.findAll().stream().noneMatch(c -> c.getState() == CertificateState.PENDING_REGISTRATION),
                "a store failure must fail the placeholder, not orphan it in PENDING_REGISTRATION");
    }

    @Test
    void connectorRejectionAfterAuthorizationSavedRemovesTheAuthorization() throws Exception {
        // The authorization row is committed before the connector call; a connector rejection then fails the
        // placeholder, and the registration never became effective, so its encrypted secret must not linger.
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenThrow(new ConnectorException("authority rejected the registration"));
        ClientCertificateRegistrationDto request = registrationRequest();
        request.setAuthorizationSecret(CHALLENGE);

        Assertions.assertThrows(ConnectorException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));

        Assertions.assertEquals(0, authorizationRepository.count(),
                "a connector rejection after the authorization was saved must remove it");
        Assertions.assertTrue(
                certificateRepository.findAll().stream().noneMatch(c -> c.getState() == CertificateState.PENDING_REGISTRATION),
                "the placeholder is failed, not orphaned in PENDING_REGISTRATION");
    }

    private String registerWithSecret(OffsetDateTime expiresAt) throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-1,O=Acme");
        request.setAuthorizationSecret(CHALLENGE);
        if (expiresAt != null) {
            request.setExpiresAt(expiresAt);
        }
        return clientOperationService.registerCertificate(authorityParent, securedRaProfile, request).getUuid();
    }

    private Certificate seedIssuedCert() {
        Certificate issued = new Certificate();
        issued.setState(CertificateState.ISSUED);
        issued.setRaProfile(raProfile);
        issued.setRaProfileUuid(raProfile.getUuid());
        return certificateRepository.save(issued);
    }

    private void activeAuthorizationFor(UUID certificateUuid) {
        CertificateRegistrationAuthorization auth = new CertificateRegistrationAuthorization();
        auth.setCertificateUuid(certificateUuid);
        auth.setState(RegistrationState.ACTIVE);
        auth.setFailedAttempts(0);
        auth.setExpiresAt(OffsetDateTime.now().plusDays(7));
        registrationChallengeStore.store(auth, CHALLENGE);
        authorizationRepository.save(auth);
    }

    private String registerSyncRegistered() throws Exception {
        when(registeringAdapter().register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        return register().getUuid();
    }

    private String generateCsrBase64() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=device-1,O=Acme"), keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate()));
        return Base64.getEncoder().encodeToString(csr.getEncoded());
    }
}
