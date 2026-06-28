package com.otilm.core.service;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.v2.AvailableOperationsDto;
import com.otilm.api.model.core.v2.CertificateOperationKind;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.otilm.api.model.core.v2.OperationSupport;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.RegisterCapability;
import com.otilm.core.service.v2.ClientOperationService;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import com.otilm.core.util.BaseSpringBootTest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Service-level coverage for the v3 register flow. The authority adapter is mocked so the test drives
 * each branch (sync 200 / async 202 / connector failure / unsupported authority) and asserts the
 * orchestration the service owns — placeholder creation, state-machine transitions and poll scheduling.
 * The real adapter + v3 wire contract are covered by {@code AuthorityProviderV3AdapterTest}; the full
 * connector round-trip is deferred to the v3 integration suite.
 */
@SpringBootTest
class ClientOperationServiceRegisterTest extends BaseSpringBootTest {

    @Autowired
    private ClientOperationService clientOperationService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @MockitoBean
    private AuthorityProviderAdapterFactory adapterFactory;

    // Mocked so the test verifies that an async registration schedules a REGISTER poll, without
    // depending on the poll row surviving the background sweep/listener (covered by the v3 integration suite).
    @MockitoBean
    private CertificateStatusPollWriter pollWriter;

    // Mocked so issue enqueue is a deterministic no-op (no async action processing during the test).
    @MockitoBean
    private ActionProducer actionProducer;

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
    }

    private ClientCertificateRegistrationDto registrationRequest() {
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-1,O=Acme");
        return request;
    }

    /** Mocks an adapter that supports registration and makes the factory return it. */
    private RegisterCapability registeringAdapter() {
        // Both capabilities, like the real v3 adapter — so an async-accepted registration actually schedules a poll.
        AuthorityProviderAdapter adapter = Mockito.mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class, AsyncOperationCapability.class));
        Mockito.when(adapterFactory.forAuthority(Mockito.any())).thenReturn(adapter);
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
        Mockito.when(registeringAdapter().register(Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));

        ClientCertificateDataResponseDto response = register();

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
    }

    @Test
    void asyncRegistrationStaysPendingAndSchedulesRegisterPoll() throws Exception {
        Mockito.when(registeringAdapter().register(Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(null));

        ClientCertificateDataResponseDto response = register();

        UUID certUuid = UUID.fromString(response.getUuid());
        Certificate cert = certificateRepository.findByUuid(certUuid).orElseThrow();
        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, cert.getState());
        Mockito.verify(pollWriter).schedule(Mockito.eq(certUuid), Mockito.eq(CertificateOperation.REGISTER), Mockito.any());
    }

    @Test
    void unsupportedAuthorityIsRejectedWithoutCreatingPlaceholder() {
        // Adapter without RegisterCapability — i.e. a v2 authority.
        Mockito.when(adapterFactory.forAuthority(Mockito.any()))
                .thenReturn(Mockito.mock(AuthorityProviderAdapter.class));

        Assertions.assertThrows(ValidationException.class, this::register);
        Assertions.assertEquals(0, certificateRepository.count(), "no placeholder should be persisted on a rejected request");
    }

    @Test
    void connectorFailureLeavesPlaceholderFailed() throws Exception {
        Mockito.when(registeringAdapter().register(Mockito.any(), Mockito.any()))
                .thenThrow(new ConnectorException("upstream refused"));

        Assertions.assertThrows(ConnectorException.class, this::register);

        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertEquals(1, certs.size());
        Assertions.assertEquals(CertificateState.FAILED, certs.get(0).getState());
    }

    @Test
    void listAvailableOperationsForV2AuthorityExcludesRegisterAndAsync() throws Exception {
        Mockito.when(adapterFactory.forAuthority(Mockito.any()))
                .thenReturn(Mockito.mock(AuthorityProviderAdapter.class)); // v2: neither register nor async

        AvailableOperationsDto ops = listOperations();

        Assertions.assertFalse(operation(ops, CertificateOperationKind.REGISTER).isSupported());
        OperationSupport issue = operation(ops, CertificateOperationKind.ISSUE);
        Assertions.assertTrue(issue.isSupported());
        Assertions.assertFalse(issue.isAsyncSupported());
        Assertions.assertFalse(issue.isCancelSupported());
    }

    @Test
    void listAvailableOperationsForV3AuthoritySupportsRegisterAndAsync() throws Exception {
        AuthorityProviderAdapter adapter = Mockito.mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class, AsyncOperationCapability.class));
        Mockito.when(adapterFactory.forAuthority(Mockito.any())).thenReturn(adapter);

        OperationSupport register = operation(listOperations(), CertificateOperationKind.REGISTER);
        Assertions.assertTrue(register.isSupported());
        Assertions.assertTrue(register.isAsyncSupported());
        Assertions.assertTrue(register.isCancelSupported());
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
        ClientCertificateSignRequestDto noCsr = new ClientCertificateSignRequestDto(); // request == null

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, noCsr));
    }

    @Test
    void issueRegisteredCertificateWithNullCsrFormatIsRejected() throws Exception {
        // An explicit null format must surface a clear validation error, not NPE in the CSR parser's
        // switch(format).
        String certUuid = registerSyncRegistered();
        ClientCertificateSignRequestDto noFormat = new ClientCertificateSignRequestDto();
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

        ClientCertificateSignRequestDto withCsr = new ClientCertificateSignRequestDto();
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

        ClientCertificateSignRequestDto blank = new ClientCertificateSignRequestDto();
        blank.setRequest("   ");

        clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, certUuid, blank);

        Mockito.verify(actionProducer).produceMessage(Mockito.argThat(m -> m.getResourceAction() == ResourceAction.ISSUE));
    }

    @Test
    void issueRegisteredCertificateAttachesOperatorCsr() throws Exception {
        String certUuid = registerSyncRegistered();
        ClientCertificateSignRequestDto signRequest = new ClientCertificateSignRequestDto();
        signRequest.setRequest(generateCsrBase64());

        clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, signRequest);

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(certUuid)).orElseThrow();
        Assertions.assertNotNull(cert.getCertificateRequest(), "operator CSR should be attached to the registered placeholder");
        Mockito.verify(actionProducer).produceMessage(Mockito.argThat(m -> m.getResourceAction() == ResourceAction.ISSUE));
    }

    @Test
    void registerStaysPendingWhenConnectorAcceptedButLocalFailureRaised() throws Exception {
        Mockito.when(registeringAdapter().register(Mockito.any(), Mockito.any()))
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
        Mockito.when(registeringAdapter().register(Mockito.any(), Mockito.any()))
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

        ClientCertificateSignRequestDto signRequest = new ClientCertificateSignRequestDto();
        signRequest.setRequest("ignored-rejected-before-parse");
        SecuredParentUUID otherAuthority = SecuredParentUUID.fromUUID(otherRaProfile.getAuthorityInstanceReferenceUuid());
        SecuredUUID otherRa = otherRaProfile.getSecuredUuid();
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                otherAuthority, otherRa, certUuid, signRequest));
    }

    @Test
    void asyncRegistrationWithoutAsyncCapabilityDoesNotSchedulePoll() throws Exception {
        // Register-capable but NOT async-capable adapter that nonetheless returns async-accepted.
        AuthorityProviderAdapter adapter = Mockito.mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class));
        Mockito.when(adapterFactory.forAuthority(Mockito.any())).thenReturn(adapter);
        Mockito.when(((RegisterCapability) adapter).register(Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.asyncAccepted(null));

        ClientCertificateDataResponseDto response = register();

        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, cert.getState());
        Mockito.verify(pollWriter, Mockito.never()).schedule(Mockito.any(), Mockito.any(), Mockito.any());
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
        ClientCertificateSignRequestDto signRequest = new ClientCertificateSignRequestDto();
        signRequest.setRequest("!!!not-valid-base64!!!");
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, signRequest));
    }

    @Test
    void registerPersistsConnectorMetadata() throws Exception {
        Mockito.when(registeringAdapter().register(Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, List.of(Mockito.mock(MetadataAttribute.class)), CertificateType.X509));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent,
                securedRaProfile, registrationRequest());

        // Metadata persistence runs (and tolerates failure); registration still completes.
        Certificate cert = certificateRepository.findByUuid(UUID.fromString(response.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState());
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
        ClientCertificateSignRequestDto signRequest = new ClientCertificateSignRequestDto();
        signRequest.setRequest("x");
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueExistingCertificate(
                authorityParent,
                securedRaProfile, certUuid, signRequest));
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

    private String registerSyncRegistered() throws Exception {
        Mockito.when(registeringAdapter().register(Mockito.any(), Mockito.any()))
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
