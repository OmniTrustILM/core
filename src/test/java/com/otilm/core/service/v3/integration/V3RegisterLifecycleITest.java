package com.otilm.core.service.v3.integration;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.acme.AcmeTestUtil;
import com.otilm.core.service.v2.ClientOperationService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.V3ConnectorStubs;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.UUID;

/**
 * End-to-end integration tests for the v3 authority register lifecycle.
 *
 * <p>Exercises the real service → adapter → state-machine stack against a WireMock connector:
 * <ol>
 *   <li>Sync register (HTTP 200) → {@code REGISTERED} + optional meta persisted.</li>
 *   <li>Async register (HTTP 202) + both flags → {@code PENDING_REGISTRATION} + a
 *       {@code certificate_status_poll} row is written.</li>
 *   <li>Async register (HTTP 202) + only {@code CERTIFICATE_REGISTRATION} (no polling flag) →
 *       {@code PENDING_REGISTRATION} but <em>zero</em> poll rows (negative gate).</li>
 *   <li>Register sync → {@code REGISTERED}; supply CSR; {@code issueExistingCertificate} →
 *       ActionProducer spy forwards the ISSUE action → v2 issue stub 200 → {@code ISSUED};
 *       registration subject identity is preserved on the row.</li>
 * </ol>
 *
 * <p>The {@link ActionProducer} spy is wired using the same pattern as
 * {@link com.otilm.core.service.acme.integration.AcmeProtocolFlowITest}, forwarding ISSUE actions
 * synchronously to avoid a RabbitMQ dependency.
 */
public class V3RegisterLifecycleITest extends BaseSpringBootTest {

    // ── Spring beans ──────────────────────────────────────────────────────────

    @Autowired
    private ClientOperationService clientOperationService;

    @MockitoSpyBean
    private ActionProducer actionProducer;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateStatusPollRepository pollRepository;

    // Fixture builder repos
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    // ── Per-test state ────────────────────────────────────────────────────────

    private WireMockServer wireMockServer;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @BeforeEach
    public void setUpWireMock() {
        wireMockServer = new WireMockServer(0);
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());

        // Intercept ActionProducer to drive ISSUE actions synchronously, bypassing RabbitMQ.
        // All other action types are no-ops. Mirrors the AcmeProtocolFlowITest ActionProducer spy pattern.
        Mockito.doAnswer(inv -> {
            ActionMessage msg = inv.getArgument(0);
            if (msg.getResourceAction() == ResourceAction.ISSUE) {
                clientOperationService.issueCertificateAction(msg.getResourceUuid(), false);
            }
            return null;
        }).when(actionProducer).produceMessage(Mockito.any());
    }

    @AfterEach
    public void tearDownWireMock() {
        wireMockServer.stop();
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /**
     * Scenario 1: sync register (HTTP 200) → certificate reaches {@code REGISTERED}.
     *
     * <p>Asserts:
     * <ul>
     *   <li>State is {@code REGISTERED}.</li>
     *   <li>The registration subject DN from the request is recorded on the certificate row.</li>
     * </ul>
     */
    @Test
    public void registerSync_reachesRegistered() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture(FeatureFlag.CERTIFICATE_REGISTRATION);

        V3ConnectorStubs.stubRegisterSync(wireMockServer, null);

        ClientCertificateDataResponseDto response = registerCertificate(fixture, "CN=sync-device,O=Acme");

        Certificate cert = reloadCert(response.getUuid());
        Assertions.assertEquals(CertificateState.REGISTERED, cert.getState(),
                "Synchronous register must transition the certificate to REGISTERED");
        // The subject DN is stored in X.500 canonical (reversed) order by CertificateUtil.applyRegistrationSubject.
        // "CN=sync-device,O=Acme" → stored as "O=Acme, CN=sync-device".
        Assertions.assertNotNull(cert.getSubjectDn(), "Registration subject DN must be persisted on the placeholder");
        Assertions.assertTrue(cert.getSubjectDn().contains("CN=sync-device") && cert.getSubjectDn().contains("O=Acme"),
                "Registration subject DN must contain the requested CN and O values; was: " + cert.getSubjectDn());
    }

    /**
     * Scenario 2: async register (HTTP 202) with both {@code CERTIFICATE_REGISTRATION} and
     * {@code CERTIFICATE_STATUS_POLLING} flags → {@code PENDING_REGISTRATION} AND a
     * {@code certificate_status_poll} row exists.
     */
    @Test
    public void registerAsync_parksPendingAndSchedulesPoll() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture(
                FeatureFlag.CERTIFICATE_REGISTRATION,
                FeatureFlag.CERTIFICATE_STATUS_POLLING);

        V3ConnectorStubs.stubRegisterAsync(wireMockServer, null);

        ClientCertificateDataResponseDto response = registerCertificate(fixture, "CN=async-device,O=Acme");

        UUID certUuid = UUID.fromString(response.getUuid());
        Certificate cert = reloadCert(response.getUuid());

        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, cert.getState(),
                "Async register must park the certificate in PENDING_REGISTRATION");

        long pollRows = pollRepository.findAll().stream()
                .filter(p -> certUuid.equals(p.getCertificateUuid()))
                .count();
        Assertions.assertEquals(1L, pollRows,
                "Async register with both flags must write exactly one certificate_status_poll row");
    }

    /**
     * Scenario 3 (negative gate): async register (HTTP 202) with only {@code CERTIFICATE_REGISTRATION}
     * (no {@code CERTIFICATE_STATUS_POLLING}) → {@code PENDING_REGISTRATION} but zero poll rows.
     *
     * <p>The gate in {@code ClientOperationServiceImpl.scheduleStatusPoll} requires both conditions:
     * {@code adapter instanceof AsyncOperationCapability} AND
     * {@code capabilityService.supports(authority, CERTIFICATE_STATUS_POLLING)}.
     * Omitting the polling flag from the connector interface means the second condition is false.</p>
     */
    @Test
    public void registerAsync_withoutPollingFlag_parksPendingWithNoPollRow() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture(FeatureFlag.CERTIFICATE_REGISTRATION);

        V3ConnectorStubs.stubRegisterAsync(wireMockServer, null);

        ClientCertificateDataResponseDto response = registerCertificate(fixture, "CN=nopoll-device,O=Acme");

        UUID certUuid = UUID.fromString(response.getUuid());
        Certificate cert = reloadCert(response.getUuid());

        Assertions.assertEquals(CertificateState.PENDING_REGISTRATION, cert.getState(),
                "Async register without polling flag must still park the certificate in PENDING_REGISTRATION");

        long pollRows = pollRepository.findAll().stream()
                .filter(p -> certUuid.equals(p.getCertificateUuid()))
                .count();
        Assertions.assertEquals(0L, pollRows,
                "Async register without CERTIFICATE_STATUS_POLLING must NOT write a poll row");
    }

    /**
     * Scenario 4: register sync → {@code REGISTERED}; supply a CSR; {@code issueExistingCertificate}
     * → ActionProducer spy forwards ISSUE → v2 issue stub 200 → {@code ISSUED};
     * registration subject identity is preserved on the certificate row.
     */
    @Test
    public void registerThenIssue_roundTrip() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture(FeatureFlag.CERTIFICATE_REGISTRATION);

        // Step 1: register
        V3ConnectorStubs.stubRegisterSync(wireMockServer, null);
        ClientCertificateDataResponseDto registerResponse = registerCertificate(fixture, "CN=round-trip,O=Acme");

        Certificate certAfterRegister = reloadCert(registerResponse.getUuid());
        Assertions.assertEquals(CertificateState.REGISTERED, certAfterRegister.getState(),
                "Pre-condition: certificate must be REGISTERED before issue");
        // Subject DN is stored in canonical (reversed) order by CertificateUtil.applyRegistrationSubject.
        Assertions.assertNotNull(certAfterRegister.getSubjectDn(),
                "Pre-condition: registration subject DN must be stored");
        Assertions.assertTrue(certAfterRegister.getSubjectDn().contains("CN=round-trip"),
                "Pre-condition: subject DN must contain the requested CN; was: " + certAfterRegister.getSubjectDn());

        // Step 2: generate a CSR and stub the v2 issue endpoint
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();

        java.security.cert.X509Certificate x509 = AcmeTestUtil.createTestCertificate(kp, "round-trip");
        String certData = Base64.getEncoder().encodeToString(x509.getEncoded());
        V3ConnectorStubs.stubV2Issue(wireMockServer, certData);

        PKCS10CertificationRequest csr = AcmeTestUtil.createCsr(kp, "round-trip");
        String base64Csr = Base64.getEncoder().encodeToString(csr.getEncoded());

        // Step 3: issue the registered certificate
        ClientCertificateSignRequestDto signRequest = new ClientCertificateSignRequestDto();
        signRequest.setRequest(base64Csr);
        signRequest.setFormat(CertificateRequestFormat.PKCS10);
        signRequest.setAttributes(java.util.List.of());
        signRequest.setCustomAttributes(java.util.List.of());

        clientOperationService.issueExistingCertificate(
                SecuredParentUUID.fromUUID(fixture.authority().getUuid()),
                fixture.raProfile().getSecuredUuid(),
                registerResponse.getUuid(),
                signRequest);

        // Step 4: assert final state
        Certificate certAfterIssue = reloadCert(registerResponse.getUuid());
        Assertions.assertEquals(CertificateState.ISSUED, certAfterIssue.getState(),
                "issueExistingCertificate → ISSUE action → v2 issue 200 must transition cert to ISSUED");

        // Registration identity preserved: the subject DN from the registration step is still on the row
        // (the issued certificate's identity is written from the CA response at issuance time, but the
        // registration placeholder subject is always kept for traceability).
        Assertions.assertNotNull(certAfterIssue.getSubjectDn(),
                "Subject DN must not be null after issuance");
        Assertions.assertTrue(certAfterIssue.getSubjectDn().contains("CN=round-trip"),
                "Registration subject DN must be preserved through issuance; was: " + certAfterIssue.getSubjectDn());
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private AuthorityFixtures.Repos repos() {
        return new AuthorityFixtures.Repos(
                connectorRepository,
                functionGroupRepository,
                connector2FunctionGroupRepository,
                authorityInstanceReferenceRepository,
                raProfileRepository,
                connectorInterfaceRepository);
    }

    private AuthorityFixtures.Fixture buildV3Fixture(FeatureFlag... features) {
        return AuthorityFixtures.v3Authority(repos(), wireMockServer, features);
    }

    private ClientCertificateDataResponseDto registerCertificate(AuthorityFixtures.Fixture fixture, String subjectDn)
            throws Exception {
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn(subjectDn);

        return clientOperationService.registerCertificate(
                SecuredParentUUID.fromUUID(fixture.authority().getUuid()),
                fixture.raProfile().getSecuredUuid(),
                request);
    }

    private Certificate reloadCert(String uuidStr) {
        return certificateRepository.findByUuid(UUID.fromString(uuidStr))
                .orElseThrow(() -> new AssertionError("Certificate not found: " + uuidStr));
    }
}
