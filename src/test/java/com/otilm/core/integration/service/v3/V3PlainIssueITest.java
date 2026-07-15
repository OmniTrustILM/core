package com.otilm.core.integration.service.v3;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.service.acme.AcmeTestUtil;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.V3ConnectorStubs;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateContentBuilder.aCertificateContent;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests for the v3 "plain issue" path: a {@code REQUESTED} certificate
 * with a real CSR and <em>no</em> {@link com.otilm.core.dao.entity.CertificateRegistration} binding.
 */
class V3PlainIssueITest extends BaseSpringBootTest {

    private static final String V3_ISSUE_PATH = "/v3/authorityProvider/certificates/issue";
    private static final String V2_ISSUE_PATTERN = "/v2/authorityProvider/authorities/[^/]+/certificates/issue";

    // ── Spring beans ──────────────────────────────────────────────────────────

    @Autowired
    private ClientOperationInternalService clientOperationInternalService;

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRequestRepository certificateRequestRepository;
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
    void startWireMockServer() {
        wireMockServer = new WireMockServer(0);
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());
    }

    @AfterEach
    void stopWireMockServer() {
        wireMockServer.stop();
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /**
     * Scenario 1: sync v3 issue (HTTP 200) on a {@code REQUESTED} certificate with no registration binding
     * → certificate reaches {@code ISSUED}, and the request landed on the v3 issue endpoint.
     */
    @Test
    void reachesIssued_whenSyncV3IssueSucceeds() throws Exception {
        // given
        AuthorityFixtures.Fixture fixture = buildV3Fixture(FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED);
        KeyPair kp = generateKeyPair();
        Certificate cert = seedRequestedCertWithCsr(fixture, kp, "plain-issue-sync");
        X509Certificate x509 = AcmeTestUtil.createTestCertificate(kp, "plain-issue-sync");
        String certData = Base64.getEncoder().encodeToString(x509.getEncoded());
        V3ConnectorStubs.stubV3IssueSync(wireMockServer, certData);

        // when
        clientOperationInternalService.issueCertificateAction(cert.getUuid(), true);

        // then
        Certificate after = reloadCert(cert.getUuid());
        assertThat(after.getState())
                .as("Plain issue with a synchronous v3 200 response must transition the certificate to ISSUED")
                .isEqualTo(CertificateState.ISSUED);
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(V3_ISSUE_PATH)));
        wireMockServer.verify(0, postRequestedFor(urlPathMatching(V2_ISSUE_PATTERN)));
    }

    /**
     * Scenario 2: async v3 issue (HTTP 202) on a {@code REQUESTED} certificate with no registration binding
     * and {@code CERTIFICATE_STATUS_POLLING} advertised → certificate parks in {@code PENDING_ISSUE}
     * and exactly one {@code certificate_status_poll} row is scheduled.
     */
    @Test
    void parksPendingIssueAndSchedulesPoll_whenAsyncV3IssueIsAccepted() throws Exception {
        // given
        AuthorityFixtures.Fixture fixture = buildV3Fixture(FeatureFlag.CERTIFICATE_STATUS_POLLING);
        KeyPair kp = generateKeyPair();
        Certificate cert = seedRequestedCertWithCsr(fixture, kp, "plain-issue-async");
        UUID certUuid = cert.getUuid();
        V3ConnectorStubs.stubV3IssueAsync(wireMockServer);

        // when
        clientOperationInternalService.issueCertificateAction(certUuid, true);

        // then
        Certificate after = reloadCert(certUuid);
        assertThat(after.getState())
                .as("Plain issue with an async v3 202 response must park the certificate in PENDING_ISSUE")
                .isEqualTo(CertificateState.PENDING_ISSUE);
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(V3_ISSUE_PATH)));

        long pollRows = pollRepository.findAll().stream()
                .filter(p -> certUuid.equals(p.getCertificateUuid()))
                .count();
        assertThat(pollRows)
                .as("Async plain issue with CERTIFICATE_STATUS_POLLING must schedule exactly one status-poll row")
                .isEqualTo(1L);
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

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    /**
     * Seeds a {@code REQUESTED} certificate with a real PKCS#10 CSR and <em>no</em> {@code CertificateRegistration} binding,
     * associated with the fixture's RA profile.
     */
    private Certificate seedRequestedCertWithCsr(AuthorityFixtures.Fixture fixture, KeyPair kp, String commonName)
            throws Exception {
        PKCS10CertificationRequest csr = AcmeTestUtil.createCsr(kp, commonName);
        String csrBase64 = Base64.getEncoder().encodeToString(csr.getEncoded());

        CertificateRequestEntity csrEntity = certificateRequestRepository.save(
                aCertificateRequest()
                        .withContent(csrBase64)
                        .withSubjectDn("CN=" + commonName)
                        .withPublicKeyAlgorithm("RSA")
                        .withSignatureAlgorithm("SHA256WithRSA")
                        .build());

        CertificateContent content = certificateContentRepository.save(aCertificateContent().build());

        return certificateRepository.save(
                aCertificate()
                        .withSubjectDn("CN=" + commonName)
                        .withCertificateContent(content)
                        .withCertificateContentId(content.getId())
                        .withState(CertificateState.REQUESTED)
                        .withValidationStatus(CertificateValidationStatus.NOT_CHECKED)
                        .withRaProfile(fixture.raProfile())
                        .withCertificateRequest(csrEntity)
                        .withCertificateRequestUuid(csrEntity.getUuid())
                        .build());
    }

    private Certificate reloadCert(UUID uuid) {
        return certificateRepository.findByUuid(uuid)
                .orElseThrow(() -> new AssertionError("Certificate not found: " + uuid));
    }
}
