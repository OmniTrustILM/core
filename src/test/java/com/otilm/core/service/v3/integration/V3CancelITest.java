package com.otilm.core.service.v3.integration;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.client.certificate.UploadCertificateRequestDto;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.v2.ClientOperationService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.AuthorityFixtures;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;

/**
 * Integration tests for cancel flows on v3 authorities.
 *
 * <p>Two distinct cancel paths are exercised:
 * <ol>
 *   <li><b>Operator cancel</b> ({@code cancelPendingCertificateOperation}) — routes through the
 *       <em>v2 cancel client</em> regardless of adapter version. The v3 adapter's
 *       {@code cancel()} is NOT involved here. HTTP status from the connector drives the
 *       exception-type mapping: 404 is a soft success (local cancel proceeds); 422 is a hard
 *       refusal ({@link ValidationException}, cert stays {@code PENDING_*}).
 *       This path is shared with v2; the tests here are a thin v3-authority smoke.</li>
 *   <li><b>Manual-issue cancel hook</b> ({@code manuallyIssueCertificate}) — after the operator
 *       uploads the issued certificate, the service fires a best-effort v3 adapter
 *       {@code cancel(ISSUE)} to tell the connector to abort the in-flight async operation.
 *       The {@code CancelResult} is discarded; a failure must not abort the issuance.</li>
 * </ol>
 */
public class V3CancelITest extends BaseSpringBootTest {

    // v3 issue/cancel path — used by cancelInFlightAsyncIssueBestEffort via v3 adapter cancel(ISSUE)
    private static final String V3_ISSUE_CANCEL_PATH = "/v3/authorityProvider/certificates/issue/cancel";

    // v2 cancel paths used by cancelPendingCertificateOperation via the v2 cancel client
    private static final String V2_ISSUE_CANCEL_PATTERN  = "/v2/authorityProvider/authorities/[^/]+/certificates/issue/cancel";
    private static final String V2_REVOKE_CANCEL_PATTERN = "/v2/authorityProvider/authorities/[^/]+/certificates/revoke/cancel";

    // v2 identify path used by manuallyIssueCertificate
    private static final String V2_IDENTIFY_PATTERN = "/v2/authorityProvider/authorities/[^/]+/certificates/identify";

    // ── Spring beans ──────────────────────────────────────────────────────────

    @Autowired
    private ClientOperationService clientOperationService;

    @MockitoSpyBean
    @SuppressWarnings("unused") // required by context; no spy interactions in this suite
    private ActionProducer actionProducer;

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRequestRepository certificateRequestRepository;

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
    }

    @AfterEach
    public void tearDownWireMock() {
        wireMockServer.stop();
    }

    // ── Step 1: Operator-cancel scenarios ─────────────────────────────────────

    /**
     * Operator cancel of a {@code PENDING_ISSUE} v3-authority cert: connector returns 404
     * (soft — not tracked) → local cancel proceeds → cert transitions to {@code FAILED}.
     */
    @Test
    public void operatorCancel_pendingIssue_softConnector404_transitionsToFailed() {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        Certificate cert = seedCertificate(fixture, CertificateState.PENDING_ISSUE);

        wireMockServer.stubFor(post(urlPathMatching(V2_ISSUE_CANCEL_PATTERN))
                .willReturn(aResponse().withStatus(404).withBody("not tracked")));

        Assertions.assertDoesNotThrow(() ->
                        clientOperationService.cancelPendingCertificateOperation(
                                SecuredParentUUID.fromUUID(fixture.authority().getUuid()),
                                fixture.raProfile().getSecuredUuid(),
                                cert.getUuid().toString(),
                                new CancelPendingCertificateRequestDto()),
                "Operator cancel with connector 404 must not throw (soft failure, local cancel proceeds)");

        Certificate after = reloadCert(cert.getUuid());
        Assertions.assertEquals(CertificateState.FAILED, after.getState(),
                "PENDING_ISSUE + connector 404 → cert must transition to FAILED");
    }

    /**
     * Operator cancel of a {@code PENDING_REVOKE} v3-authority cert: connector returns 404
     * (soft) → local cancel proceeds → cert reverts to {@code ISSUED}.
     */
    @Test
    public void operatorCancel_pendingRevoke_softConnector404_revertsToIssued() {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        Certificate cert = seedCertificate(fixture, CertificateState.PENDING_REVOKE);
        cert.setPendingRevokeDestroyKey(true);
        cert.setPendingRevokeAttributes(List.of());
        certificateRepository.save(cert);

        wireMockServer.stubFor(post(urlPathMatching(V2_REVOKE_CANCEL_PATTERN))
                .willReturn(aResponse().withStatus(404).withBody("not tracked")));

        Assertions.assertDoesNotThrow(() ->
                        clientOperationService.cancelPendingCertificateOperation(
                                SecuredParentUUID.fromUUID(fixture.authority().getUuid()),
                                fixture.raProfile().getSecuredUuid(),
                                cert.getUuid().toString(),
                                new CancelPendingCertificateRequestDto()),
                "Operator cancel with connector 404 on PENDING_REVOKE must not throw");

        Certificate after = reloadCert(cert.getUuid());
        Assertions.assertEquals(CertificateState.ISSUED, after.getState(),
                "PENDING_REVOKE + connector 404 → cert must revert to ISSUED");
    }

    /**
     * Operator cancel of a {@code PENDING_ISSUE} v3-authority cert: connector returns 422
     * (hard refusal) → {@link ValidationException} is thrown and the cert stays
     * {@code PENDING_ISSUE}.
     */
    @Test
    public void operatorCancel_pendingIssue_hardConnector422_throwsAndCertUnchanged() {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        Certificate cert = seedCertificate(fixture, CertificateState.PENDING_ISSUE);

        wireMockServer.stubFor(post(urlPathMatching(V2_ISSUE_CANCEL_PATTERN))
                .willReturn(aResponse()
                        .withStatus(422)
                        .withHeader("Content-Type", "application/json")
                        .withBody("[\"Issuance is past the point of no return\"]")));

        Assertions.assertThrows(ValidationException.class, () ->
                clientOperationService.cancelPendingCertificateOperation(
                        SecuredParentUUID.fromUUID(fixture.authority().getUuid()),
                        fixture.raProfile().getSecuredUuid(),
                        cert.getUuid().toString(),
                        new CancelPendingCertificateRequestDto()),
                "Operator cancel with connector 422 must throw ValidationException (hard refusal)");

        Certificate after = reloadCert(cert.getUuid());
        Assertions.assertEquals(CertificateState.PENDING_ISSUE, after.getState(),
                "Cert must stay PENDING_ISSUE after connector hard 422 refusal");
    }

    // ── Step 2: Manual-issue cancel-hook scenarios ────────────────────────────

    /**
     * Manual-issue cancel hook: after the operator uploads the issued certificate, the service
     * fires a best-effort v3 adapter {@code cancel(ISSUE)} at the connector. The hook fires
     * even though the certificate is already issued locally.
     *
     * <p>Assertion: the v3 issue-cancel endpoint ({@code /v3/authorityProvider/certificates/issue/cancel})
     * received exactly one request after {@code manuallyIssueCertificate} completes.</p>
     */
    @Test
    public void manualIssueHook_firesV3CancelOnce_whenConnectorReturns204() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        KeyPair kp = seedPendingIssueCertWithCsr(fixture);
        String certBase64 = buildSelfSignedCertBase64(kp, "v3-manual-cancel-hook");

        // v2 identify endpoint — required by manuallyIssueCertificate
        wireMockServer.stubFor(post(urlPathMatching(V2_IDENTIFY_PATTERN))
                .willReturn(WireMock.okJson("{\"meta\":[]}")));

        // v3 issue-cancel endpoint — the best-effort hook
        wireMockServer.stubFor(post(urlEqualTo(V3_ISSUE_CANCEL_PATH))
                .willReturn(aResponse().withStatus(204)));

        UploadCertificateRequestDto req = new UploadCertificateRequestDto();
        req.setCertificate(certBase64);
        req.setCustomAttributes(List.of());

        // Act: manuallyIssueCertificate issues locally and then fires the best-effort cancel hook
        Certificate certBefore = reloadCert(findCertUuidForFixture(fixture));
        SecuredUUID raProfileSecured = fixture.raProfile().getSecuredUuid();
        clientOperationService.manuallyIssueCertificate(
                SecuredParentUUID.fromUUID(fixture.authority().getUuid()),
                raProfileSecured,
                certBefore.getUuid().toString(),
                req);

        // The v3 cancel endpoint must have been called exactly once by the best-effort hook
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(V3_ISSUE_CANCEL_PATH)));
    }

    /**
     * Manual-issue cancel hook resilience: when the connector cancel endpoint returns 500, the
     * best-effort hook failure must be swallowed and {@code manuallyIssueCertificate} must still
     * complete. The certificate ends up in {@code ISSUED} state.
     */
    @Test
    public void manualIssueHook_doesNotBreakIssuance_whenConnectorReturns500() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        KeyPair kp = seedPendingIssueCertWithCsr(fixture);
        String certBase64 = buildSelfSignedCertBase64(kp, "v3-manual-cancel-resilience");

        // v2 identify endpoint
        wireMockServer.stubFor(post(urlPathMatching(V2_IDENTIFY_PATTERN))
                .willReturn(WireMock.okJson("{\"meta\":[]}")));

        // v3 issue-cancel: simulate connector error — the hook must swallow this
        wireMockServer.stubFor(post(urlEqualTo(V3_ISSUE_CANCEL_PATH))
                .willReturn(aResponse().withStatus(500)));

        UploadCertificateRequestDto req = new UploadCertificateRequestDto();
        req.setCertificate(certBase64);
        req.setCustomAttributes(List.of());

        Certificate certBefore = reloadCert(findCertUuidForFixture(fixture));
        SecuredUUID raProfileSecured = fixture.raProfile().getSecuredUuid();

        // Act: must complete without throwing even though the cancel hook encounters a 500
        Assertions.assertDoesNotThrow(() ->
                clientOperationService.manuallyIssueCertificate(
                        SecuredParentUUID.fromUUID(fixture.authority().getUuid()),
                        raProfileSecured,
                        certBefore.getUuid().toString(),
                        req),
                "manuallyIssueCertificate must complete even when the best-effort cancel hook returns 500");

        Certificate after = reloadCert(certBefore.getUuid());
        Assertions.assertEquals(CertificateState.ISSUED, after.getState(),
                "Certificate must reach ISSUED state despite the cancel hook failure");
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

    /**
     * Builds a v3 authority fixture bound to the per-test WireMock server. No feature flags are
     * needed for operator-cancel (the v2 cancel client path is flag-agnostic); the manual-issue
     * hook tests do not gate on flags either. A single fixture is used for each test.
     */
    private AuthorityFixtures.Fixture buildV3Fixture() {
        return AuthorityFixtures.v3Authority(repos(), wireMockServer);
    }

    /**
     * Creates and persists a minimal {@link Certificate} in the given state, associated with the
     * fixture's RA profile. For PENDING_REVOKE the cert includes a stub CertificateContent so the
     * service can read it.
     */
    private Certificate seedCertificate(AuthorityFixtures.Fixture fixture, CertificateState state) {
        CertificateContent content = certificateContentRepository.save(new CertificateContent());

        Certificate cert = new Certificate();
        cert.setSubjectDn("CN=cancel-test-" + UUID.randomUUID());
        cert.setIssuerDn("CN=test-issuer");
        cert.setSerialNumber(UUID.randomUUID().toString());
        cert.setCertificateContent(content);
        cert.setCertificateContentId(content.getId());
        cert.setState(state);
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        cert.setRaProfile(fixture.raProfile());
        return certificateRepository.save(cert);
    }

    /**
     * Seeds a PENDING_ISSUE certificate with a real PKCS#10 CSR, as required by
     * {@code manuallyIssueCertificate}. Returns the key pair so the caller can build a
     * matching certificate.
     */
    private KeyPair seedPendingIssueCertWithCsr(AuthorityFixtures.Fixture fixture) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=v3-manual-issue");
        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);
        String csrBase64 = Base64.getEncoder().encodeToString(csr.getEncoded());

        CertificateRequestEntity csrEntity = new CertificateRequestEntity();
        csrEntity.setContent(csrBase64);
        csrEntity.setCertificateRequestFormat(CertificateRequestFormat.PKCS10);
        csrEntity.setSubjectDn("CN=v3-manual-issue");
        csrEntity.setPublicKeyAlgorithm("RSA");
        csrEntity.setSignatureAlgorithm("SHA256WithRSA");
        certificateRequestRepository.save(csrEntity);

        Certificate cert = seedCertificate(fixture, CertificateState.PENDING_ISSUE);
        cert.setCertificateRequest(csrEntity);
        cert.setCertificateRequestUuid(csrEntity.getUuid());
        certificateRepository.save(cert);

        return kp;
    }

    /**
     * Finds the UUID of the certificate seeded for the given fixture. Used when the cert UUID is
     * not tracked by the caller directly (e.g. after {@link #seedPendingIssueCertWithCsr}).
     */
    private UUID findCertUuidForFixture(AuthorityFixtures.Fixture fixture) {
        return certificateRepository.findAll().stream()
                .filter(c -> fixture.raProfile().equals(c.getRaProfile()))
                .filter(c -> c.getState() == CertificateState.PENDING_ISSUE)
                .map(Certificate::getUuid)
                .findFirst()
                .orElseThrow(() -> new AssertionError("No PENDING_ISSUE certificate found for fixture RA profile"));
    }

    /** Builds a self-signed X.509 certificate matching the given key pair; returns base64-DER. */
    private String buildSelfSignedCertBase64(KeyPair kp, String cn) throws Exception {
        X500Name name = new X500Name("CN=" + cn);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(name, BigInteger.ONE, notBefore, notAfter, name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        X509Certificate x509 = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        return Base64.getEncoder().encodeToString(x509.getEncoded());
    }

    private Certificate reloadCert(UUID uuid) {
        return certificateRepository.findByUuid(uuid)
                .orElseThrow(() -> new AssertionError("Certificate not found: " + uuid));
    }
}
