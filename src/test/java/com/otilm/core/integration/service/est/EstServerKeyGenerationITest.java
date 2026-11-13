package com.otilm.core.integration.service.est;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.messaging.jms.listeners.ActionsListener;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.service.est.EstExternalService;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.QueuedMessageDelivery;
import com.otilm.core.util.builders.EstProfileBuilder;
import com.otilm.core.util.builders.V3ConnectorStubs;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.mocks.CertifyingIssueTransformer;
import com.otilm.core.util.seeders.ApprovalProfileSeeder;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.CertificateRequestPolicySeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import com.otilm.core.util.seeders.SecretSeeder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.awaitility.Awaitility;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicCredentials;
import static com.otilm.core.util.EstServerKeyGenerationAnswers.certificateOf;
import static com.otilm.core.util.EstServerKeyGenerationAnswers.isKeyOf;
import static com.otilm.core.util.EstServerKeyGenerationAnswers.keyOf;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static com.otilm.core.util.seeders.CertificateRegistrationSeeder.CHALLENGE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code /serverkeygen} in memory through the service, against a connector double that certifies the request it is sent
 * at once. The mocked {@link ActionProducer} hands each queued message to the real {@link ActionsListener} through
 * {@link QueuedMessageDelivery}, as the broker consumer would.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class EstServerKeyGenerationITest extends BaseSpringBootTest {

    private static final String ESTPROFILE_NAME = "devices-profile";
    private static final String RA_PROFILE_NAME = "devices-ra";
    private static final String USERNAME = "device-owner";
    private static final String PASSWORD = "s3cret";
    private static final String CLIENT_SUBJECT = "CN=device-1";
    private static final UUID APPROVER_UUID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static final String V3_ISSUE_CANCEL_PATH = "/v3/authorityProvider/certificates/issue/cancel";
    private static final String ECDSA_SIGNATURE = "SHA256withECDSA";
    private static final String V3_ISSUE_PATH = "/v3/authorityProvider/certificates/issue";
    private static final Duration ANSWER_TIMEOUT = Duration.ofSeconds(30);
    /** A key generation answers a timeout within moments, so a test of it does not wait the default 30 s. */
    private static final int SERVER_KEY_GENERATION_TIMEOUT_SECONDS = 5;

    @Autowired
    private EstExternalService estService;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private SecretSeeder secrets;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private CertificateRequestPolicySeeder requestPolicies;

    @Autowired
    private ApprovalProfileSeeder approvals;

    @Autowired
    private QueuedMessageDelivery delivery;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateProtocolAssociationRepository protocolAssociations;

    @Autowired
    private CryptographicKeyRepository keyRepository;

    private final ExecutorService requestThread = Executors.newSingleThreadExecutor();
    private WireMockServer authService;
    private WireMockServer connector;

    @BeforeEach
    void startAuthServiceAndAConnectorThatCertifiesEveryRequest() {
        authService = AuthServiceWireMockStubs.startImpersonating(UUID.randomUUID(), "est-user");
        connector = LoopbackWireMock.start(new CertifyingIssueTransformer(PkiFixtures.rootCa("EST Issuing Root")));
        AuthorityV2ConnectorStubs.on(connector).stubIssueCertifyingTheRequest().stubIssueAttributeValidation();
        delivery.deliverQueuedActions();
    }

    @AfterEach
    void stopTheRequestThreadAndServers() throws InterruptedException {
        requestThread.shutdownNow();
        if (!requestThread.awaitTermination(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
            throw new IllegalStateException("The key generation request did not stop");
        }
        authService.stop();
        connector.stop();
    }

    @Test
    void answersWithAKeyOfTheIssuedCertificate_whenTheConnectorIssuesAtOnce() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME), true);

        // when
        ResponseEntity<byte[]> response = generate(EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT),
                basicCredentials(USERNAME, PASSWORD));

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        X509Certificate delivered = certificateOf(response);
        assertThat(isKeyOf(keyOf(response), delivered, ECDSA_SIGNATURE)).isTrue();
        Certificate inventory = theOnlyCertificate();
        assertThat(inventory.getState()).isEqualTo(CertificateState.ISSUED);
        assertThat(inventory.getFingerprint()).isEqualTo(CertificateUtil.getThumbprint(delivered));
        assertThat(protocolAssociations.findAll()).singleElement().satisfies(attribution -> {
            assertThat(attribution.getCertificateUuid()).isEqualTo(inventory.getUuid());
            assertThat(attribution.getProtocol()).isEqualTo(CertificateProtocol.EST);
            assertThat(attribution.getProtocolProfileUuid()).isEqualTo(estProfile.getUuid());
        });
    }

    @Test
    void answersWithAKeyOfTheIssuedCertificate_whenTheClientKeyIsMlDsa() throws Exception {
        // given
        seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME), true);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA-44", BouncyCastleProvider.PROVIDER_NAME);
        var mlDsaClientKey = SubjectPublicKeyInfo.getInstance(generator.generateKeyPair().getPublic().getEncoded());

        // when
        ResponseEntity<byte[]> response = generate(EstCsrFixtures.requestBodyWithPublicKey(mlDsaClientKey),
                basicCredentials(USERNAME, PASSWORD));

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        X509Certificate delivered = certificateOf(response);
        assertThat(isKeyOf(keyOf(response), delivered, "ML-DSA")).isTrue();
        assertThat(theOnlyCertificate().getFingerprint()).isEqualTo(CertificateUtil.getThumbprint(delivered));
    }

    @Test
    void completesThePreRegistration_whenTheClientIsIdentifiedByItsRegistration() throws Exception {
        // given
        RaProfile raProfile = routes.seedRaProfile(connector, RA_PROFILE_NAME);
        saveProfile(anEstProfile()
                .withName(ESTPROFILE_NAME)
                .withEnabled(true)
                .withRaProfile(raProfile)
                .withAuthenticationPolicy(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION)
                .withServerKeyGeneration(true));
        Certificate registration = registrations.seedRegistration(raProfile, CLIENT_SUBJECT);
        EstClientCredentials credentials = basicCredentials(registration.getUuid().toString(), CHALLENGE);

        // when
        ResponseEntity<byte[]> response = generate(EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT), credentials);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(isKeyOf(keyOf(response), certificateOf(response), ECDSA_SIGNATURE)).isTrue();
        assertThat(theOnlyCertificate()).satisfies(certificate -> {
            assertThat(certificate.getUuid()).isEqualTo(registration.getUuid());
            assertThat(certificate.getState()).isEqualTo(CertificateState.ISSUED);
        });
    }

    @Test
    void refusesAsUnavailableWithoutCertificateOrKey_whenTheRaProfileAsksForAnApproval() throws Exception {
        // given
        RaProfile raProfile = routes.seedRaProfile(connector, RA_PROFILE_NAME);
        seedRaBasicProfile(raProfile, true);
        approvals.requireApproval(raProfile, APPROVER_UUID);
        byte[] request = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);

        // when
        ThrowingCallable generate = () -> generate(request, basicCredentials(USERNAME, PASSWORD));

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.SERVER_KEYGEN_UNAVAILABLE));
        assertThat(certificateRepository.count()).isZero();
        assertThat(keyRepository.count()).isZero();
    }

    @Test
    void refusesAsNotEnabled_whenTheEstProfileDoesNotGenerateKeys() throws Exception {
        // given
        seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME), false);
        byte[] request = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);

        // when
        ThrowingCallable generate = () -> generate(request, basicCredentials(USERNAME, PASSWORD));

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.SERVER_KEYGEN_DISABLED));
        assertThat(certificateRepository.count()).isZero();
    }

    @Test
    void refusesAsRejected_whenComplianceRejectsTheGeneratedKey() throws Exception {
        // given — the generated key is an elliptic curve key, like the client's
        RaProfile raProfile = routes.seedRaProfile(connector, RA_PROFILE_NAME);
        seedRaBasicProfile(raProfile, true);
        requestPolicies.requireRsaRequests(raProfile);
        byte[] request = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);

        // when
        ThrowingCallable generate = () -> generate(request, basicCredentials(USERNAME, PASSWORD));

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.REQUEST_REJECTED));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.REJECTED);
    }

    @Test
    void refusesAsFailed_whenTheConnectorCannotIssue() throws Exception {
        // given
        seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME), true);
        AuthorityV2ConnectorStubs.on(connector).stubIssueFailure();
        byte[] request = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);

        // when
        ThrowingCallable generate = () -> generate(request, basicCredentials(USERNAME, PASSWORD));

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_FAILED));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.FAILED);
    }

    @Test
    void answersWithAKeyOfTheIssuedCertificate_whenTheStatusPollIssuesWithinTheBound() throws Exception {
        // given
        seedRaBasicProfile(seedAsyncV3RaProfile(), true);
        byte[] request = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);
        Future<ResponseEntity<byte[]>> generation = generateInTheBackground(request);
        UUID certificateUuid = awaitPendingIssue();
        V3ConnectorStubs.stubIssueStatusCompleted(connector, base64(certificateForTheIssuedRequest()));

        // when
        delivery.pollStatus(certificateUuid, CertificateOperation.ISSUE);

        // then
        ResponseEntity<byte[]> response = generation.get(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(isKeyOf(keyOf(response), certificateOf(response), ECDSA_SIGNATURE)).isTrue();
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.ISSUED);
        connector.verify(0, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH)));
    }

    @Test
    void cancelsTheIssueAndRefusesAsTimedOut_whenNoPollIssuesWithinTheBound() throws Exception {
        // given — nothing runs the status poll, so the certificate stays PENDING_ISSUE until the bound of the test
        // configuration passes
        seedRaBasicProfile(seedAsyncV3RaProfile(), true);
        connector
                .stubFor(WireMock
                        .post(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH))
                        .willReturn(WireMock.aResponse().withStatus(204)));
        byte[] request = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);

        // when
        ThrowingCallable generate = () -> generate(request, basicCredentials(USERNAME, PASSWORD));

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.FAILED);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH)));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ResponseEntity<byte[]> generate(byte[] request, EstClientCredentials credentials) {
        return estService.serverKeyGeneration(ESTPROFILE_NAME, request, credentials);
    }

    /** Generates on another thread as the user that the test is authenticated as, while the test runs the poll. */
    private Future<ResponseEntity<byte[]>> generateInTheBackground(byte[] request) {
        SecurityContext testContext = SecurityContextHolder.getContext();
        return requestThread.submit(() -> {
            SecurityContextHolder.setContext(testContext);
            try {
                return generate(request, basicCredentials(USERNAME, PASSWORD));
            } finally {
                SecurityContextHolder.clearContext();
            }
        });
    }

    private UUID awaitPendingIssue() {
        return Awaitility
                .await()
                .atMost(ANSWER_TIMEOUT)
                .until(() -> certificateRepository
                        .findAll()
                        .stream()
                        .filter(certificate -> certificate.getState() == CertificateState.PENDING_ISSUE)
                        .map(Certificate::getUuid)
                        .findFirst(), Optional::isPresent)
                .orElseThrow();
    }

    /** A certificate of the authority for the request that the v3 issue carried. */
    private X509Certificate certificateForTheIssuedRequest() throws Exception {
        LoggedRequest issue = connector
                .findAll(WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_PATH)))
                .getFirst();
        String requestBase64 = new ObjectMapper().readTree(issue.getBodyAsString()).path("request").asText();
        JcaPKCS10CertificationRequest issued = new JcaPKCS10CertificationRequest(
                Base64.getMimeDecoder().decode(requestBase64));
        Instant now = Instant.now();
        return PkiFixtures
                .clientCertificateFor(PkiFixtures.rootCa("EST Async Root"), new KeyPair(issued.getPublicKey(), null),
                        now.minus(Duration.ofMinutes(1)), now.plus(Duration.ofDays(1)), CLIENT_SUBJECT);
    }

    private RaProfile seedAsyncV3RaProfile() {
        RaProfile raProfile = routes
                .seedRaProfileOnV3Authority(connector, RA_PROFILE_NAME, FeatureFlag.CERTIFICATE_STATUS_POLLING);
        V3ConnectorStubs.stubAttributesAndValidate(connector);
        V3ConnectorStubs.stubV3IssueAsync(connector);
        return raProfile;
    }

    private static String base64(X509Certificate certificate) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    private EstProfile seedRaBasicProfile(RaProfile raProfile, boolean serverKeyGeneration) {
        Secret credential = secrets.seedBasicAuthSecret("ra-credential", USERNAME, PASSWORD);
        return saveProfile(anEstProfile()
                .withName(ESTPROFILE_NAME)
                .withEnabled(true)
                .withRaProfile(raProfile)
                .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                .withBasicCredentialSecrets(credential.getUuid())
                .withServerKeyGeneration(serverKeyGeneration)
                .withServerKeyGenerationTimeout(SERVER_KEY_GENERATION_TIMEOUT_SECONDS));
    }

    private EstProfile saveProfile(EstProfileBuilder profile) {
        return estProfileRepository.save(profile.build());
    }

    private Certificate theOnlyCertificate() {
        List<Certificate> all = certificateRepository.findAll();
        assertThat(all).hasSize(1);
        return all.getFirst();
    }

    private static void assertRefusal(Throwable thrown, EstError error) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(error);
            assertThat(refusal.realm()).contains(ESTPROFILE_NAME);
        });
    }
}
