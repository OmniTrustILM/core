package com.otilm.core.integration.service.est;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyExportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.Pkcs8Envelopes;
import com.otilm.core.messaging.jms.listeners.ActionsListener;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.ExportedKeyMaterial;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.CryptographicKeyExportExternalService;
import com.otilm.core.service.est.EstExternalService;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.v2.ClientOperationExternalService;
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
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.CertificateRequestPolicySeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import com.otilm.core.util.seeders.SecretSeeder;
import com.otilm.core.util.seeders.TokenProfileSeeder;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.awaitility.Awaitility;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
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
 * {@code /serverkeygen} with key recovery through the service: the key is created on a v2 token double that signs with
 * a key the test holds and exports that key under the passphrase it is sent, and an authority double certifies the
 * request it is sent at once. The mocked {@link ActionProducer} hands each queued message to the real
 * {@link ActionsListener} through {@link QueuedMessageDelivery}, as the broker consumer would.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class EstServerKeyGenerationKeyRecoveryITest extends BaseSpringBootTest {

    private static final String ESTPROFILE_NAME = "recovery-profile";
    private static final String RA_PROFILE_NAME = "recovery-ra";
    private static final String USERNAME = "device-owner";
    private static final String PASSWORD = "s3cret";
    private static final String CLIENT_SUBJECT = "CN=device-1";
    private static final String ECDSA_SIGNATURE = "SHA256withECDSA";
    private static final int P256_LENGTH = 256;
    private static final int KEY_PAIR_ITEMS = 2;
    private static final Duration ANSWER_TIMEOUT = Duration.ofSeconds(30);
    /** A key generation answers a timeout within moments, so a test of it does not wait the default 30 s. */
    private static final int SERVER_KEY_GENERATION_TIMEOUT_SECONDS = 5;
    private static final String V3_ISSUE_CANCEL_PATH = "/v3/authorityProvider/certificates/issue/cancel";
    private static final String NOT_TRACKED_PROBLEM = """
            {"type":"about:blank","title":"Unprocessable Content","status":422,"detail":"No tracked issuance","errorCode":"OPERATION_NOT_TRACKED"}
            """;

    @Autowired
    private EstExternalService estService;

    @Autowired
    private CryptographicKeyExportExternalService keyExportService;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private TokenProfileSeeder tokenProfiles;

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private SecretSeeder secrets;

    @Autowired
    private CertificateRequestPolicySeeder requestPolicies;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private QueuedMessageDelivery delivery;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CryptographicKeyRepository keyRepository;

    @Autowired
    private CryptographicKeyItemRepository keyItemRepository;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    @Autowired
    private ClientOperationExternalService clientOperationService;

    private final ExecutorService requestThread = Executors.newSingleThreadExecutor();

    private final KeyPair tokenKeyPair = PkiFixtures.keyPair();
    private WireMockServer authService;
    private WireMockServer authority;
    private CryptographyProviderV2ConnectorMock token;
    private TokenProfile tokenProfile;

    @BeforeEach
    void startServersAndAnExportingToken() throws Exception {
        authService = AuthServiceWireMockStubs.startImpersonating(UUID.randomUUID(), "est-user");
        authority = LoopbackWireMock.start(new CertifyingIssueTransformer(PkiFixtures.rootCa("EST Recovery Root")));
        AuthorityV2ConnectorStubs.on(authority).stubIssueCertifyingTheRequest().stubIssueAttributeValidation();
        token = connectorMockFactory.startCryptographyProviderV2();
        token
                .stubCreateKeyPair(tokenKeyPair.getPublic(), KeyAlgorithm.ECDSA, P256_LENGTH)
                .stubExportableKeyTypes(KeyRequestType.KEY_PAIR, KeyAlgorithm.ECDSA)
                .stubSignatureAlgorithmAttribute(SignatureAlgorithm.SHA256_WITH_ECDSA)
                .stubRealSigning(tokenKeyPair.getPrivate(), SignatureAlgorithm.SHA256_WITH_ECDSA)
                .stubExportKeyAttributes("[]")
                .stubExportOf(tokenKeyPair, KeyAlgorithm.ECDSA, P256_LENGTH)
                .stubDestroyKey();
        tokenProfile = tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);
        delivery.deliverQueuedActions();
    }

    @AfterEach
    void stopTheRequestThreadAndServers() throws InterruptedException {
        requestThread.shutdownNow();
        if (!requestThread.awaitTermination(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
            throw new IllegalStateException("The key generation request did not stop");
        }
        authService.stop();
        authority.stop();
        token.stop();
    }

    @Test
    void answersWithTheTokenKeyAndItsCertificate_whenTheAuthorityIssuesAtOnce() throws Exception {
        // given
        seedRecoveringProfile(routes.seedRaProfile(authority, RA_PROFILE_NAME));

        // when
        ResponseEntity<byte[]> response = generate();

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        X509Certificate delivered = certificateOf(response);
        assertThat(isKeyOf(keyOf(response), delivered, ECDSA_SIGNATURE)).isTrue();
        assertThat(delivered.getPublicKey().getEncoded()).isEqualTo(tokenKeyPair.getPublic().getEncoded());
        Certificate inventory = theOnlyCertificate();
        assertThat(inventory.getState()).isEqualTo(CertificateState.ISSUED);
        assertThat(inventory.getFingerprint()).isEqualTo(CertificateUtil.getThumbprint(delivered));
    }

    @Test
    void keepsTheKeyLinkedToTheCertificateForTheKeyExport_whenTheKeyIsDelivered() throws Exception {
        // given
        seedRecoveringProfile(routes.seedRaProfile(authority, RA_PROFILE_NAME));
        generate();
        CryptographicKey key = theOnlyKey();
        char[] operatorPassphrase = "an operator's passphrase".toCharArray();

        // when
        ExportedKeyMaterial recovered = keyExportService
                .exportKey(key.getUuid(), privateItemOf(key).getUuid(), exportRequest(operatorPassphrase));

        // then
        assertThat(theOnlyCertificate().getKeyUuid()).isEqualTo(key.getUuid());
        PrivateKeyInfo recoveredKey = Pkcs8Envelopes
                .decrypt(recovered.encryptedPrivateKeyInfo(), new Passphrase(operatorPassphrase),
                        DerivationBudget.forFile());
        assertThat(recoveredKey.getEncoded()).isEqualTo(tokenKeyPair.getPrivate().getEncoded());
        token.verifyDestroyKeyRequests(0);
    }

    @Test
    void completesThePreRegistrationWithTheTokenKey_whenTheClientIsIdentifiedByItsRegistration() throws Exception {
        // given
        RaProfile raProfile = routes.seedRaProfile(authority, RA_PROFILE_NAME);
        estProfileRepository
                .save(recoveringProfile(raProfile)
                        .withAuthenticationPolicy(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION)
                        .build());
        Certificate registration = registrations.seedRegistration(raProfile, CLIENT_SUBJECT);
        EstClientCredentials credentials = basicCredentials(registration.getUuid().toString(), CHALLENGE);

        // when
        ResponseEntity<byte[]> response = estService
                .serverKeyGeneration(ESTPROFILE_NAME, EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT), credentials);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(isKeyOf(keyOf(response), certificateOf(response), ECDSA_SIGNATURE)).isTrue();
        assertThat(theOnlyCertificate()).satisfies(certificate -> {
            assertThat(certificate.getUuid()).isEqualTo(registration.getUuid());
            assertThat(certificate.getState()).isEqualTo(CertificateState.ISSUED);
            assertThat(certificate.getKeyUuid()).isEqualTo(theOnlyKey().getUuid());
        });
        token.verifyDestroyKeyRequests(0);
    }

    @Test
    void refusesTheRegistrationAndDestroysTheKeyOnce_whenTheChallengeIsWrong() throws Exception {
        // given
        RaProfile raProfile = routes.seedRaProfile(authority, RA_PROFILE_NAME);
        estProfileRepository
                .save(recoveringProfile(raProfile)
                        .withAuthenticationPolicy(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION)
                        .build());
        Certificate registration = registrations.seedRegistration(raProfile, CLIENT_SUBJECT);
        EstClientCredentials wrongChallenge = basicCredentials(registration.getUuid().toString(), "not-the-challenge");

        // when
        ThrowingCallable generate = () -> estService
                .serverKeyGeneration(ESTPROFILE_NAME, EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT), wrongChallenge);

        // then
        assertThatThrownBy(generate).isInstanceOf(EstException.class);
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.REGISTERED);
        assertTheKeyIsDestroyedOnce();
    }

    @Test
    void refusesAsUnavailableAndDestroysTheKeyOnce_whenTheTokenCannotSignTheRequest() throws Exception {
        // given
        seedRecoveringProfile(routes.seedRaProfile(authority, RA_PROFILE_NAME));
        token.stubOperationError("sign");

        // when
        ThrowingCallable generate = this::generate;

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE));
        assertThat(certificateRepository.count()).isZero();
        assertTheKeyIsDestroyedOnce();
    }

    @Test
    void refusesAsRejectedAndDestroysTheKeyOnce_whenComplianceRejectsTheKey() throws Exception {
        // given — the token key is an elliptic curve key
        RaProfile raProfile = routes.seedRaProfile(authority, RA_PROFILE_NAME);
        seedRecoveringProfile(raProfile);
        requestPolicies.requireRsaRequests(raProfile);

        // when
        ThrowingCallable generate = this::generate;

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.REQUEST_REJECTED));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.REJECTED);
        assertTheKeyIsDestroyedOnce();
    }

    @Test
    void refusesAsFailedAndKeepsTheKeyLinkedToTheCertificate_whenTheAuthorityCannotIssue() throws Exception {
        // given
        seedRecoveringProfile(routes.seedRaProfile(authority, RA_PROFILE_NAME));
        AuthorityV2ConnectorStubs.on(authority).stubIssueFailure();

        // when
        ThrowingCallable generate = this::generate;

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_FAILED));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.FAILED);
        assertTheKeyIsKeptLinkedToTheCertificate();
    }

    @Test
    void refusesAsFailedAndKeepsTheKey_whenAnOperatorCancelsTheIssueThatTheAuthorityFailsToCancel() throws Exception {
        // given — nothing runs the status poll, so the request waits in PENDING_ISSUE until the operator cancels it
        RaProfile raProfile = seedAsyncV3RaProfile();
        seedRecoveringProfile(raProfile);
        authority
                .stubFor(WireMock
                        .post(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH))
                        .willReturn(WireMock.aResponse().withStatus(500)));
        Future<ResponseEntity<byte[]>> generation = generateInTheBackground();
        Certificate pending = awaitPendingIssue();

        // when
        clientOperationService
                .cancelPendingCertificateOperation(
                        SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()),
                        raProfile.getSecuredUuid(), pending.getUuid().toString(),
                        new CancelPendingCertificateRequestDto());

        // then
        assertThatThrownBy(() -> generation.get(ANSWER_TIMEOUT.toSeconds(), TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .satisfies(thrown -> assertRefusal(thrown.getCause(), EstError.ISSUANCE_FAILED));
        authority.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH)));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.FAILED);
        assertTheKeyIsKeptLinkedToTheCertificate();
    }

    @Test
    void cancelsTheIssueAndDestroysTheKeyOnce_whenNoPollIssuesWithinTheBound() throws Exception {
        // given — nothing runs the status poll, so the certificate stays PENDING_ISSUE until the bound of the test
        // configuration passes
        seedRecoveringProfile(seedAsyncV3RaProfile());
        authority
                .stubFor(WireMock
                        .post(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH))
                        .willReturn(WireMock.aResponse().withStatus(204)));

        // when
        ThrowingCallable generate = this::generate;

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.FAILED);
        authority.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH)));
        assertTheKeyIsDestroyedOnce();
    }

    @Test
    void destroysTheKeyOnce_whenTheAuthorityDoesNotTrackTheTimedOutIssue() throws Exception {
        // given
        seedRecoveringProfile(seedAsyncV3RaProfile());
        authority
                .stubFor(WireMock
                        .post(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(422)
                                .withHeader("Content-Type", "application/problem+json")
                                .withBody(NOT_TRACKED_PROBLEM)));

        // when
        ThrowingCallable generate = this::generate;

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.FAILED);
        assertTheKeyIsDestroyedOnce();
    }

    @Test
    void keepsTheKeyLinkedToTheCertificate_whenTheAuthorityFailsTheCancelOfTheTimedOutIssue() throws Exception {
        // given
        seedRecoveringProfile(seedAsyncV3RaProfile());
        authority
                .stubFor(WireMock
                        .post(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH))
                        .willReturn(WireMock.aResponse().withStatus(500)));

        // when
        ThrowingCallable generate = this::generate;

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.FAILED);
        assertTheKeyIsKeptLinkedToTheCertificate();
    }

    @Test
    void refusesAsUnavailableAndKeepsTheKey_whenTheAuthorityRedirectsTheCancelOfTheTimedOutIssue() throws Exception {
        // given
        seedRecoveringProfile(seedAsyncV3RaProfile());
        authority
                .stubFor(WireMock
                        .post(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(302)
                                .withHeader("Location", "https://gateway.invalid/login")));

        // when
        ThrowingCallable generate = this::generate;

        // then
        assertThatThrownBy(generate).satisfies(thrown -> {
            assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT);
            assertThat(((EstException) thrown).error().status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        });
        assertThat(theOnlyCertificate().getKeyUuid()).isEqualTo(theOnlyKey().getUuid());
        token.verifyDestroyKeyRequests(0);
        assertThat(keyItemRepository.findByKeyUuidIn(List.of(theOnlyKey().getUuid())))
                .noneSatisfy(item -> assertThat(item.getState()).isEqualTo(KeyState.DESTROYED));
    }

    @Test
    void refusesAsInternalErrorAndKeepsTheCertificateAndKey_whenTheExportedKeyIsNotTheCertifiedKey() throws Exception {
        // given
        seedRecoveringProfile(routes.seedRaProfile(authority, RA_PROFILE_NAME));
        token
                .stubExportOf(PkiFixtures.keyPair().getPrivate(), tokenKeyPair.getPublic(), KeyAlgorithm.ECDSA,
                        P256_LENGTH);

        // when
        ThrowingCallable generate = this::generate;

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.INTERNAL_ERROR));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.ISSUED);
        assertThat(theOnlyCertificate().getKeyUuid()).isEqualTo(theOnlyKey().getUuid());
        token.verifyDestroyKeyRequests(0);
    }

    @Test
    void refusesAsUnavailableWithoutKeyOrCertificate_whenTheUserMayNotCreateKeys() throws Exception {
        // given
        seedRecoveringProfile(routes.seedRaProfile(authority, RA_PROFILE_NAME));
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.CREATE);

        // when
        ThrowingCallable generate = this::generate;

        // then
        assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE));
        assertThat(keyRepository.count()).isZero();
        assertThat(certificateRepository.count()).isZero();
        token.verifyCreateKeyRequests(0);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ResponseEntity<byte[]> generate() throws Exception {
        return estService
                .serverKeyGeneration(ESTPROFILE_NAME, EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT),
                        basicCredentials(USERNAME, PASSWORD));
    }

    /** Generates on another thread as the user that the test is authenticated as, while the test acts meanwhile. */
    private Future<ResponseEntity<byte[]>> generateInTheBackground() {
        SecurityContext testContext = SecurityContextHolder.getContext();
        return requestThread.submit(() -> {
            SecurityContextHolder.setContext(testContext);
            try {
                return generate();
            } finally {
                SecurityContextHolder.clearContext();
            }
        });
    }

    private Certificate awaitPendingIssue() {
        return Awaitility
                .await()
                .atMost(ANSWER_TIMEOUT)
                .until(() -> certificateRepository
                        .findAll()
                        .stream()
                        .filter(certificate -> certificate.getState() == CertificateState.PENDING_ISSUE)
                        .findFirst(), Optional::isPresent)
                .orElseThrow();
    }

    private void seedRecoveringProfile(RaProfile raProfile) {
        Secret credential = secrets.seedBasicAuthSecret("ra-credential", USERNAME, PASSWORD);
        estProfileRepository
                .save(recoveringProfile(raProfile)
                        .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                        .withBasicCredentialSecrets(credential.getUuid())
                        .build());
    }

    private EstProfileBuilder recoveringProfile(RaProfile raProfile) {
        return anEstProfile()
                .withName(ESTPROFILE_NAME)
                .withEnabled(true)
                .withRaProfile(raProfile)
                .withServerKeyGeneration(true)
                .withServerKeyGenerationTimeout(SERVER_KEY_GENERATION_TIMEOUT_SECONDS)
                .withKeyRecovery(true)
                .withKeyRecoveryTokenProfile(tokenProfile);
    }

    private RaProfile seedAsyncV3RaProfile() {
        RaProfile raProfile = routes
                .seedRaProfileOnV3Authority(authority, RA_PROFILE_NAME, FeatureFlag.CERTIFICATE_STATUS_POLLING);
        V3ConnectorStubs.stubAttributesAndValidate(authority);
        V3ConnectorStubs.stubV3IssueAsync(authority);
        return raProfile;
    }

    private static KeyExportRequestDto exportRequest(char[] passphrase) {
        KeyExportRequestDto request = new KeyExportRequestDto();
        request.setPassphrase(new Passphrase(passphrase));
        request.setExportAttributes(List.of());
        return request;
    }

    private Certificate theOnlyCertificate() {
        List<Certificate> all = certificateRepository.findAll();
        assertThat(all).hasSize(1);
        return all.getFirst();
    }

    private CryptographicKey theOnlyKey() {
        List<CryptographicKey> all = keyRepository.findAll();
        assertThat(all).hasSize(1);
        return all.getFirst();
    }

    private CryptographicKeyItem privateItemOf(CryptographicKey key) {
        return keyItemRepository
                .findByKeyUuidIn(List.of(key.getUuid()))
                .stream()
                .filter(item -> item.getType() == KeyType.PRIVATE_KEY)
                .findFirst()
                .orElseThrow();
    }

    /** No destroy reached the token, no item of the key is destroyed, and the certificate still names the key. */
    private void assertTheKeyIsKeptLinkedToTheCertificate() {
        UUID keyUuid = theOnlyKey().getUuid();
        token.verifyDestroyKeyRequests(0);
        assertThat(keyItemRepository.findByKeyUuidIn(List.of(keyUuid)))
                .noneSatisfy(item -> assertThat(item.getState()).isEqualTo(KeyState.DESTROYED));
        assertThat(theOnlyCertificate().getKeyUuid()).isEqualTo(keyUuid);
    }

    /** The key is destroyed by one destroy of each item of its pair, and every item ends destroyed. */
    private void assertTheKeyIsDestroyedOnce() {
        token.verifyDestroyKeyRequests(KEY_PAIR_ITEMS);
        assertThat(keyItemRepository.findByKeyUuidIn(List.of(theOnlyKey().getUuid())))
                .hasSize(KEY_PAIR_ITEMS)
                .allSatisfy(item -> assertThat(item.getState()).isEqualTo(KeyState.DESTROYED));
    }

    private static void assertRefusal(Throwable thrown, EstError error) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(error);
            assertThat(refusal.realm()).contains(ESTPROFILE_NAME);
        });
    }
}
