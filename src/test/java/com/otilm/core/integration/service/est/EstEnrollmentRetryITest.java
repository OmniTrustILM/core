package com.otilm.core.integration.service.est;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.messaging.jms.listeners.ActionsListener;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.est.EstExternalService;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.ConcurrentCalls;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.QueuedMessageDelivery;
import com.otilm.core.util.WireMockPorts;
import com.otilm.core.util.WireMockResponseGate;
import com.otilm.core.util.builders.V3ConnectorStubs;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.seeders.ApprovalProfileSeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import com.otilm.core.util.seeders.SecretSeeder;
import com.zaxxer.hikari.HikariDataSource;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicCredentials;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.awaitility.Awaitility.await;

/**
 * Retries of {@code /simpleenroll} through the service: an identical request is answered from the certificate the first
 * one created, which only the database remembers. The mocked {@link ActionProducer} hands each queued message to the
 * real {@link ActionsListener} through {@link QueuedMessageDelivery}, as the broker consumer would.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class EstEnrollmentRetryITest extends BaseSpringBootTest {

    private static final String ESTPROFILE_NAME = "devices-profile";
    private static final String RA_PROFILE_NAME = "devices-ra";
    private static final String USERNAME = "device-owner";
    private static final String PASSWORD = "s3cret";
    private static final UUID APPROVER_UUID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static final String V2_ISSUE_PATH = "/v2/authorityProvider/authorities/[^/]+/certificates/issue";
    private static final String V3_ISSUE_PATH = "/v3/authorityProvider/certificates/issue";

    @Autowired
    private EstExternalService estService;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private SecretSeeder secrets;

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private QueuedMessageDelivery delivery;

    @Autowired
    private CertificateStatusPollRepository statusPollRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateExternalService certificateService;

    @Autowired
    private ApprovalRepository approvalRepository;

    @Autowired
    private ApprovalProfileSeeder approvals;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private DataSourceProperties dataSourceProperties;

    private final WireMockResponseGate responseGate = new WireMockResponseGate();
    private WireMockServer authService;
    private WireMockServer connector;
    private X509Certificate issued;

    @BeforeEach
    void startConnectorThatIssuesAtOnceAndAuthService() throws Exception {
        authService = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authService.start();
        AuthServiceWireMockStubs.stubImpersonation(authService, UUID.randomUUID(), "est-user");
        connector = LoopbackWireMock.start(responseGate);
        issued = PkiFixtures.clientCertificate(PkiFixtures.rootCa("EST Issuing Root"));
        stubV2Issue(issued);
        delivery.deliverQueuedActions();
    }

    @AfterEach
    void stopServers() {
        authService.stop();
        connector.stop();
    }

    @Test
    void answersSameCertificate_whenIdenticalRequestIsRepeated() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        byte[] request = EstCsrFixtures.signedRequestBody();
        enroll(estProfile, request);

        // when
        ResponseEntity<byte[]> retry = enroll(estProfile, request);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateRepository.findAll())
                .singleElement()
                .satisfies(certificate -> assertThat(certificate.getState()).isEqualTo(CertificateState.ISSUED));
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(V2_ISSUE_PATH)));
    }

    @Test
    void issuesOnce_whenIdenticalRequestsArriveConcurrently() throws Exception {
        // given
        int concurrentRequests = 3;
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        byte[] request = EstCsrFixtures.signedRequestBody();
        stubV2Issue(issued);
        stubV2AttributeValidationTakingLong();

        // when
        List<ResponseEntity<byte[]>> answers = ConcurrentCalls
                .callTogether(concurrentRequests, () -> enroll(estProfile, request));

        // then
        assertThat(answers).hasSize(concurrentRequests);
        assertThat(answers).extracting(ResponseEntity::getStatusCode).containsOnly(HttpStatus.OK);
        assertThat(answers).extracting(ResponseEntity::getBody).containsOnly(answers.getFirst().getBody());
        assertThat(certificateRepository.findAll()).hasSize(1);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(V2_ISSUE_PATH)));
    }

    @Test
    void answersFromTakeover_whenClaimWasTakenOverWhileOwnerSubmitted() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        byte[] request = EstCsrFixtures.signedRequestBody();
        CountDownLatch ownerValidation = responseGate.hold();
        Future<ResponseEntity<byte[]>> owner = ConcurrentCalls.callInBackground(() -> enroll(estProfile, request));
        awaitAttributeValidations(1);
        responseGate.awaitHeld();
        responseGate.hold().countDown();
        ageClaims();
        ResponseEntity<byte[]> takeover = enroll(estProfile, request);

        // when
        ownerValidation.countDown();
        ResponseEntity<byte[]> ownerAnswer = owner.get(30, TimeUnit.SECONDS);

        // then
        assertThat(takeover.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ownerAnswer.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ownerAnswer.getBody()).isEqualTo(takeover.getBody());
        assertThat(certificateRepository.findAll()).hasSize(1);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(V2_ISSUE_PATH)));
    }

    @Test
    void answersPending_whenClaimIsTakenOverThroughAnotherPoolWhileOwnerStores() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        byte[] request = EstCsrFixtures.signedRequestBody();
        CountDownLatch ownerValidation = responseGate.hold();
        Future<ResponseEntity<byte[]>> owner = ConcurrentCalls.callInBackground(() -> enroll(estProfile, request));
        awaitAttributeValidations(1);
        responseGate.awaitHeld();
        responseGate.hold().countDown();

        // when
        try (HikariDataSource otherNode = dataSourceProperties
                .initializeDataSourceBuilder()
                .type(HikariDataSource.class)
                .build(); Connection otherNodeConnection = otherNode.getConnection()) {
            otherNodeConnection.setAutoCommit(false);
            takeOverClaims(otherNodeConnection);
            ownerValidation.countDown();
            awaitSessionBlockedBy(backendPid(otherNodeConnection));
            otherNodeConnection.commit();
            releaseClaims(otherNodeConnection);
            otherNodeConnection.commit();
        }
        ResponseEntity<byte[]> ownerAnswer = owner.get(30, TimeUnit.SECONDS);

        // then
        assertThat(ownerAnswer.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(certificateRepository.findAll()).isEmpty();
        connector.verify(0, WireMock.postRequestedFor(WireMock.urlPathMatching(V2_ISSUE_PATH)));
    }

    @Test
    void answersIssuanceFailedToEveryRequest_whenConcurrentIssueFails() throws Exception {
        // given
        int concurrentRequests = 2;
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        byte[] request = EstCsrFixtures.signedRequestBody();
        stubV2AttributeValidationTakingLong();
        connector
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(V2_ISSUE_PATH))
                        .willReturn(WireMock.jsonResponse("{\"message\": \"the authority failed\"}", 500)));

        // when
        List<Throwable> failures = ConcurrentCalls
                .callTogether(concurrentRequests, () -> catchThrowable(() -> enroll(estProfile, request)));

        // then
        assertThat(failures)
                .hasSize(concurrentRequests)
                .allSatisfy(failure -> assertThat(failure)
                        .isInstanceOfSatisfying(EstException.class,
                                refusal -> assertThat(refusal.error()).isEqualTo(EstError.ISSUANCE_FAILED)));
    }

    @Test
    void answersPendingThenIssued_whenConnectorIssuesLater() throws Exception {
        // given
        RaProfile raProfile = routes
                .seedRaProfileOnV3Authority(connector, RA_PROFILE_NAME, FeatureFlag.CERTIFICATE_STATUS_POLLING);
        EstProfile estProfile = seedRaBasicProfile(raProfile);
        V3ConnectorStubs.stubAttributesAndValidate(connector);
        V3ConnectorStubs.stubV3IssueAsync(connector);
        byte[] request = EstCsrFixtures.signedRequestBody();
        ResponseEntity<byte[]> first = enroll(estProfile, request);
        UUID certificateUuid = theOnlyCertificate().getUuid();
        V3ConnectorStubs.stubIssueStatusCompleted(connector, base64(issued));
        delivery.pollStatus(certificateUuid, CertificateOperation.ISSUE);

        // when
        ResponseEntity<byte[]> retry = enroll(estProfile, request);

        // then
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(first.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.ISSUED);
        assertThat(statusPollRepository.existsByCertificateUuid(certificateUuid)).isFalse();
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_PATH)));
    }

    @Test
    void answersPending_whileApprovalIsPending_withoutSecondApproval() throws Exception {
        // given
        EstProfile estProfile = seedProfileWithApproval();
        byte[] request = EstCsrFixtures.signedRequestBody();
        ResponseEntity<byte[]> first = enroll(estProfile, request);

        // when
        ResponseEntity<byte[]> retry = enroll(estProfile, request);

        // then
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(retry.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.PENDING_APPROVAL);
        assertThat(approvalRepository.count()).isEqualTo(1);
    }

    @Test
    void answersPendingWithTheRetryAfterOfTheProfile_whenItsIssueWaitIsZero() throws Exception {
        // given
        EstProfile estProfile = seedProfileWithApproval();
        jdbcTemplate
                .update("UPDATE est_profile SET retry_after = 7, issue_wait_timeout = 0 WHERE uuid = ?",
                        estProfile.getUuid());

        // when
        ResponseEntity<byte[]> answer = enroll(estProfile, EstCsrFixtures.signedRequestBody());

        // then
        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(answer.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("7");
    }

    @Test
    void answersIssued_afterApprovalIsGiven() throws Exception {
        // given
        EstProfile estProfile = seedProfileWithApproval();
        byte[] request = EstCsrFixtures.signedRequestBody();
        enroll(estProfile, request);
        approvals.approveAs(APPROVER_UUID, approvalRepository.findAll().getFirst().getUuid());
        delivery.deliverApprovalAnswers();

        // when
        ResponseEntity<byte[]> retry = enroll(estProfile, request);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.ISSUED);
        assertThat(approvalRepository.count()).isEqualTo(1);
    }

    @Test
    void answersRejected_afterApprovalIsRefused_andForTheRetry() throws Exception {
        // given
        EstProfile estProfile = seedProfileWithApproval();
        byte[] request = EstCsrFixtures.signedRequestBody();
        enroll(estProfile, request);
        approvals.refuseAs(APPROVER_UUID, approvalRepository.findAll().getFirst().getUuid());
        delivery.deliverApprovalAnswers();

        // when
        ThrowingCallable retry = () -> enroll(estProfile, request);

        // then
        assertThatThrownBy(retry)
                .isInstanceOfSatisfying(EstException.class,
                        refusal -> assertThat(refusal.error()).isEqualTo(EstError.REQUEST_REJECTED));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.REJECTED);
        assertThat(approvalRepository.count()).isEqualTo(1);
    }

    @Test
    void createsNewCertificate_whenFoundCertificateFailed() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        byte[] request = EstCsrFixtures.signedRequestBody();
        enroll(estProfile, request);
        Certificate first = theOnlyCertificate();
        first.setState(CertificateState.FAILED);
        certificateRepository.save(first);
        stubV2Issue(PkiFixtures.clientCertificate(PkiFixtures.rootCa("Second Root")));

        // when
        ResponseEntity<byte[]> retry = enroll(estProfile, request);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateRepository.findAll()).hasSize(2);
        connector.verify(2, WireMock.postRequestedFor(WireMock.urlPathMatching(V2_ISSUE_PATH)));
    }

    @Test
    void createsNewCertificate_whenFoundCertificateWasRevoked() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        byte[] request = EstCsrFixtures.signedRequestBody();
        enroll(estProfile, request);
        Certificate first = theOnlyCertificate();
        first.setState(CertificateState.REVOKED);
        certificateRepository.save(first);
        stubV2Issue(PkiFixtures.clientCertificate(PkiFixtures.rootCa("Second Root")));

        // when
        ResponseEntity<byte[]> retry = enroll(estProfile, request);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateRepository.findAll()).hasSize(2);
    }

    @Test
    void createsNewCertificate_whenFoundCertificateHasExpired() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        byte[] request = EstCsrFixtures.signedRequestBody();
        enroll(estProfile, request);
        Certificate first = theOnlyCertificate();
        first.setNotAfter(new Date(System.currentTimeMillis() - 86_400_000L));
        certificateRepository.save(first);
        stubV2Issue(PkiFixtures.clientCertificate(PkiFixtures.rootCa("Second Root")));

        // when
        ResponseEntity<byte[]> retry = enroll(estProfile, request);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateRepository.findAll()).hasSize(2);
    }

    @Test
    void createsNewCertificate_whenFoundCertificateWasDeleted() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        byte[] request = EstCsrFixtures.signedRequestBody();
        enroll(estProfile, request);
        UUID firstUuid = theOnlyCertificate().getUuid();
        certificateService.deleteCertificate(SecuredUUID.fromUUID(firstUuid));
        stubV2Issue(PkiFixtures.clientCertificate(PkiFixtures.rootCa("Second Root")));

        // when
        ResponseEntity<byte[]> retry = enroll(estProfile, request);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(theOnlyCertificate().getUuid()).isNotEqualTo(firstUuid);
    }

    @Test
    void createsNewCertificate_whenCsrDiffers() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile(routes.seedRaProfile(connector, RA_PROFILE_NAME));
        enroll(estProfile, EstCsrFixtures.signedRequestBody());
        stubV2Issue(PkiFixtures.clientCertificate(PkiFixtures.rootCa("Second Root")));

        // when
        ResponseEntity<byte[]> other = enroll(estProfile, EstCsrFixtures.signedRequestBody());

        // then
        assertThat(other.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateRepository.findAll()).hasSize(2);
    }

    @Test
    void answersFromInventory_whenNoRequestStateSurvives() throws Exception {
        // given
        RaProfile raProfile = routes.seedRaProfile(connector, RA_PROFILE_NAME);
        EstProfile estProfile = seedRaBasicProfile(raProfile);
        byte[] request = EstCsrFixtures.signedRequestBody();
        ClientCertificateIssueRequestDto earlier = new ClientCertificateIssueRequestDto();
        earlier.setRequest(Base64.getEncoder().encodeToString(Base64.getMimeDecoder().decode(request)));
        earlier.setFormat(CertificateRequestFormat.PKCS10);
        clientOperationService
                .issueCertificate(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(),
                        raProfile.getSecuredUuid(), earlier, CertificateProtocolInfo.est(estProfile.getUuid()));

        // when
        ResponseEntity<byte[]> answer = enroll(estProfile, request);

        // then
        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.ISSUED);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(V2_ISSUE_PATH)));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ResponseEntity<byte[]> enroll(EstProfile estProfile, byte[] request) {
        return estService.simpleEnroll(estProfile.getName(), request, basicCredentials(USERNAME, PASSWORD));
    }

    private EstProfile seedRaBasicProfile(RaProfile raProfile) {
        Secret credential = secrets.seedBasicAuthSecret("ra-credential", USERNAME, PASSWORD);
        return routes.seedRaBasicEstProfile(ESTPROFILE_NAME, raProfile, credential);
    }

    private EstProfile seedProfileWithApproval() throws Exception {
        RaProfile raProfile = routes.seedRaProfile(connector, RA_PROFILE_NAME);
        approvals.requireApproval(raProfile, APPROVER_UUID);
        return seedRaBasicProfile(raProfile);
    }

    private Certificate theOnlyCertificate() {
        List<Certificate> all = certificateRepository.findAll();
        assertThat(all).hasSize(1);
        return all.getFirst();
    }

    private void stubV2Issue(X509Certificate certificate) {
        connector
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(V2_ISSUE_PATH))
                        .willReturn(WireMock.okJson("{ \"certificateData\": \"" + base64(certificate) + "\" }")));
        connector
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching(V2_ISSUE_PATH + "/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        connector
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(V2_ISSUE_PATH + "/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
    }

    /**
     * The connector takes long to validate the issue attributes, which Core does before it stores the certificate that
     * an identical request finds, so every concurrent request has looked for an earlier one before any exists.
     */
    private void stubV2AttributeValidationTakingLong() {
        connector
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(V2_ISSUE_PATH + "/attributes/validate"))
                        .willReturn(WireMock.okJson("true").withFixedDelay(500)));
    }

    private void awaitAttributeValidations(int count) {
        await()
                .atMost(10, TimeUnit.SECONDS)
                .until(() -> connector
                        .countRequestsMatching(WireMock
                                .postRequestedFor(WireMock.urlPathMatching(V2_ISSUE_PATH + "/attributes/validate"))
                                .build())
                        .getCount() == count);
    }

    /** Makes every claim look older than its expiry, as if its owner had been submitting for minutes. */
    private void ageClaims() {
        jdbcTemplate.update("UPDATE est_request_claim SET claimed_at = now() - INTERVAL '1 hour'");
    }

    /** Takes over every claim, as another node does, and keeps the claims locked until the connection commits. */
    private static void takeOverClaims(Connection connection) throws SQLException {
        try (PreparedStatement takeOver = connection
                .prepareStatement("UPDATE est_request_claim SET uuid = ?, claimed_at = now()")) {
            takeOver.setObject(1, UUID.randomUUID());
            takeOver.executeUpdate();
        }
    }

    private static void releaseClaims(Connection connection) throws SQLException {
        try (PreparedStatement release = connection.prepareStatement("DELETE FROM est_request_claim")) {
            release.executeUpdate();
        }
    }

    private static int backendPid(Connection connection) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement("SELECT pg_backend_pid()");
                ResultSet result = query.executeQuery()) {
            result.next();
            return result.getInt(1);
        }
    }

    private void awaitSessionBlockedBy(int lockHolderPid) {
        await()
                .atMost(10, TimeUnit.SECONDS)
                .until(() -> jdbcTemplate
                        .queryForObject("SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))",
                                Long.class, lockHolderPid) > 0);
    }

    private static String base64(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
