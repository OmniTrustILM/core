package com.otilm.core.integration.service.est;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.api.est.EstExceptionHandlingAdvice;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.jms.listeners.ActionsListener;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.est.EstExternalService;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.authentication.EstClientCredentials.BasicCredentials;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstResponses;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.QueuedMessageDelivery;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.seeders.ApprovalProfileSeeder;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicCredentials;
import static com.otilm.core.util.mocks.AuthorityV2ConnectorStubs.ISSUE_PATH;
import static com.otilm.core.util.seeders.CertificateRegistrationSeeder.CHALLENGE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * {@code /simpleenroll} through the service for clients that complete a pre-registered certificate, against a connector
 * double that issues at once. The mocked {@link ActionProducer} hands each queued message to the real
 * {@link ActionsListener} through {@link QueuedMessageDelivery}, as the broker consumer would: a failure of the
 * consumer stays with it, and the answers of an approval wait until it is decided.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class EstRegistrationEnrollmentITest extends BaseSpringBootTest {

    private static final String ESTPROFILE_NAME = "devices-profile";
    private static final String RA_PROFILE_NAME = "devices-ra";
    private static final String SUBJECT = "CN=device-1";
    private static final String NO_USERNAME = "";
    private static final String ANOTHER_PASSWORD = "not-the-challenge";
    private static final UUID APPROVER_UUID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    @Autowired
    private EstExternalService estService;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private ActionProducer actionProducer;

    @Autowired
    private QueuedMessageDelivery delivery;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizations;

    @Autowired
    private CertificateEventHistoryRepository eventHistory;

    @Autowired
    private CertificateProtocolAssociationRepository protocolAssociations;

    @Autowired
    private ApprovalRepository approvalRepository;

    @Autowired
    private ApprovalProfileSeeder approvals;

    @Autowired
    private CertificateExternalService certificateService;

    private WireMockServer authService;
    private WireMockServer connector;
    private X509Certificate issued;
    private RaProfile raProfile;
    private EstProfile estProfile;

    @BeforeEach
    void startAuthServiceAndSeedRouteOnAConnectorThatIssuesAtOnce() throws Exception {
        authService = AuthServiceWireMockStubs.startImpersonating(UUID.randomUUID(), "est-user");
        connector = LoopbackWireMock.start();
        issued = PkiFixtures.clientCertificate(PkiFixtures.rootCa("EST Issuing Root"));
        stubIssue(WireMock.okJson("{ \"certificateData\": \"" + base64(issued) + "\" }"));
        raProfile = routes.seedRaProfile(connector, RA_PROFILE_NAME);
        estProfile = routes
                .seedEstProfile(ESTPROFILE_NAME, EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, raProfile, List.of(),
                        List.of());
        delivery.deliverQueuedActions();
    }

    @AfterEach
    void stopServers() {
        authService.stop();
        connector.stop();
    }

    // ── Completing ────────────────────────────────────────────────────────────

    @Test
    void completesRegistration_whenPasswordIsRight() throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);
        EstClientCredentials credentials = IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            ResponseEntity<byte[]> response = enroll(request, credentials);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(certificateOf(response)).isEqualTo(issued);
            assertThat(certificateRepository.findAll()).singleElement().satisfies(certificate -> {
                assertThat(certificate.getUuid()).isEqualTo(registration.getUuid());
                assertThat(certificate.getState()).isEqualTo(CertificateState.ISSUED);
            });
            assertThat(protocolAssociations.findAll()).singleElement().satisfies(attribution -> {
                assertThat(attribution.getCertificateUuid()).isEqualTo(registration.getUuid());
                assertThat(attribution.getProtocol()).isEqualTo(CertificateProtocol.EST);
                assertThat(attribution.getProtocolProfileUuid()).isEqualTo(estProfile.getUuid());
            });
            assertThat(authorizationOf(registration).getExpiresAt()).isNull();
            assertNoCredentialLogged(probe, credentials);
        }
    }

    @ParameterizedTest
    @EnumSource(IdentifiedBy.class)
    void answersPending_whenCompletionWaitsForApproval_andForTheRetry(IdentifiedBy identifiedBy) throws Exception {
        // given
        approvals.requireApproval(raProfile, APPROVER_UUID);
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);
        EstClientCredentials credentials = identifiedBy.credentials(registration, CHALLENGE);
        ResponseEntity<byte[]> first = enroll(request, credentials);

        // when
        ResponseEntity<byte[]> retry = enroll(request, credentials);

        // then
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(retry.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(stateOf(registration)).isEqualTo(CertificateState.PENDING_APPROVAL);
        assertThat(approvalRepository.count()).isEqualTo(1);
    }

    @ParameterizedTest
    @MethodSource("repetitions")
    void answersSameCertificate_whenCompletionIsRepeated(IdentifiedBy identifiedBy, String passwordOfTheRetry)
            throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);
        enroll(request, identifiedBy.credentials(registration, CHALLENGE));
        int historyBeforeTheRetry = eventHistory.findByCertificateOrderByCreatedDesc(registration).size();

        // when
        ResponseEntity<byte[]> retry = enroll(request, identifiedBy.credentials(registration, passwordOfTheRetry));

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateOf(retry)).isEqualTo(issued);
        assertThat(certificateRepository.findAll())
                .singleElement()
                .extracting(Certificate::getUuid)
                .isEqualTo(registration.getUuid());
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(ISSUE_PATH)));
        assertThat(authorizationOf(registration).getFailedAttempts()).isZero();
        assertThat(eventHistory.findByCertificateOrderByCreatedDesc(registration)).hasSize(historyBeforeTheRetry);
    }

    @Test
    void startsNewCompletion_whenRetriedAfterRefusal() throws Exception {
        // given — a refused approval returns the registration to REGISTERED without its request
        approvals.requireApproval(raProfile, APPROVER_UUID);
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);
        EstClientCredentials credentials = IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE);
        enroll(request, credentials);
        refuseTheApproval();

        // when
        ResponseEntity<byte[]> retry = enroll(request, credentials);

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(stateOf(registration)).isEqualTo(CertificateState.PENDING_APPROVAL);
        assertThat(approvalRepository.count()).isEqualTo(2);
        assertThat(protocolAssociations.findAll())
                .singleElement()
                .extracting(CertificateProtocolAssociation::getCertificateUuid)
                .isEqualTo(registration.getUuid());
        assertThat(certificateService.getCertificate(registration.getSecuredUuid()).getUuid())
                .isEqualTo(registration.getUuid().toString());
    }

    @Test
    void attributesToTheEstProfile_whenAnotherProtocolAttributedTheRegistration() throws Exception {
        // given — a completion through SCEP attributed the registration, and its refused approval kept the attribution
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        CertificateProtocolAssociation scepAttribution = new CertificateProtocolAssociation();
        scepAttribution.setCertificateUuid(registration.getUuid());
        scepAttribution.setProtocol(CertificateProtocol.SCEP);
        scepAttribution.setProtocolProfileUuid(UUID.randomUUID());
        protocolAssociations.save(scepAttribution);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);

        // when
        enroll(request, IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE));

        // then
        assertThat(protocolAssociations.findAll()).singleElement().satisfies(attribution -> {
            assertThat(attribution.getCertificateUuid()).isEqualTo(registration.getUuid());
            assertThat(attribution.getProtocol()).isEqualTo(CertificateProtocol.EST);
            assertThat(attribution.getProtocolProfileUuid()).isEqualTo(estProfile.getUuid());
        });
    }

    @Test
    void answersPending_whenRetryFindsACompletionThatWasNeverQueued() throws Exception {
        // given — the node stopped between attaching the request and queueing its issue
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);
        registrations
                .seedCompletion(registration, Base64.getMimeDecoder().decode(request), CertificateState.REGISTERED);

        // when
        ResponseEntity<byte[]> retry = enroll(request, IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE));

        // then
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(retry.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(stateOf(registration)).isEqualTo(CertificateState.REGISTERED);
        Mockito.verify(actionProducer, Mockito.never()).produceMessage(Mockito.any());
    }

    @Test
    void completesAgain_whenRetriedAfterQueueingTheIssueFailed() throws Exception {
        // given — the platform undoes a completion whose issue it could not queue
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);
        EstClientCredentials credentials = IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE);
        Mockito.doThrow(new IllegalStateException("broker down")).doAnswer(invocation -> {
            delivery.deliver(invocation.getArgument(0));
            return null;
        }).when(actionProducer).produceMessage(Mockito.any());
        Throwable first = catchThrowable(() -> enroll(request, credentials));

        // when
        ResponseEntity<byte[]> retry = enroll(request, credentials);

        // then
        assertThat(first)
                .isInstanceOfSatisfying(EstException.class,
                        refusal -> assertThat(refusal.error()).isEqualTo(EstError.SERVICE_UNAVAILABLE));
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateOf(retry)).isEqualTo(issued);
        assertThat(stateOf(registration)).isEqualTo(CertificateState.ISSUED);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(ISSUE_PATH)));
    }

    @Test
    void throwsServiceUnavailable_whenTheAuthorityCannotValidateTheIssueAttributes() throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);
        AuthorityV2ConnectorStubs.on(connector).stubIssueAttributeValidationFailure();

        // when
        ThrowingCallable simpleEnroll = () -> enroll(request,
                IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE));

        // then
        assertThatThrownBy(simpleEnroll)
                .isInstanceOfSatisfying(EstException.class,
                        refusal -> assertThat(refusal.error()).isEqualTo(EstError.SERVICE_UNAVAILABLE));
        assertThat(certificateRepository.findByUuid(registration.getUuid()).orElseThrow()).satisfies(unchanged -> {
            assertThat(unchanged.getState()).isEqualTo(CertificateState.REGISTERED);
            assertThat(unchanged.getCertificateRequestUuid()).isNull();
        });
        connector.verify(0, WireMock.postRequestedFor(WireMock.urlPathMatching(ISSUE_PATH)));
    }

    // ── Refusals ──────────────────────────────────────────────────────────────

    @Test
    void answersAsNonMatch_whenNothingIsRegistered() throws Exception {
        // given — no registration of the subject
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);

        // when
        ThrowingCallable enroll = () -> enroll(request, basicCredentials(NO_USERNAME, CHALLENGE));

        // then
        assertThatThrownBy(enroll).satisfies(EstRegistrationEnrollmentITest::assertAnsweredAsNonMatch);
    }

    @Test
    void answersAsNonMatch_whenPasswordIsWrong() throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);
        EstClientCredentials credentials = IdentifiedBy.REFERENCE.credentials(registration, ANOTHER_PASSWORD);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            ThrowingCallable enroll = () -> enroll(request, credentials);

            // then
            assertThatThrownBy(enroll).satisfies(EstRegistrationEnrollmentITest::assertAnsweredAsNonMatch);
            assertThat(authorizationOf(registration).getFailedAttempts()).isEqualTo(1);
            assertThat(stateOf(registration)).isEqualTo(CertificateState.REGISTERED);
            assertNoCredentialLogged(probe, credentials);
        }
    }

    @Test
    void answersAsNonMatch_whenRegistrationIsLocked() throws Exception {
        // given
        Certificate registration = registrations
                .seedRegistrationWithAuthorization(raProfile, SUBJECT, RegistrationState.LOCKED);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);

        // when
        ThrowingCallable enroll = () -> enroll(request, IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE));

        // then
        assertThatThrownBy(enroll).satisfies(EstRegistrationEnrollmentITest::assertAnsweredAsNonMatch);
    }

    @Test
    void answersAsNonMatch_whenRegistrationHasExpired() throws Exception {
        // given — the window has passed, which the challenge gate finds when the completion asks it
        Certificate registration = registrations.seedRegistrationWithPassedWindow(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);

        // when
        ThrowingCallable enroll = () -> enroll(request, IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE));

        // then
        assertThatThrownBy(enroll).satisfies(EstRegistrationEnrollmentITest::assertAnsweredAsNonMatch);
        assertThat(authorizationOf(registration).getState()).isEqualTo(RegistrationState.EXPIRED);
    }

    @Test
    void answersAsNonMatch_whenSignatureDoesNotVerifyForRegisteredSubject() throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] forgedRequest = EstCsrFixtures.forgedRequestBody(SUBJECT);

        // when
        ThrowingCallable enroll = () -> enroll(forgedRequest,
                IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE));

        // then
        assertThatThrownBy(enroll).satisfies(EstRegistrationEnrollmentITest::assertAnsweredAsNonMatch);
        assertThat(authorizationOf(registration).getFailedAttempts()).isZero();
        assertThat(eventHistory.findByCertificateOrderByCreatedDesc(registration)).isEmpty();
    }

    @Test
    void answersAsNonMatch_whenRegistrationWasCompletedWithAnotherCsr() throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE);
        enroll(EstCsrFixtures.signedRequestBody(SUBJECT), credentials);
        byte[] anotherRequest = EstCsrFixtures.signedRequestBody(SUBJECT);

        // when
        ThrowingCallable enroll = () -> enroll(anotherRequest, credentials);

        // then
        assertThatThrownBy(enroll).satisfies(EstRegistrationEnrollmentITest::assertAnsweredAsNonMatch);
        assertThat(certificateRepository.findAll())
                .singleElement()
                .extracting(Certificate::getState)
                .isEqualTo(CertificateState.ISSUED);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(ISSUE_PATH)));
    }

    @Test
    void answersAsNonMatch_whenAnotherRequestIsIssuedWhileTheCompletionWaits() throws Exception {
        // given — before the first completion reads its registration again, its approval is refused, and another
        // request completes the registration and is approved and issued
        approvals.requireApproval(raProfile, APPROVER_UUID);
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE);
        byte[] anotherRequest = EstCsrFixtures.signedRequestBody(SUBJECT);
        onTheFirstQueuedIssue(() -> {
            refuseTheApproval();
            enroll(anotherRequest, credentials);
            giveTheApproval(registration);
        });
        byte[] firstRequest = EstCsrFixtures.signedRequestBody(SUBJECT);

        // when
        ThrowingCallable enroll = () -> enroll(firstRequest, credentials);

        // then
        assertThatThrownBy(enroll).satisfies(EstRegistrationEnrollmentITest::assertAnsweredAsNonMatch);
        assertThat(stateOf(registration)).isEqualTo(CertificateState.ISSUED);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(ISSUE_PATH)));
    }

    @Test
    void answersAsNonMatch_whenRegistrationFailed() throws Exception {
        // given — the connector refuses to issue, so the queued issue fails the certificate of the registration
        stubIssue(WireMock.serverError());
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] request = EstCsrFixtures.signedRequestBody(SUBJECT);
        EstClientCredentials credentials = IdentifiedBy.REFERENCE.credentials(registration, CHALLENGE);
        catchThrowable(() -> enroll(request, credentials));

        // when
        ThrowingCallable retry = () -> enroll(request, credentials);

        // then
        assertThatThrownBy(retry).satisfies(EstRegistrationEnrollmentITest::assertAnsweredAsNonMatch);
        assertThat(stateOf(registration)).isEqualTo(CertificateState.FAILED);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> repetitions() {
        return Stream
                .of(arguments(IdentifiedBy.REFERENCE, named("with the challenge", CHALLENGE)),
                        arguments(IdentifiedBy.SUBJECT, named("with the challenge", CHALLENGE)),
                        arguments(IdentifiedBy.REFERENCE, named("with another password", ANOTHER_PASSWORD)),
                        arguments(IdentifiedBy.SUBJECT, named("with another password", ANOTHER_PASSWORD)));
    }

    /**
     * How a client names its registration: by its reference as the Basic user name, or by the subject of the request,
     * which the empty user name leaves it to.
     */
    private enum IdentifiedBy {
        REFERENCE,
        SUBJECT;

        EstClientCredentials credentials(Certificate registration, String password) {
            String username = this == REFERENCE ? registration.getUuid().toString() : NO_USERNAME;
            return basicCredentials(username, password);
        }
    }

    private ResponseEntity<byte[]> enroll(byte[] request, EstClientCredentials credentials) {
        return estService.simpleEnroll(ESTPROFILE_NAME, request, credentials);
    }

    private void stubIssue(ResponseDefinitionBuilder issueAnswer) {
        connector.stubFor(WireMock.post(WireMock.urlPathMatching(ISSUE_PATH)).willReturn(issueAnswer));
        AuthorityV2ConnectorStubs.on(connector).stubIssueAttributeValidation();
    }

    /**
     * Delivers every queued message as {@link QueuedMessageDelivery#deliver} does, and runs the steps once the first
     * one is delivered, before the enrolment that queued it reads its registration again.
     */
    private void onTheFirstQueuedIssue(ThrowingCallable steps) {
        AtomicBoolean ran = new AtomicBoolean();
        Mockito.doAnswer(invocation -> {
            delivery.deliver(invocation.getArgument(0));
            if (ran.compareAndSet(false, true)) {
                steps.call();
            }
            return null;
        }).when(actionProducer).produceMessage(Mockito.any());
    }

    /**
     * The approver, who is not the user that enrolled, refuses the approval. Its answer is delivered once the decision
     * has committed, as the broker would, and the user that enrolled is back afterwards.
     */
    private void refuseTheApproval() throws Exception {
        approvals.refuseAs(APPROVER_UUID, approvalRepository.findAll().getFirst().getUuid());
        delivery.deliverApprovalAnswers();
    }

    /** As {@link #refuseTheApproval()}, but the approver gives the approval that the registration waits for. */
    private void giveTheApproval(Certificate registration) throws Exception {
        UUID approvalUuid = approvalRepository
                .findByResourceAndObjectUuidAndStatus(Resource.CERTIFICATE, registration.getUuid(),
                        ApprovalStatusEnum.PENDING)
                .getUuid();
        approvals.approveAs(APPROVER_UUID, approvalUuid);
        delivery.deliverApprovalAnswers();
    }

    private CertificateState stateOf(Certificate registration) {
        return certificateRepository.findByUuid(registration.getUuid()).orElseThrow().getState();
    }

    private CertificateRegistrationAuthorization authorizationOf(Certificate registration) {
        return authorizations.findByCertificateUuid(registration.getUuid()).orElseThrow();
    }

    /** Neither the password, nor the challenge of the registration, nor the base64 of the credentials was logged. */
    private static void assertNoCredentialLogged(SecretLeakProbe probe, EstClientCredentials credentials) {
        BasicCredentials basic = credentials.basic().orElseThrow();
        String basicCredentials = Base64
                .getEncoder()
                .encodeToString((basic.username() + ":" + basic.password()).getBytes(StandardCharsets.UTF_8));
        SecretLeakProbe.assertNoneReveals(probe.logged(), basic.password(), CHALLENGE, basicCredentials);
    }

    /**
     * The client is told what a request that matches no registration is told: 401 with the challenge of the realm and
     * the same sentence, and nothing else.
     */
    private static void assertAnsweredAsNonMatch(Throwable thrown) {
        ResponseEntity<byte[]> nonMatch = EstResponses.error(EstError.REGISTRATION_REJECTED, ESTPROFILE_NAME);
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            ResponseEntity<byte[]> answer = new EstExceptionHandlingAdvice().handleEstException(refusal);
            assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(answer.getHeaders()).isEqualTo(nonMatch.getHeaders());
            assertThat(answer.getBody()).isEqualTo(nonMatch.getBody());
        });
    }

    private static String base64(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate certificateOf(ResponseEntity<byte[]> response) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(response.getBody());
        var held = new CMSSignedData(der).getCertificates().getMatches(null);
        assertThat(held).hasSize(1);
        return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) held.iterator().next());
    }
}
