package com.otilm.core.service.est.enrollment;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.EstRequestedCertificate;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.enrollment.EstRequestClaims.ClaimedRequest;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.service.writer.est.EstRequestClaimLostException;
import com.otilm.core.service.writer.est.EstRequestClaimWriter;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.EstClientCredentialsFixtures;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.PkiFixtures;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstEnrollmentTest {

    private static final String LABEL = "devices";
    private static final String PASSWORD = "the-challenge";
    private static final String ECHOED_TEXT = "connector-echoed-secret";
    private static final Duration DOCUMENTED_ISSUE_WAIT = Duration.ofSeconds(10);

    @Mock
    private ClientOperationInternalService clientOperationService;

    @Mock
    private ClientOperationExternalService clientOperationExternalService;

    @Mock
    private CertificateInternalService certificateService;

    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private EstIssueRequests issueRequests;

    @Mock
    private EstIssuanceWait issuanceWait;

    @Mock
    private EstRequestClaimWriter claimWriter;

    @Mock
    private EstRequestClaims claims;

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger enrollmentLogger = (Logger) LoggerFactory.getLogger(EstEnrollment.class.getPackageName());
    private Level previousLevel;
    private boolean previousAdditive;

    private EstEnrollment enrollment;
    private EstRoute route;
    private Pkcs10CertificateRequest csr;
    private final UUID certificateUuid = UUID.randomUUID();
    private final UUID registrationUuid = UUID.randomUUID();

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** The logger is a process-wide singleton, so what is set on it here is taken off again after each test. */
    @BeforeEach
    void createEnrollmentAndCaptureTheLog() throws Exception {
        enrollment = enrollmentAnsweringPending();
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        EstProfile estProfile = anEstProfile().withUuid(UUID.randomUUID()).build();
        route = new EstRoute(estProfile, raProfile, false, LABEL);
        lenient().when(claimWriter.claim(any(), any(), any(), any())).thenReturn(Optional.of(UUID.randomUUID()));
        csr = new Pkcs10CertificateRequest(Base64.getDecoder().decode(EstCsrFixtures.signedRequestBody()));
        previousLevel = enrollmentLogger.getLevel();
        previousAdditive = enrollmentLogger.isAdditive();
        enrollmentLogger.setLevel(Level.DEBUG);
        enrollmentLogger.setAdditive(false);
        logged.start();
        enrollmentLogger.addAppender(logged);
    }

    @AfterEach
    void releaseTheLog() {
        enrollmentLogger.detachAppender(logged);
        logged.stop();
        enrollmentLogger.setLevel(previousLevel);
        enrollmentLogger.setAdditive(previousAdditive);
    }

    @ParameterizedTest
    @MethodSource("statesThatWaitForTheClientToCallAgain")
    void answersAcceptedWithRetryAfter_whenCertificateIsStillInProgress(CertificateState state) throws Exception {
        // given
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.of(state));

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(response.getBody()).isNull();
    }

    @Test
    void answersAcceptedWithTheRetryAfterOfTheEstProfile_whenCertificateIsStillInProgress() throws Exception {
        // given
        var configuredRetryAfter = Duration.ofSeconds(45);
        route = new EstRoute(anEstProfile().withUuid(UUID.randomUUID()).withRetryAfter(45).build(), route.raProfile(),
                false, LABEL);
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.of(CertificateState.REQUESTED));

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER))
                .isEqualTo(Long.toString(configuredRetryAfter.toSeconds()));
    }

    @Test
    void throwsRequestRejected_whenCertificateIsRejected() throws Exception {
        // given
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.of(CertificateState.REJECTED));

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REQUEST_REJECTED));
    }

    @Test
    void throwsIssuanceFailed_whenCertificateFailed() throws Exception {
        // given
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.of(CertificateState.FAILED));

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_FAILED));
    }

    @Test
    void throwsIllegalState_whenCertificateIsInAStateNoEnrolmentReaches() throws Exception {
        // given
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.of(CertificateState.REVOKED));

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void completesRegistrationWithThePassword_whenItHasNoRequest() throws Exception {
        // given
        stubRegistration(CertificateState.REGISTERED, null);
        ClientCertificateIssueRequestDto completion = stubCompletionRequest();
        when(issuanceWait.awaitSettled(route, registrationUuid, fingerprintOfTheCsr()))
                .thenReturn(Optional.of(CertificateState.PENDING_APPROVAL));

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        verify(clientOperationExternalService)
                .issueExistingCertificate(
                        argThat(authority -> authority
                                .getValue()
                                .equals(route.raProfile().getAuthorityInstanceReference().getUuid())),
                        argThat(raProfile -> raProfile.getValue().equals(route.raProfile().getUuid())),
                        eq(registrationUuid.toString()), same(completion));
    }

    @Test
    void attributesCompletedRegistrationToTheEstProfile_whenItHasNoRequest() throws Exception {
        // given
        stubRegistration(CertificateState.REGISTERED, null);
        stubCompletionRequest();
        when(issuanceWait.awaitSettled(route, registrationUuid, fingerprintOfTheCsr()))
                .thenReturn(Optional.of(CertificateState.PENDING_APPROVAL));

        // when
        enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        verify(certificateService)
                .applyProtocolAssociations(eq(registrationUuid), argThat(this::isAttributedToTheEstProfile));
    }

    @Test
    void answersWithoutCompletingAgain_whenRegistrationWasCompletedWithTheRequest() {
        // given
        stubRegistration(CertificateState.PENDING_APPROVAL, fingerprintOfTheCsr());

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        verifyNoInteractions(clientOperationExternalService, issueRequests, certificateService, issuanceWait);
    }

    @Test
    void answersAcceptedAtOnce_whenRetryFindsItsCompletionStillQueued() {
        // given — the registration carries this request, and nothing has claimed its issue
        stubRegistration(CertificateState.REGISTERED, fingerprintOfTheCsr());

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        verifyNoInteractions(issuanceWait, clientOperationExternalService);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"FAILED", "REJECTED", "REVOKED", "PENDING_REVOKE"})
    void throwsRegistrationRejected_whenRegistrationCompletedWithTheRequestNoLongerAnswersIt(CertificateState state) {
        // given
        stubRegistration(state, fingerprintOfTheCsr());

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
        verifyNoInteractions(clientOperationExternalService, issuanceWait);
    }

    @Test
    void throwsRegistrationRejected_whenCertificateOfTheRegistrationHasExpired() {
        // given
        var expired = new Date(System.currentTimeMillis() - 86_400_000L);
        stubRegistration(CertificateState.ISSUED, expired, fingerprintOfTheCsr());

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
        verifyNoInteractions(clientOperationExternalService, issuanceWait);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"REGISTERED", "PENDING_APPROVAL", "ISSUED"})
    void throwsRegistrationRejected_whenRegistrationWasCompletedWithAnotherRequest(CertificateState state) {
        // given
        var fingerprintOfAnotherRequest = "0f".repeat(32);
        stubRegistration(state, fingerprintOfAnotherRequest);

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
        verifyNoInteractions(clientOperationExternalService, issuanceWait);
    }

    @Test
    void throwsRegistrationRejected_whenRegistrationFailedWithoutARequest() {
        // given
        stubRegistration(CertificateState.FAILED, null);

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
        verifyNoInteractions(clientOperationExternalService, issuanceWait);
    }

    @Test
    void throwsRegistrationRejected_whenRegistrationIsGone() {
        // given — the certificate was deleted after the client was identified by it
        when(certificateRepository.findEstRequestedCertificateByUuid(registrationUuid)).thenReturn(Optional.empty());

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"FAILED", "REJECTED"})
    void throwsRegistrationRejected_whenCompletedRegistrationEndsInAStateThatDoesNotAnswer(CertificateState state) {
        // given
        stubRegistration(CertificateState.REGISTERED, null);
        stubCompletionRequest();
        when(issuanceWait.awaitSettled(route, registrationUuid, fingerprintOfTheCsr())).thenReturn(Optional.of(state));

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
    }

    @Test
    void throwsRegistrationRejected_whenCompletionLosesItsRequestDuringTheWait() {
        // given — a refused approval takes the request off, and another request may complete the registration since
        stubRegistration(CertificateState.REGISTERED, null);
        stubCompletionRequest();
        when(issuanceWait.awaitSettled(route, registrationUuid, fingerprintOfTheCsr())).thenReturn(Optional.empty());

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
    }

    @Test
    void answersAcceptedWithoutReadingAgain_whenCompletionIsStillQueuedAfterTheWait() {
        // given — the wait read the registration with this request, so a refusal that lands later changes nothing
        stubRegistration(CertificateState.REGISTERED, null);
        stubCompletionRequest();
        when(issuanceWait.awaitSettled(route, registrationUuid, fingerprintOfTheCsr()))
                .thenReturn(Optional.of(CertificateState.REGISTERED));

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        verify(certificateRepository, times(1)).findEstRequestedCertificateByUuid(registrationUuid);
    }

    @Test
    void answersIssuedCertificate_whenCompletionIsIssuedForTheRequest() throws Exception {
        // given
        stubRegistration(CertificateState.REGISTERED, null);
        stubCompletionRequest();
        when(issuanceWait.awaitSettled(route, registrationUuid, fingerprintOfTheCsr()))
                .thenReturn(Optional.of(CertificateState.ISSUED));
        X509Certificate issued = stubIssuedContent(registrationUuid);

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateOf(response)).isEqualTo(issued);
    }

    @Test
    void throwsRegistrationRejected_whenCompletionHoldsNoContentForTheRequest() {
        // given — the content is read only while the registration still carries this request
        stubRegistration(CertificateState.REGISTERED, null);
        stubCompletionRequest();
        when(issuanceWait.awaitSettled(route, registrationUuid, fingerprintOfTheCsr()))
                .thenReturn(Optional.of(CertificateState.ISSUED));
        when(certificateRepository.findContentByUuidAndRequestFingerprint(registrationUuid, fingerprintOfTheCsr()))
                .thenReturn(Optional.empty());

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
    }

    @Test
    void throwsPolicyViolationWithTheMessageAsDetail_whenCompletionViolatesThePolicy() throws Exception {
        // given
        String policyText = "The request does not carry a common name.";
        stubCompletionFailure(new RequestAttributePolicyViolationException(policyText, List.of(policyText)));

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(EstError.POLICY_VIOLATION);
            assertThat(refusal.detail()).contains(policyText);
            assertThat(refusal.realm()).contains(LABEL);
        });
        verifyNoInteractions(certificateService, issuanceWait);
    }

    @ParameterizedTest
    @MethodSource("refusalsOfTheCompletion")
    void throwsRegistrationRejectedWithoutAnError_whenThePlatformRefusesTheCompletion(Exception refusal)
            throws Exception {
        // given
        stubCompletionFailure(refusal);

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
        assertThat(errorEvents()).isEmpty();
        verifyNoInteractions(certificateService, issuanceWait);
    }

    @ParameterizedTest
    @MethodSource("refusalsOfTheCompletion")
    void logsTheClassOfTheRefusalAtDebug_whenThePlatformRefusesTheCompletion(Exception refusal) throws Exception {
        // given
        stubCompletionFailure(refusal);

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).isInstanceOf(EstException.class);
        assertThat(logged.list)
                .extracting(ILoggingEvent::getFormattedMessage)
                .anyMatch(line -> line.contains(refusal.getClass().getName()))
                .noneMatch(line -> line.contains(refusal.getMessage()));
    }

    @Test
    void answersUnavailableAndLogsClassNamesOnly_whenAConnectorFailureCausedIt() throws Exception {
        // given — what a connector reports can echo the credentials of the authority
        var failure = new IllegalStateException(ECHOED_TEXT, new ConnectorException(ECHOED_TEXT));
        stubCompletionFailure(failure);

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE));
        assertLoggedClassNamesOnly(failure);
        verifyNoInteractions(certificateService, issuanceWait);
    }

    @Test
    void throwsServiceUnavailable_whenTheAuthorityFailsTheCompletion() throws Exception {
        // given — the platform answers a connector failure, or issue attributes the authority refused, with this
        // before it attaches the request to the registration
        stubCompletionFailure(new CertificateException(ECHOED_TEXT));

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE));
        verifyNoInteractions(certificateService, issuanceWait);
    }

    @Test
    void logsClassNamesOnly_whenTheAuthorityFailsTheCompletion() throws Exception {
        // given
        var failure = new CertificateException(ECHOED_TEXT);
        stubCompletionFailure(failure);

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).isInstanceOf(EstException.class);
        assertLoggedClassNamesOnly(failure);
    }

    @Test
    void warnsWithTheClassOnly_whenAttributionFails() throws Exception {
        // given
        String attributionText = "attribute-engine-detail";
        stubRegistration(CertificateState.REGISTERED, null);
        stubCompletionRequest();
        doThrow(new IllegalStateException(attributionText))
                .when(certificateService)
                .applyProtocolAssociations(any(), any());
        when(issuanceWait.awaitSettled(route, registrationUuid, fingerprintOfTheCsr()))
                .thenReturn(Optional.of(CertificateState.PENDING_APPROVAL));

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aRegistrationClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(logged.list).filteredOn(event -> event.getLevel() == Level.WARN).singleElement().satisfies(event -> {
            assertThat(event.getFormattedMessage())
                    .contains(registrationUuid.toString())
                    .contains(IllegalStateException.class.getName())
                    .doesNotContain(attributionText);
            assertThat(event.getThrowableProxy()).isNull();
        });
    }

    @Test
    void returnsTheRegistrationItCompleted_whenCompletingARegistrationWithoutARequest() throws Exception {
        // given
        stubRegistration(CertificateState.REGISTERED, null);
        ClientCertificateIssueRequestDto completion = stubCompletionRequest();

        // when
        UUID completed = enrollment.completeRegistration(route, aRegistrationClient(), csr, credentials());

        // then
        assertThat(completed).isEqualTo(registrationUuid);
        verify(clientOperationExternalService)
                .issueExistingCertificate(any(), any(), eq(registrationUuid.toString()), same(completion));
        verifyNoInteractions(issuanceWait);
    }

    @Test
    void throwsRegistrationRejectedAndLogsTheRegistrationAtWarn_whenCompletingARegistrationThatHasARequest() {
        // given
        var fingerprintOfAnotherRequest = "0f".repeat(32);
        stubRegistration(CertificateState.REGISTERED, fingerprintOfAnotherRequest);

        // when
        ThrowingCallable complete = () -> enrollment
                .completeRegistration(route, aRegistrationClient(), csr, credentials());

        // then
        assertThatThrownBy(complete).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
        assertThat(logged.list)
                .filteredOn(event -> event.getLevel() == Level.WARN)
                .extracting(ILoggingEvent::getFormattedMessage)
                .singleElement()
                .satisfies(line -> assertThat(line).contains(registrationUuid.toString()));
        verifyNoInteractions(clientOperationExternalService);
    }

    @Test
    void throwsIllegalState_whenRegistrationClientPresentedNoPassword() {
        // given — the authenticator of certificateRegistration accepts no client without a Basic password
        stubRegistration(CertificateState.REGISTERED, null);
        EstClientCredentials noCredentials = EstClientCredentialsFixtures.noCredentials();

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aRegistrationClient(), csr, noCredentials);

        // then
        assertThatThrownBy(enroll).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(clientOperationExternalService);
    }

    @ParameterizedTest
    @MethodSource("statesThatWaitForTheClientToCallAgain")
    void answersAcceptedAtOnce_whenRetryFindsTheCertificateOnItsWay(CertificateState state) {
        // given
        when(certificateRepository
                .findLatestRequestedThroughEst(route.raProfile().getUuid(), route.estProfile().getUuid(),
                        fingerprintOfTheCsr()))
                .thenReturn(Optional.of(new FoundCertificate(certificateUuid, state, null, fingerprintOfTheCsr())));

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        verifyNoInteractions(issuanceWait, clientOperationService);
    }

    @ParameterizedTest
    @EnumSource(value = EstAuthenticationPolicy.class, names = {"RA_BASIC", "VENDOR_MTLS", "RA_MTLS"})
    void submitsOnce_whenPolicyIsAuthenticated(EstAuthenticationPolicy policy) throws Exception {
        // given
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.of(CertificateState.PENDING_APPROVAL));
        EstClient client = new EstClient(policy, "secret:" + UUID.randomUUID(), null);

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, client, csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
    }

    @Test
    void answersUnavailableAndLogsClassNamesOnly_whenThePlatformShapedTheFailure() throws Exception {
        // given — the platform logged what it caught and kept its validation text without the cause
        var failure = new CertificateOperationException("Failed to submit certificate request: " + ECHOED_TEXT);
        stubSubmissionFailure(failure);

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE));
        assertLoggedClassNamesOnly(failure);
        verifyNoInteractions(issuanceWait);
    }

    @Test
    void answersUnavailable_whenSubmissionFailsCheckedBeforeTheCertificateIsStored() throws Exception {
        // given
        stubSubmissionFailure(new NotFoundException("RA profile"));

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE));
        verifyNoInteractions(issuanceWait);
    }

    @Test
    void answersAcceptedWithoutReadingAgain_whenWaitEndsWithTheRequestAttached() throws Exception {
        // given — the wait read the certificate with this request, so nothing needs to be read again
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.of(CertificateState.REGISTERED));

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        verify(certificateRepository, never()).findEstRequestedCertificateByUuid(any());
    }

    @Test
    void throwsIllegalState_whenSubmittedCertificateNoLongerCarriesItsRequest() throws Exception {
        // given
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.empty());

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void answersIssuedCertificate_whenSubmittedCertificateIsIssued() throws Exception {
        // given
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.of(CertificateState.ISSUED));
        X509Certificate issued = stubIssuedContent(certificateUuid);

        // when
        ResponseEntity<byte[]> response = enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateOf(response)).isEqualTo(issued);
    }

    @Test
    void throwsIllegalState_whenIssuedCertificateHoldsNoContentForTheRequest() throws Exception {
        // given
        stubSubmission();
        when(issuanceWait.awaitSettled(certificateUuid, fingerprintOfTheCsr(), DOCUMENTED_ISSUE_WAIT))
                .thenReturn(Optional.of(CertificateState.ISSUED));
        when(certificateRepository.findContentByUuidAndRequestFingerprint(certificateUuid, fingerprintOfTheCsr()))
                .thenReturn(Optional.empty());

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void throwsPolicyViolationWithTheMessageAsDetail_whenRequestAttributePolicyIsViolated() throws Exception {
        // given
        String policyText = "The request does not carry a common name.";
        stubSubmissionFailure(new RequestAttributePolicyViolationException(policyText, List.of(policyText)));

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(EstError.POLICY_VIOLATION);
            assertThat(refusal.detail()).contains(policyText);
            assertThat(refusal.realm()).contains(LABEL);
        });
    }

    @Test
    void throwsIssuanceFailedAndLogsTheException_whenQueueingTheIssueFails() throws Exception {
        // given — the request is stored, and publishing its issue fails
        var failure = new IllegalStateException("The broker cannot be reached.");
        stubQueueingFailure(failure);

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_FAILED));
        assertThat(errorEvents()).singleElement().satisfies(event -> {
            assertThat(event.getThrowableProxy()).isNotNull();
            assertThat(event.getThrowableProxy().getClassName()).isEqualTo(failure.getClass().getName());
        });
        verifyNoInteractions(issuanceWait);
    }

    @Test
    void throwsIssuanceFailed_whenQueueingFailsCheckedAfterTheCertificateIsStored() throws Exception {
        // given
        stubQueueingFailure(new CertificateOperationException("queueing failed"));

        // when
        ThrowingCallable enroll = () -> enrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_FAILED));
    }

    static Stream<CertificateState> statesThatWaitForTheClientToCallAgain() {
        return Stream.of(CertificateState.REQUESTED, CertificateState.PENDING_APPROVAL, CertificateState.PENDING_ISSUE);
    }

    static Stream<Exception> refusalsOfTheCompletion() {
        return Stream
                .of(new ValidationException("The certificate registration challenge is invalid."),
                        new NotFoundException("The certificate of the registration is gone."));
    }

    @Test
    void carriesTheOnStoredHookInTheProtocolInfo_whenSubmitting() throws Exception {
        // given
        Consumer<UUID> onStored = storedUuid -> {
        };
        EstEnrollment claimingEnrollment = enrollmentSubmittingWith(onStored);
        when(issueRequests.newRequest(route, csr)).thenReturn(new ClientCertificateIssueRequestDto());
        when(clientOperationService.issueCertificate(any(SecuredParentUUID.class), any(), any(), any(), any()))
                .thenThrow(new IllegalStateException("stop after capturing"));

        // when
        ThrowingCallable enroll = () -> claimingEnrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).isInstanceOf(EstException.class);
        ArgumentCaptor<CertificateProtocolInfo> info = ArgumentCaptor.forClass(CertificateProtocolInfo.class);
        verify(clientOperationService)
                .issueCertificate(any(SecuredParentUUID.class), any(), any(), info.capture(), any());
        assertThat(info.getValue().getProtocol()).isEqualTo(CertificateProtocol.EST);
        assertThat(info.getValue().getProtocolProfileUuid()).isEqualTo(route.estProfile().getUuid());
        assertThat(info.getValue().getOnStored()).isSameAs(onStored);
    }

    @Test
    void rethrowsTheLostClaimUnmapped_whenSubmissionFailsBecauseTheClaimWasTakenOver() throws Exception {
        // given
        EstEnrollment claimingEnrollment = enrollmentSubmittingWith(storedUuid -> {
        });
        var claimLost = new EstRequestClaimLostException(UUID.randomUUID());
        when(issueRequests.newRequest(route, csr)).thenReturn(new ClientCertificateIssueRequestDto());
        when(clientOperationService.issueCertificate(any(SecuredParentUUID.class), any(), any(), any(), any()))
                .thenThrow(shapedFailureCausedBy(claimLost));

        // when
        ThrowingCallable enroll = () -> claimingEnrollment.enroll(route, aClient(), csr, credentials());

        // then
        assertThatThrownBy(enroll).isSameAs(claimLost);
    }

    private void stubSubmissionFailure(Exception failure) throws Exception {
        when(issueRequests.newRequest(route, csr)).thenReturn(new ClientCertificateIssueRequestDto());
        when(clientOperationService.issueCertificate(any(SecuredParentUUID.class), any(), any(), any(), any()))
                .thenThrow(failure);
    }

    /** The request is stored and the step before queueing ran, so the failure comes from queueing its issue. */
    private void stubQueueingFailure(Exception failure) throws Exception {
        when(issueRequests.newRequest(route, csr)).thenReturn(new ClientCertificateIssueRequestDto());
        when(clientOperationService.issueCertificate(any(SecuredParentUUID.class), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    Consumer<UUID> beforeDispatch = invocation.getArgument(4);
                    beforeDispatch.accept(certificateUuid);
                    throw failure;
                });
    }

    /** An enrolment whose claims helper submits once with the hook, as it does for the winner, and answers nothing. */
    private EstEnrollment enrollmentSubmittingWith(Consumer<UUID> onStored) {
        when(claims.answerOnce(any(), any(), any(), any(), any())).thenAnswer(invocation -> {
            ClaimedRequest request = invocation.getArgument(4);
            request.submit(onStored);
            return null;
        });
        return new EstEnrollment(clientOperationService, clientOperationExternalService, certificateService,
                certificateRepository, issueRequests, issuanceWait, new EstAnswers(certificateRepository), claims);
    }

    private EstEnrollment enrollmentAnsweringPending() {
        return new EstEnrollment(clientOperationService, clientOperationExternalService, certificateService,
                certificateRepository, issueRequests, issuanceWait, new EstAnswers(certificateRepository),
                new EstRequestClaims(claimWriter, issuanceWait));
    }

    private void stubSubmission() throws Exception {
        when(issueRequests.newRequest(route, csr)).thenReturn(new ClientCertificateIssueRequestDto());
        ClientCertificateDataResponseDto submitted = new ClientCertificateDataResponseDto();
        submitted.setUuid(certificateUuid.toString());
        when(clientOperationService
                .issueCertificate(any(SecuredParentUUID.class), any(), any(ClientCertificateIssueRequestDto.class),
                        argThat(this::isAttributedToTheEstProfile), any()))
                .thenReturn(submitted);
    }

    private boolean isAttributedToTheEstProfile(CertificateProtocolInfo info) {
        return info.getProtocol() == CertificateProtocol.EST
                && route.estProfile().getUuid().equals(info.getProtocolProfileUuid());
    }

    private static EstClient aClient() {
        return new EstClient(EstAuthenticationPolicy.RA_BASIC, "secret:" + UUID.randomUUID(), null);
    }

    private EstClient aRegistrationClient() {
        return new EstClient(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, "registration:" + registrationUuid,
                registrationUuid);
    }

    private static EstClientCredentials credentials() {
        return EstClientCredentialsFixtures.basicCredentials("user", PASSWORD);
    }

    private void stubRegistration(CertificateState state, String requestFingerprint) {
        stubRegistration(state, null, requestFingerprint);
    }

    private void stubRegistration(CertificateState state, Date notAfter, String requestFingerprint) {
        when(certificateRepository.findEstRequestedCertificateByUuid(registrationUuid))
                .thenReturn(Optional.of(registration(state, notAfter, requestFingerprint)));
    }

    private ClientCertificateIssueRequestDto stubCompletionRequest() {
        ClientCertificateIssueRequestDto completion = new ClientCertificateIssueRequestDto();
        when(issueRequests.completionRequest(route, csr, PASSWORD)).thenReturn(completion);
        return completion;
    }

    private void stubCompletionFailure(Exception failure) throws Exception {
        stubRegistration(CertificateState.REGISTERED, null);
        stubCompletionRequest();
        when(clientOperationExternalService.issueExistingCertificate(any(), any(), any(), any())).thenThrow(failure);
    }

    /** The issued certificate is read only while the certificate still carries this request. */
    private X509Certificate stubIssuedContent(UUID uuid) throws Exception {
        X509Certificate issued = PkiFixtures.clientCertificate(PkiFixtures.rootCa("EST Issuing Root"));
        when(certificateRepository.findContentByUuidAndRequestFingerprint(uuid, fingerprintOfTheCsr()))
                .thenReturn(Optional.of(Base64.getEncoder().encodeToString(issued.getEncoded())));
        return issued;
    }

    private String fingerprintOfTheCsr() {
        try {
            return CertificateUtil.getThumbprint(csr.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private FoundCertificate registration(CertificateState state, Date notAfter, String requestFingerprint) {
        return new FoundCertificate(registrationUuid, state, notAfter, requestFingerprint);
    }

    private record FoundCertificate(UUID uuid, CertificateState state, Date notAfter,
            String requestFingerprint) implements EstRequestedCertificate {

        @Override
        public UUID getUuid() {
            return uuid;
        }

        @Override
        public CertificateState getState() {
            return state;
        }

        @Override
        public Date getNotAfter() {
            return notAfter;
        }

        @Override
        public String getRequestFingerprint() {
            return requestFingerprint;
        }
    }

    private static X509Certificate certificateOf(ResponseEntity<byte[]> response) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(response.getBody());
        var held = new CMSSignedData(der).getCertificates().getMatches(null);
        assertThat(held).hasSize(1);
        return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) held.iterator().next());
    }

    private void assertRefusal(Throwable thrown, EstError error) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(error);
            assertThat(refusal.realm()).contains(LABEL);
        });
    }

    /** One ERROR line names the class of the failure, and carries neither its text nor its stack trace. */
    private void assertLoggedClassNamesOnly(Exception failure) {
        assertThat(errorEvents()).singleElement().satisfies(event -> {
            assertThat(event.getThrowableProxy()).isNull();
            assertThat(event.getFormattedMessage()).contains(failure.getClass().getName()).doesNotContain(ECHOED_TEXT);
        });
    }

    private List<ILoggingEvent> errorEvents() {
        return logged.list.stream().filter(event -> event.getLevel() == Level.ERROR).toList();
    }

    private static CertificateOperationException shapedFailureCausedBy(Throwable cause) {
        var shapedFailure = new CertificateOperationException("Failed to submit");
        shapedFailure.initCause(cause);
        return shapedFailure;
    }
}
