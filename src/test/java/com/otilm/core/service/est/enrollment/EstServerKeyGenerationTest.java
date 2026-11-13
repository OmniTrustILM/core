package com.otilm.core.service.est.enrollment;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.aop.AuditOperationDataOverride;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.ApprovalProfileRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.enrollment.EstKeyRecovery.NoSignatureAlgorithmException;
import com.otilm.core.service.est.enrollment.EstKeyRecovery.TokenKey;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstServerKeyGenerationRequest.Content;
import com.otilm.core.service.v2.CancelConfirmation;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.EstClientCredentialsFixtures;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.EstServerKeyGenerationAnswers;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.SignatureVerificationBoundsFixtures;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstServerKeyGenerationTest {

    private static final String LABEL = "devices";
    private static final String CLIENT_SUBJECT = "CN=device-1";
    private static final String CLIENT_DNS_NAME = "device-1.example";
    private static final int SERVER_KEYGEN_TIMEOUT_SECONDS = 42;
    private static final Duration SERVER_KEYGEN_TIMEOUT = Duration.ofSeconds(SERVER_KEYGEN_TIMEOUT_SECONDS);

    @Mock
    private EstEnrollment enrollment;

    @Mock
    private EstKeyRecovery keyRecovery;

    @Mock
    private EstIssuanceWait issuanceWait;

    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private ClientOperationExternalService clientOperationService;

    @Mock
    private ApprovalProfileRelationRepository approvalProfileRelationRepository;

    @Mock
    private AuditOperationDataOverride auditOperationDataOverride;

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger generationLogger = (Logger) LoggerFactory.getLogger(EstServerKeyGeneration.class);
    private Level previousLevel;
    private boolean previousAdditive;

    private EstServerKeyGeneration serverKeyGeneration;
    private RaProfile raProfile;
    private final UUID certificateUuid = UUID.randomUUID();

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** The logger is a process-wide singleton, so what is set on it here is taken off again after each test. */
    @BeforeEach
    void createServerKeyGenerationAndCaptureTheLog() {
        serverKeyGeneration = new EstServerKeyGeneration(enrollment, keyRecovery, issuanceWait,
                new EstAnswers(certificateRepository), clientOperationService, approvalProfileRelationRepository);
        serverKeyGeneration.setAuditOperationDataOverride(auditOperationDataOverride);
        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        previousLevel = generationLogger.getLevel();
        previousAdditive = generationLogger.isAdditive();
        generationLogger.setLevel(Level.DEBUG);
        generationLogger.setAdditive(false);
        logged.start();
        generationLogger.addAppender(logged);
    }

    @AfterEach
    void releaseTheLog() {
        RequestContextHolder.resetRequestAttributes();
        generationLogger.detachAppender(logged);
        generationLogger.setLevel(previousLevel);
        generationLogger.setAdditive(previousAdditive);
    }

    // ── RequireAvailable ──────────────────────────────────────────────────────

    @Nested
    class RequireAvailable {

        @Test
        void throwsDisabledWithTheRealm_whenTheEstProfileDoesNotGenerateKeys() {
            // given
            EstRoute route = routeGeneratingKeys(false);

            // when
            ThrowingCallable requireAvailable = () -> serverKeyGeneration.requireAvailable(route);

            // then
            assertThatThrownBy(requireAvailable)
                    .satisfies(thrown -> assertRefusal(thrown, EstError.SERVER_KEYGEN_DISABLED));
            verifyNoInteractions(approvalProfileRelationRepository);
        }

        @Test
        void throwsUnavailableWithTheRealm_whenTheRaProfileAsksForAnApproval() {
            // given
            EstRoute route = routeGeneratingKeys(true);
            when(approvalProfileRelationRepository
                    .existsByResourceAndResourceUuid(Resource.RA_PROFILE, raProfile.getUuid())).thenReturn(true);

            // when
            ThrowingCallable requireAvailable = () -> serverKeyGeneration.requireAvailable(route);

            // then
            assertThatThrownBy(requireAvailable)
                    .satisfies(thrown -> assertRefusal(thrown, EstError.SERVER_KEYGEN_UNAVAILABLE));
        }

        @Test
        void acceptsTheRoute_whenItGeneratesKeysWithoutApproval() {
            // given
            EstRoute route = routeGeneratingKeys(true);

            // when
            ThrowingCallable requireAvailable = () -> serverKeyGeneration.requireAvailable(route);

            // then
            assertThatCode(requireAvailable).doesNotThrowAnyException();
        }
    }

    // ── Generate ──────────────────────────────────────────────────────────────

    @Nested
    class Generate {

        private final EstClientCredentials credentials = EstClientCredentialsFixtures
                .basicCredentials("device-owner", "p4ssw0rd");

        private EstRoute route;
        private Pkcs10CertificateRequest clientCsr;

        @BeforeEach
        void createRouteAndClientRequest() throws Exception {
            route = routeGeneratingKeys(true);
            clientCsr = new Pkcs10CertificateRequest(
                    Base64.getDecoder().decode(EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT, CLIENT_DNS_NAME)));
        }

        @Test
        void answersWithTheGeneratedKeyAndItsCertificate_whenTheCertificateIsIssued() throws Exception {
            // given
            AtomicReference<Pkcs10CertificateRequest> submitted = submitAndCertify(CertificateState.ISSUED);

            // when
            ResponseEntity<byte[]> response = serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            byte[] key = EstServerKeyGenerationAnswers.keyOf(response);
            X509Certificate certificate = EstServerKeyGenerationAnswers.certificateOf(response);
            assertThat(EstServerKeyGenerationAnswers.isKeyOf(key, certificate, "SHA256withECDSA")).isTrue();
            assertThat(certificate.getPublicKey()).isEqualTo(submitted.get().getPublicKey());
        }

        @ParameterizedTest
        @MethodSource("clientKeysOfOtherTypes")
        void answersWithAKeyOfTheClientsType_whenTheCertificateCertifiesIt(SubjectPublicKeyInfo clientKey,
                String signatureAlgorithm) throws Exception {
            // given
            var clientRequest = new Pkcs10CertificateRequest(
                    Base64.getDecoder().decode(EstCsrFixtures.requestBodyWithPublicKey(clientKey)));
            submitAndCertify(CertificateState.ISSUED);

            // when
            ResponseEntity<byte[]> response = serverKeyGeneration
                    .generate(route, aClient(), clientRequest, credentials);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            byte[] key = EstServerKeyGenerationAnswers.keyOf(response);
            X509Certificate certificate = EstServerKeyGenerationAnswers.certificateOf(response);
            assertThat(EstServerKeyGenerationAnswers.isKeyOf(key, certificate, signatureAlgorithm)).isTrue();
        }

        @Test
        void throwsBadRequestWithTheRealmWithoutSubmitting_whenNoKeyCanBeGeneratedLikeTheClients() throws Exception {
            // given
            var tooShortToGenerate = 384;
            var clientRequest = new Pkcs10CertificateRequest(Base64
                    .getDecoder()
                    .decode(EstCsrFixtures
                            .requestBodyWithRsaPublicKey(PKCSObjectIdentifiers.rsaEncryption, tooShortToGenerate,
                                    RSAKeyGenParameterSpec.F4)));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration
                    .generate(route, aClient(), clientRequest, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.BAD_REQUEST));
            verifyNoInteractions(enrollment);
        }

        @Test
        void submitsARequestOfANewKeyForTheClientsSubject_whenGenerating() throws Exception {
            // given
            AtomicReference<Pkcs10CertificateRequest> submitted = submitAndCertify(CertificateState.ISSUED);

            // when
            serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            Pkcs10CertificateRequest request = submitted.get();
            assertThat(request.getSubject()).isEqualTo(clientCsr.getSubject());
            assertThat(request.getSubjectAlternativeNames()).isEqualTo(clientCsr.getSubjectAlternativeNames());
            assertThat(request.getPublicKey()).isNotEqualTo(clientCsr.getPublicKey());
            assertThat(request
                    .getJcaObject()
                    .isSignatureValid(new JcaContentVerifierProviderBuilder()
                            .build(request.getJcaObject().getSubjectPublicKeyInfo())))
                    .isTrue();
        }

        @Test
        void waitsWithTheServerKeyGenerationTimeoutOfTheProfile_whenGenerating() throws Exception {
            // given
            AtomicReference<Pkcs10CertificateRequest> submitted = submitAndCertify(CertificateState.ISSUED);

            // when
            serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            String submittedFingerprint = CertificateUtil.getThumbprint(submitted.get().getEncoded());
            verify(issuanceWait)
                    .awaitSettledThroughStatusPolls(certificateUuid, submittedFingerprint, SERVER_KEYGEN_TIMEOUT);
        }

        @Test
        void completesTheRegistrationOfTheClient_whenTheClientIsIdentifiedByItsRegistration() throws Exception {
            // given
            UUID registrationUuid = UUID.randomUUID();
            EstClient registrationClient = new EstClient(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION,
                    "registration:" + registrationUuid, registrationUuid);
            when(enrollment
                    .completeRegistration(eq(route), eq(registrationClient), any(Pkcs10CertificateRequest.class),
                            eq(credentials)))
                    .thenReturn(registrationUuid);
            when(issuanceWait
                    .awaitSettledThroughStatusPolls(eq(registrationUuid), anyString(), eq(SERVER_KEYGEN_TIMEOUT)))
                    .thenReturn(Optional.of(CertificateState.REJECTED));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration
                    .generate(route, registrationClient, clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.REQUEST_REJECTED));
            verify(enrollment, never()).submit(any(), any());
        }

        @ParameterizedTest
        @MethodSource("refusedStates")
        void throwsTheRefusalOfTheStateWithoutCancelling_whenTheCertificateIsNotIssued(CertificateState state,
                EstError error) {
            // given
            submitAndSettle(state);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, error));
            verifyNoInteractions(clientOperationService);
        }

        @Test
        void cancelsTheIssueAndThrowsTimedOut_whenTheCertificateIsStillPendingIssue() throws Exception {
            // given
            submitAndSettle(CertificateState.PENDING_ISSUE);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
            ArgumentCaptor<CancelPendingCertificateRequestDto> cancel = ArgumentCaptor
                    .forClass(CancelPendingCertificateRequestDto.class);
            verify(clientOperationService)
                    .cancelPendingCertificateOperationWithConfirmation(
                            argThat(authority -> authority
                                    .toString()
                                    .equals(raProfile.getAuthorityInstanceReference().getUuid().toString())),
                            argThat(securedRaProfile -> securedRaProfile
                                    .toString()
                                    .equals(raProfile.getUuid().toString())),
                            eq(certificateUuid.toString()), cancel.capture());
            assertThat(cancel.getValue().getReason()).isNotBlank();
        }

        @ParameterizedTest
        @EnumSource(CancelConfirmation.class)
        void throwsTimedOut_whenTheCancelOfAKeyGeneratedInMemoryEndsWithAnyConfirmation(CancelConfirmation confirmation)
                throws Exception {
            // given
            submitAndSettle(CertificateState.PENDING_ISSUE);
            when(clientOperationService
                    .cancelPendingCertificateOperationWithConfirmation(any(), any(), anyString(), any()))
                    .thenReturn(confirmation);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
        }

        @Test
        void throwsTimedOutAndLogsTheCertificate_whenTheAuthorityRefusesTheCancel() throws Exception {
            // given
            submitAndSettle(CertificateState.PENDING_ISSUE);
            when(clientOperationService
                    .cancelPendingCertificateOperationWithConfirmation(any(), any(), anyString(), any()))
                    .thenThrow(new ValidationException("past the point of no return"));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.WARN)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .anyMatch(line -> line.contains(certificateUuid.toString()) && line.contains("cancelled"));
        }

        @Test
        void recordsAndLogsTheAnswerOnce_whenTheCertificateIsIssued() throws Exception {
            // given
            submitAndCertify(CertificateState.ISSUED);
            EstClient client = aClient();
            enterARequest();

            // when
            serverKeyGeneration.generate(route, client, clientCsr, credentials);

            // then
            verify(auditOperationDataOverride)
                    .set(new EstServerKeyGenerationAudit(LABEL, client.policy(), client.identity(),
                            EstServerKeyGenerationMode.IN_MEMORY, EstEnrollmentAudit.ISSUED));
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.INFO)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line)
                            .contains(EstEnrollmentAudit.ISSUED, "in-memory", certificateUuid.toString(),
                                    client.identity(), LABEL));
        }

        @Test
        void recordsTheRefusal_whenTheCertificateIsRefused() {
            // given
            submitAndSettle(CertificateState.FAILED);
            EstClient client = aClient();
            enterARequest();

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, client, clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isInstanceOf(EstException.class);
            verify(auditOperationDataOverride)
                    .set(new EstServerKeyGenerationAudit(LABEL, client.policy(), client.identity(),
                            EstServerKeyGenerationMode.IN_MEMORY, EstError.ISSUANCE_FAILED.name()));
        }

        @Test
        void logsTheRefusalOnceAtInfo_whenTheCertificateIsRefused() {
            // given
            submitAndSettle(CertificateState.FAILED);
            EstClient client = aClient();

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, client, clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isInstanceOf(EstException.class);
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.INFO)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line)
                            .contains(EstError.ISSUANCE_FAILED.name(), "in-memory", certificateUuid.toString(),
                                    client.identity(), LABEL));
        }

        @Test
        void logsTheTimeoutOnceAtInfo_whenTheCertificateIsNotIssuedInTime() {
            // given
            submitAndSettle(CertificateState.REQUESTED);
            EstClient client = aClient();

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, client, clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.INFO)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line)
                            .contains(EstError.ISSUANCE_TIMED_OUT.name(), certificateUuid.toString(),
                                    client.identity()));
        }

        @Test
        void logsTheCertificateAtWarn_whenTheCertificateIsRefused() {
            // given
            submitAndSettle(CertificateState.FAILED);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isInstanceOf(EstException.class);
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.WARN)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line).contains(certificateUuid.toString()));
        }

        @Test
        void throwsIssuanceFailed_whenTheCertificateNoLongerCarriesTheRequest() {
            // given
            when(enrollment.submit(eq(route), any(Pkcs10CertificateRequest.class))).thenReturn(certificateUuid);
            when(issuanceWait
                    .awaitSettledThroughStatusPolls(eq(certificateUuid), anyString(), eq(SERVER_KEYGEN_TIMEOUT)))
                    .thenReturn(Optional.empty());

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_FAILED));
        }

        @Test
        void throwsRegistrationRejected_whenTheRegistrationLosesTheRequestDuringTheWait() {
            // given
            UUID registrationUuid = UUID.randomUUID();
            EstClient registrationClient = new EstClient(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION,
                    "registration:" + registrationUuid, registrationUuid);
            when(enrollment
                    .completeRegistration(eq(route), eq(registrationClient), any(Pkcs10CertificateRequest.class),
                            eq(credentials)))
                    .thenReturn(registrationUuid);
            when(issuanceWait
                    .awaitSettledThroughStatusPolls(eq(registrationUuid), anyString(), eq(SERVER_KEYGEN_TIMEOUT)))
                    .thenReturn(Optional.empty());

            // when
            ThrowingCallable generate = () -> serverKeyGeneration
                    .generate(route, registrationClient, clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED));
        }

        @Test
        void throwsInternalErrorAndLogsTheCertificate_whenTheCertificateCertifiesAnotherKey() {
            // given
            var anotherKey = PkiFixtures.keyPair();
            submitAndSettle(CertificateState.ISSUED);
            when(certificateRepository.findContentByUuidAndRequestFingerprint(eq(certificateUuid), anyString()))
                    .thenReturn(Optional.of(certificateContentFor(anotherKey)));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.INTERNAL_ERROR));
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.ERROR)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line).contains(certificateUuid.toString()));
            verifyNoInteractions(clientOperationService);
        }

        @Test
        void throwsIllegalState_whenTheIssuedCertificateHoldsNoContentForTheRequest() {
            // given
            submitAndSettle(CertificateState.ISSUED);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isInstanceOf(IllegalStateException.class);
        }

        @ParameterizedTest
        @EnumSource(value = CertificateState.class, names = {"REVOKED", "PENDING_REVOKE"})
        void throwsIllegalState_whenTheCertificateReachesAStateThatNoIssueReaches(CertificateState state) {
            // given
            submitAndSettle(state);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isInstanceOf(IllegalStateException.class).hasMessageContaining(state.name());
        }

        @Test
        void passesTheRefusalOfTheSubmissionOn_whenTheRequestCannotBeSubmitted() {
            // given
            EstException unavailable = new EstException(EstError.SERVICE_UNAVAILABLE, LABEL);
            doThrow(unavailable).when(enrollment).submit(eq(route), any(Pkcs10CertificateRequest.class));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(unavailable);
            verifyNoInteractions(issuanceWait);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> refusedStates() {
            return Stream
                    .of(arguments(CertificateState.REJECTED, EstError.REQUEST_REJECTED),
                            arguments(CertificateState.FAILED, EstError.ISSUANCE_FAILED),
                            arguments(CertificateState.REQUESTED, EstError.ISSUANCE_TIMED_OUT),
                            arguments(CertificateState.PENDING_APPROVAL, EstError.ISSUANCE_TIMED_OUT),
                            arguments(CertificateState.REGISTERED, EstError.ISSUANCE_TIMED_OUT));
        }

        private void submitAndSettle(CertificateState state) {
            when(enrollment.submit(eq(route), any(Pkcs10CertificateRequest.class))).thenReturn(certificateUuid);
            when(issuanceWait
                    .awaitSettledThroughStatusPolls(eq(certificateUuid), anyString(), eq(SERVER_KEYGEN_TIMEOUT)))
                    .thenReturn(Optional.of(state));
        }

        /**
         * Submits the request, settles its certificate in the state and stores a certificate for its public key as the
         * content of the certificate.
         */
        private AtomicReference<Pkcs10CertificateRequest> submitAndCertify(CertificateState state) {
            AtomicReference<Pkcs10CertificateRequest> submitted = new AtomicReference<>();
            when(enrollment.submit(eq(route), any(Pkcs10CertificateRequest.class))).thenAnswer(invocation -> {
                submitted.set(invocation.getArgument(1));
                return certificateUuid;
            });
            when(issuanceWait
                    .awaitSettledThroughStatusPolls(eq(certificateUuid), anyString(), eq(SERVER_KEYGEN_TIMEOUT)))
                    .thenReturn(Optional.of(state));
            when(certificateRepository.findContentByUuidAndRequestFingerprint(eq(certificateUuid), anyString()))
                    .thenAnswer(invocation -> Optional
                            .of(certificateContentFor(new KeyPair(publicKeyOf(submitted.get()), null))));
            return submitted;
        }

        static Stream<Arguments> clientKeysOfOtherTypes() throws Exception {
            SubjectPublicKeyInfo rsaPssKey = SignatureVerificationBoundsFixtures
                    .rsaPublicKeyInfo(PKCSObjectIdentifiers.id_RSASSA_PSS, 2048, RSAKeyGenParameterSpec.F4);
            return Stream
                    .of(arguments(named("ML-DSA-44", clientKeyOf("ML-DSA-44")), "ML-DSA"),
                            arguments(named("Ed25519", clientKeyOf("Ed25519")), "Ed25519"),
                            arguments(named("SLH-DSA-SHA2-128F", clientKeyOf("SLH-DSA-SHA2-128F")), "SLH-DSA"),
                            arguments(named("Falcon-512", clientKeyOf("Falcon-512")), "Falcon"),
                            arguments(named("RSASSA-PSS, answered with an rsaEncryption key", rsaPssKey),
                                    "SHA256withRSA"));
        }

        private static SubjectPublicKeyInfo clientKeyOf(String algorithm) throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            return SubjectPublicKeyInfo.getInstance(generator.generateKeyPair().getPublic().getEncoded());
        }

        /** The public key of the request as BouncyCastle reads it, which reads every type a key is generated for. */
        private static PublicKey publicKeyOf(Pkcs10CertificateRequest request) throws Exception {
            return new JcaPKCS10CertificationRequest(request.getEncoded())
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getPublicKey();
        }

        private static EstClient aClient() {
            return new EstClient(EstAuthenticationPolicy.RA_BASIC, "secret:" + UUID.randomUUID(), null);
        }
    }

    // ── KeyRecovery ───────────────────────────────────────────────────────────

    @Nested
    class KeyRecovery {

        private final EstClientCredentials credentials = EstClientCredentialsFixtures
                .basicCredentials("device-owner", "p4ssw0rd");
        private final KeyPair tokenKeyPair = PkiFixtures.keyPair();

        private EstRoute route;
        private Pkcs10CertificateRequest clientCsr;
        private Pkcs10CertificateRequest tokenSignedRequest;
        private TokenKey tokenKey;

        @BeforeEach
        void createRouteAndTokenKey() throws Exception {
            route = routeRecoveringKeys();
            clientCsr = new Pkcs10CertificateRequest(
                    Base64.getDecoder().decode(EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT, CLIENT_DNS_NAME)));
            tokenSignedRequest = new Pkcs10CertificateRequest(
                    Base64.getDecoder().decode(EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT)));
            tokenKey = new TokenKey(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                    SubjectPublicKeyInfo.getInstance(tokenKeyPair.getPublic().getEncoded()));
        }

        @Test
        void answersWithTheExportedKeyAndKeepsIt_whenTheCertificateIsIssued() throws Exception {
            // given
            submitSignedRequestAndSettle(CertificateState.ISSUED);
            storeCertificateFor(tokenKeyPair);
            when(keyRecovery.export(tokenKey)).thenReturn(privateKeyInfoOf(tokenKeyPair));
            when(keyRecovery.publicKeyOf(any())).thenReturn(Optional.of(tokenKeyPair.getPublic()));

            // when
            ResponseEntity<byte[]> response = serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            byte[] key = EstServerKeyGenerationAnswers.keyOf(response);
            X509Certificate certificate = EstServerKeyGenerationAnswers.certificateOf(response);
            assertThat(EstServerKeyGenerationAnswers.isKeyOf(key, certificate, "SHA256withECDSA")).isTrue();
            assertThat(certificate.getPublicKey()).isEqualTo(tokenKeyPair.getPublic());
            verify(keyRecovery, never()).destroy(any(), any());
        }

        @Test
        void recordsAndLogsTheAnswerWithTheKeyOnce_whenTheCertificateIsIssued() throws Exception {
            // given
            submitSignedRequestAndSettle(CertificateState.ISSUED);
            storeCertificateFor(tokenKeyPair);
            when(keyRecovery.export(tokenKey)).thenReturn(privateKeyInfoOf(tokenKeyPair));
            when(keyRecovery.publicKeyOf(any())).thenReturn(Optional.of(tokenKeyPair.getPublic()));
            EstClient client = aClient();
            enterARequest();

            // when
            serverKeyGeneration.generate(route, client, clientCsr, credentials);

            // then
            verify(auditOperationDataOverride)
                    .set(new EstServerKeyGenerationAudit(LABEL, client.policy(), client.identity(),
                            EstServerKeyGenerationMode.KEY_RECOVERY, EstEnrollmentAudit.ISSUED));
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.INFO)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line)
                            .contains("key-recovery", certificateUuid.toString(), tokenKey.keyUuid().toString(),
                                    client.identity()));
        }

        @Test
        void signsTheRequestWithTheTokenKeyForTheClientsContent_whenRecoveringKeys() throws Exception {
            // given
            ArgumentCaptor<Content> signed = ArgumentCaptor.forClass(Content.class);
            submitSignedRequestAndSettle(CertificateState.REJECTED);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isInstanceOf(EstException.class);
            verify(keyRecovery).signRequest(eq(tokenKey), signed.capture());
            assertThat(signed.getValue().subject()).isEqualTo(clientCsr.getJcaObject().getSubject());
            verify(enrollment, never()).submit(any(), any());
        }

        @Test
        void throwsUnavailableWithoutDestroying_whenTheKeyCannotBeCreated() throws Exception {
            // given
            when(keyRecovery.create(route)).thenThrow(new ConnectorException("token unreachable"));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE));
            verify(keyRecovery, never()).destroy(any(), any());
            verifyNoInteractions(enrollment, issuanceWait);
        }

        @Test
        void throwsUnavailableAndDestroysTheKeyOnce_whenTheTokenCannotSignTheRequest() throws Exception {
            // given
            when(keyRecovery.create(route)).thenReturn(tokenKey);
            when(keyRecovery.signRequest(eq(tokenKey), any())).thenThrow(new IOException("signing failed"));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE));
            verify(keyRecovery).destroy(null, tokenKey);
            verifyNoInteractions(enrollment, issuanceWait);
        }

        @Test
        void throwsInternalErrorAndDestroysTheKeyOnce_whenThePlatformSignsWithNoAlgorithmOfTheKey() throws Exception {
            // given
            var noSignatureAlgorithm = new NoSignatureAlgorithmException("Ed25519");
            when(keyRecovery.create(route)).thenReturn(tokenKey);
            when(keyRecovery.signRequest(eq(tokenKey), any())).thenThrow(noSignatureAlgorithm);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.INTERNAL_ERROR));
            verify(keyRecovery).destroy(null, tokenKey);
            verifyNoInteractions(enrollment, issuanceWait);
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.ERROR)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line).contains(tokenKey.keyUuid().toString()));
        }

        @Test
        void throwsUnavailableAndDestroysTheKeyOnce_whenSigningFailsInsideThePlatform() throws Exception {
            // given
            var platformFailure = new IllegalStateException("the connector said something");
            when(keyRecovery.create(route)).thenReturn(tokenKey);
            when(keyRecovery.signRequest(eq(tokenKey), any())).thenThrow(platformFailure);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE));
            verify(keyRecovery).destroy(null, tokenKey);
            verifyNoInteractions(enrollment, issuanceWait);
        }

        @Test
        void passesTheRefusalOnAndDestroysTheKeyOnce_whenTheRequestCannotBeSubmitted() throws Exception {
            // given
            EstException unavailable = new EstException(EstError.SERVICE_UNAVAILABLE, LABEL);
            when(keyRecovery.create(route)).thenReturn(tokenKey);
            when(keyRecovery.signRequest(eq(tokenKey), any())).thenReturn(tokenSignedRequest);
            when(enrollment
                    .submitForKey(eq(route), eq(tokenSignedRequest), eq(tokenKey.keyUuid()),
                            eq(tokenKey.tokenProfileUuid()), any()))
                    .thenThrow(unavailable);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(unavailable);
            verify(keyRecovery).destroy(null, tokenKey);
            verifyNoInteractions(issuanceWait);
        }

        @Test
        void throwsRejectedAndDestroysTheKeyOnce_whenTheCertificateIsRejected() throws Exception {
            // given
            submitSignedRequestAndSettle(CertificateState.REJECTED);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.REQUEST_REJECTED));
            verify(keyRecovery).destroy(certificateUuid, tokenKey);
            verify(keyRecovery, never()).export(any());
        }

        @Test
        void throwsFailedAndKeepsTheKeyAndLogsIt_whenTheCertificateFails() throws Exception {
            // given — an operator's cancel that the authority did not confirm fails the certificate as well
            submitSignedRequestAndSettle(CertificateState.FAILED);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_FAILED));
            verify(keyRecovery, never()).destroy(any(), any());
            verify(keyRecovery, never()).export(any());
            assertTheKeptKeyIsLogged(certificateUuid);
        }

        @Test
        void throwsFailedAndKeepsTheKey_whenTheCertificateNoLongerCarriesTheRequest() throws Exception {
            // given
            submitSignedRequest();
            when(issuanceWait
                    .awaitSettledThroughStatusPolls(eq(certificateUuid), anyString(), eq(SERVER_KEYGEN_TIMEOUT)))
                    .thenReturn(Optional.empty());

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_FAILED));
            verify(keyRecovery, never()).destroy(any(), any());
            assertTheKeptKeyIsLogged(certificateUuid);
        }

        @Test
        void keepsTheKeyAndPassesTheFailureOn_whenTheWaitFails() throws Exception {
            // given
            var certificateGone = new IllegalStateException("The certificate is gone.");
            submitSignedRequest();
            when(issuanceWait
                    .awaitSettledThroughStatusPolls(eq(certificateUuid), anyString(), eq(SERVER_KEYGEN_TIMEOUT)))
                    .thenThrow(certificateGone);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(certificateGone);
            verify(keyRecovery, never()).destroy(any(), any());
            assertTheKeptKeyIsLogged(certificateUuid);
        }

        @ParameterizedTest
        @EnumSource(value = CancelConfirmation.class, names = {"CANCELLED", "NOT_TRACKED"})
        void throwsTimedOutAndDestroysTheKeyOnce_whenTheAuthorityWillNotIssue(CancelConfirmation authorityWillNotIssue)
                throws Exception {
            // given
            submitSignedRequestAndSettle(CertificateState.PENDING_ISSUE);
            when(clientOperationService
                    .cancelPendingCertificateOperationWithConfirmation(any(), any(), anyString(), any()))
                    .thenReturn(authorityWillNotIssue);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
            verify(keyRecovery).destroy(certificateUuid, tokenKey);
        }

        @Test
        void throwsTimedOutAndKeepsTheKeyAndLogsIt_whenTheAuthorityDoesNotConfirmTheCancel() throws Exception {
            // given
            submitSignedRequestAndSettle(CertificateState.PENDING_ISSUE);
            when(clientOperationService
                    .cancelPendingCertificateOperationWithConfirmation(any(), any(), anyString(), any()))
                    .thenReturn(CancelConfirmation.UNCONFIRMED);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
            verify(keyRecovery, never()).destroy(any(), any());
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.WARN)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .anyMatch(line -> line.contains(certificateUuid.toString())
                            && line.contains(tokenKey.keyUuid().toString()) && line.contains("did not confirm"));
        }

        @Test
        void throwsTimedOutAndKeepsTheKey_whenTheAuthorityRefusesTheCancel() throws Exception {
            // given
            submitSignedRequestAndSettle(CertificateState.PENDING_ISSUE);
            when(clientOperationService
                    .cancelPendingCertificateOperationWithConfirmation(any(), any(), anyString(), any()))
                    .thenThrow(new ValidationException("past the point of no return"));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
            verify(keyRecovery, never()).destroy(any(), any());
        }

        @ParameterizedTest
        @EnumSource(value = CertificateState.class, names = {"REQUESTED", "PENDING_APPROVAL", "REGISTERED"})
        void throwsTimedOutAndKeepsTheKey_whenTheCertificateWaitsInAStateThatIsNotCancelled(CertificateState state)
                throws Exception {
            // given
            submitSignedRequestAndSettle(state);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.ISSUANCE_TIMED_OUT));
            verify(keyRecovery, never()).destroy(any(), any());
            verifyNoInteractions(clientOperationService);
        }

        @Test
        void throwsInternalErrorAndOverwritesTheExportedKeyWithoutDestroying_whenTheCertificateCertifiesAnotherKey()
                throws Exception {
            // given
            submitSignedRequestAndSettle(CertificateState.ISSUED);
            storeCertificateFor(tokenKeyPair);
            KeyPair otherKeyPair = PkiFixtures.keyPair();
            PrivateKeyInfo exportedOtherKey = privateKeyInfoOf(otherKeyPair);
            when(keyRecovery.export(tokenKey)).thenReturn(exportedOtherKey);
            when(keyRecovery.publicKeyOf(exportedOtherKey)).thenReturn(Optional.of(otherKeyPair.getPublic()));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.INTERNAL_ERROR));
            assertThat(exportedOtherKey.getPrivateKey().getOctets()).containsOnly(0);
            verify(keyRecovery, never()).destroy(any(), any());
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.ERROR)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line).contains(certificateUuid.toString()));
        }

        @Test
        void overwritesTheExportedKey_whenCheckingItFailsUnexpectedly() throws Exception {
            // given
            submitSignedRequestAndSettle(CertificateState.ISSUED);
            storeCertificateFor(tokenKeyPair);
            PrivateKeyInfo exported = privateKeyInfoOf(tokenKeyPair);
            IllegalStateException unreadable = new IllegalStateException("the key cannot be read");
            when(keyRecovery.export(tokenKey)).thenReturn(exported);
            when(keyRecovery.publicKeyOf(exported)).thenThrow(unreadable);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(unreadable);
            assertThat(exported.getPrivateKey().getOctets()).containsOnly(0);
        }

        @Test
        void keepsTheKeyLinkedToItsCertificate_whenTheSubmissionFailsAfterItsIssueWasDispatched() throws Exception {
            // given
            EstException failed = new EstException(EstError.ISSUANCE_FAILED, LABEL);
            when(keyRecovery.create(route)).thenReturn(tokenKey);
            when(keyRecovery.signRequest(eq(tokenKey), any())).thenReturn(tokenSignedRequest);
            when(enrollment
                    .submitForKey(eq(route), eq(tokenSignedRequest), eq(tokenKey.keyUuid()),
                            eq(tokenKey.tokenProfileUuid()), any()))
                    .thenAnswer(invocation -> {
                        invocation.<Consumer<UUID>>getArgument(4).accept(certificateUuid);
                        throw failed;
                    });

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(failed);
            verify(keyRecovery, never()).destroy(any(), any());
            assertTheKeptKeyIsLogged(certificateUuid);
        }

        @Test
        void throwsInternalErrorAndKeepsTheKey_whenTheKeyCannotBeExported() throws Exception {
            // given
            submitSignedRequestAndSettle(CertificateState.ISSUED);
            storeCertificateFor(tokenKeyPair);
            when(keyRecovery.export(tokenKey)).thenThrow(new ConnectorException("export refused"));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration.generate(route, aClient(), clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.INTERNAL_ERROR));
            verify(keyRecovery, never()).destroy(any(), any());
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.ERROR)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line)
                            .contains(certificateUuid.toString(), tokenKey.keyUuid().toString())
                            .doesNotContain("export refused"));
        }

        @Test
        void completesTheRegistrationWithTheTokenSignedRequest_whenTheClientIsIdentifiedByItsRegistration()
                throws Exception {
            // given
            UUID registrationUuid = UUID.randomUUID();
            EstClient registrationClient = aRegistrationClient(registrationUuid);
            signTheRequest();
            when(enrollment.completeRegistration(route, registrationClient, tokenSignedRequest, credentials))
                    .thenReturn(registrationUuid);
            when(issuanceWait
                    .awaitSettledThroughStatusPolls(eq(registrationUuid), anyString(), eq(SERVER_KEYGEN_TIMEOUT)))
                    .thenReturn(Optional.of(CertificateState.REJECTED));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration
                    .generate(route, registrationClient, clientCsr, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.REQUEST_REJECTED));
            verify(keyRecovery).destroy(registrationUuid, tokenKey);
        }

        @Test
        void destroysTheKey_whenTheRefusedRegistrationDoesNotCarryTheRequest() throws Exception {
            // given
            UUID registrationUuid = UUID.randomUUID();
            EstClient registrationClient = aRegistrationClient(registrationUuid);
            EstException refused = new EstException(EstError.REGISTRATION_REJECTED, LABEL);
            signTheRequest();
            when(enrollment.completeRegistration(route, registrationClient, tokenSignedRequest, credentials))
                    .thenThrow(refused);
            when(issuanceWait.carriesRequest(registrationUuid, fingerprintOf(tokenSignedRequest))).thenReturn(false);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration
                    .generate(route, registrationClient, clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(refused);
            verify(keyRecovery).destroy(registrationUuid, tokenKey);
        }

        @Test
        void keepsTheKey_whenTheFailedRegistrationCarriesTheRequest() throws Exception {
            // given — the issue of the completed registration may have been queued before the failure
            UUID registrationUuid = UUID.randomUUID();
            EstClient registrationClient = aRegistrationClient(registrationUuid);
            EstException unavailable = new EstException(EstError.SERVICE_UNAVAILABLE, LABEL);
            signTheRequest();
            when(enrollment.completeRegistration(route, registrationClient, tokenSignedRequest, credentials))
                    .thenThrow(unavailable);
            when(issuanceWait.carriesRequest(registrationUuid, fingerprintOf(tokenSignedRequest))).thenReturn(true);

            // when
            ThrowingCallable generate = () -> serverKeyGeneration
                    .generate(route, registrationClient, clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(unavailable);
            verify(keyRecovery, never()).destroy(any(), any());
            assertTheKeptKeyIsLogged(registrationUuid);
        }

        @Test
        void keepsTheKey_whenTheFailedRegistrationCannotBeRead() throws Exception {
            // given
            UUID registrationUuid = UUID.randomUUID();
            EstClient registrationClient = aRegistrationClient(registrationUuid);
            EstException unavailable = new EstException(EstError.SERVICE_UNAVAILABLE, LABEL);
            signTheRequest();
            when(enrollment.completeRegistration(route, registrationClient, tokenSignedRequest, credentials))
                    .thenThrow(unavailable);
            when(issuanceWait.carriesRequest(eq(registrationUuid), anyString()))
                    .thenThrow(new IllegalStateException("database unavailable"));

            // when
            ThrowingCallable generate = () -> serverKeyGeneration
                    .generate(route, registrationClient, clientCsr, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(unavailable);
            verify(keyRecovery, never()).destroy(any(), any());
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void signTheRequest() throws Exception {
            when(keyRecovery.create(route)).thenReturn(tokenKey);
            when(keyRecovery.signRequest(eq(tokenKey), any())).thenReturn(tokenSignedRequest);
        }

        private void assertTheKeptKeyIsLogged(UUID keptForCertificateUuid) {
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.WARN)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .anyMatch(line -> line.contains(keptForCertificateUuid.toString())
                            && line.contains(tokenKey.keyUuid().toString()) && line.contains("kept"));
        }

        private static String fingerprintOf(Pkcs10CertificateRequest request) throws Exception {
            return CertificateUtil.getThumbprint(request.getEncoded());
        }

        private static EstClient aRegistrationClient(UUID registrationUuid) {
            return new EstClient(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, "registration:" + registrationUuid,
                    registrationUuid);
        }

        private void submitSignedRequest() throws Exception {
            when(keyRecovery.create(route)).thenReturn(tokenKey);
            when(keyRecovery.signRequest(eq(tokenKey), any())).thenReturn(tokenSignedRequest);
            when(enrollment
                    .submitForKey(eq(route), eq(tokenSignedRequest), eq(tokenKey.keyUuid()),
                            eq(tokenKey.tokenProfileUuid()), any()))
                    .thenReturn(certificateUuid);
        }

        private void submitSignedRequestAndSettle(CertificateState state) throws Exception {
            submitSignedRequest();
            String fingerprint = CertificateUtil.getThumbprint(tokenSignedRequest.getEncoded());
            when(issuanceWait.awaitSettledThroughStatusPolls(certificateUuid, fingerprint, SERVER_KEYGEN_TIMEOUT))
                    .thenReturn(Optional.of(state));
        }

        private void storeCertificateFor(KeyPair subjectKeys) {
            when(certificateRepository.findContentByUuidAndRequestFingerprint(eq(certificateUuid), anyString()))
                    .thenReturn(Optional.of(certificateContentFor(subjectKeys)));
        }

        private static PrivateKeyInfo privateKeyInfoOf(KeyPair keyPair) {
            return PrivateKeyInfo.getInstance(keyPair.getPrivate().getEncoded());
        }

        private static EstClient aClient() {
            return new EstClient(EstAuthenticationPolicy.RA_BASIC, "secret:" + UUID.randomUUID(), null);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private EstRoute routeGeneratingKeys(boolean serverKeyGeneration) {
        EstProfile estProfile = anEstProfile()
                .withUuid(UUID.randomUUID())
                .withServerKeyGeneration(serverKeyGeneration)
                .withServerKeyGenerationTimeout(SERVER_KEYGEN_TIMEOUT_SECONDS)
                .build();
        return new EstRoute(estProfile, raProfile, false, LABEL);
    }

    private static void enterARequest() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }

    private static String certificateContentFor(KeyPair subjectKeys) {
        Ca ca = PkiFixtures.rootCa("EST Issuing CA");
        Instant now = Instant.now();
        X509Certificate certificate = PkiFixtures
                .clientCertificateFor(ca, subjectKeys, now, now.plus(Duration.ofDays(1)), CLIENT_SUBJECT);
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private EstRoute routeRecoveringKeys() {
        EstProfile estProfile = anEstProfile()
                .withUuid(UUID.randomUUID())
                .withServerKeyGeneration(true)
                .withKeyRecovery(true)
                .withServerKeyGenerationTimeout(SERVER_KEYGEN_TIMEOUT_SECONDS)
                .build();
        return new EstRoute(estProfile, raProfile, false, LABEL);
    }

    private static void assertRefusal(Throwable thrown, EstError error) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(error);
            assertThat(refusal.realm()).contains(LABEL);
        });
    }
}
