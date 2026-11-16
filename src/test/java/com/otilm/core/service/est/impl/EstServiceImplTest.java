package com.otilm.core.service.est.impl;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.service.est.EstCaCertificates;
import com.otilm.core.service.est.EstCsrAttrsService;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.EstRouteResolver;
import com.otilm.core.service.est.authentication.EstAuthenticators;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.enrollment.EstEnrollment;
import com.otilm.core.service.est.enrollment.EstReenrollment;
import com.otilm.core.service.est.enrollment.EstServerKeyGeneration;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstResponses;
import com.otilm.core.util.EstClientCredentialsFixtures;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.SecretLeakProbe;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import static com.otilm.core.util.ConnectorFailureFixtures.decodeFailure;
import static com.otilm.core.util.ConnectorFailureFixtures.requestFailure;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static java.security.spec.RSAKeyGenParameterSpec.F4;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstServiceImplTest {

    private static final String LABEL = "devices";
    private static final UUID RA_PROFILE_UUID = UUID.fromString("5d0f7c52-3a41-4c5e-9d0b-5f1d2a8e7b64");
    private static final String CONNECTOR_TEXT = "connector-internal-detail";

    @Mock
    private EstRouteResolver routeResolver;

    @Mock
    private EstCaCertificates caCertificates;

    @Mock
    private EstCsrAttrsService csrAttrsService;

    @Mock
    private EstAuthenticators authenticators;

    @Mock
    private EstEnrollment enrollment;

    @Mock
    private EstReenrollment reenrollment;

    @Mock
    private EstServerKeyGeneration serverKeyGeneration;

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger serviceLogger = (Logger) LoggerFactory.getLogger(EstServiceImpl.class);
    private Level previousLevel;
    private boolean previousAdditive;

    private EstServiceImpl service;
    private RaProfile raProfile;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * The logger is a process-wide singleton, so what is set on it here is taken off again after each test. It is
     * captured at DEBUG, so that a line which leaked would be caught at any level.
     */
    @BeforeEach
    void createServiceAndCaptureTheLog() {
        raProfile = new RaProfile();
        raProfile.setUuid(RA_PROFILE_UUID);
        raProfile.setName("devices-ra");
        service = new EstServiceImpl(routeResolver, caCertificates, csrAttrsService, authenticators, enrollment,
                reenrollment, serverKeyGeneration);
        previousLevel = serviceLogger.getLevel();
        previousAdditive = serviceLogger.isAdditive();
        serviceLogger.setLevel(Level.DEBUG);
        serviceLogger.setAdditive(false);
        logged.start();
        serviceLogger.addAppender(logged);
    }

    @AfterEach
    void releaseTheLog() {
        serviceLogger.detachAppender(logged);
        logged.stop();
        serviceLogger.setLevel(previousLevel);
        serviceLogger.setAdditive(previousAdditive);
        MDC.clear();
    }

    @ParameterizedTest
    @MethodSource("connectorFailures")
    void throwsServiceUnavailableWithTheRealm_whenTheConnectorFails(Exception connectorFailure) throws Exception {
        // given
        stubRouteFor(LABEL);
        when(csrAttrsService.buildCsrAttrs(raProfile)).thenThrow(connectorFailure);

        // when
        ThrowingCallable getCsrAttributes = () -> service.getCsrAttributes(LABEL);

        // then
        assertThatThrownBy(getCsrAttributes)
                .isInstanceOf(EstException.class)
                .hasMessageContaining(EstError.SERVICE_UNAVAILABLE.text())
                .satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE, LABEL));
    }

    @ParameterizedTest
    @MethodSource("connectorFailures")
    void logsErrorWithTheClassNameOnly_whenTheConnectorFails(Exception connectorFailure) throws Exception {
        // given
        stubRouteFor(LABEL);
        when(csrAttrsService.buildCsrAttrs(raProfile)).thenThrow(connectorFailure);

        // when
        ThrowingCallable getCsrAttributes = () -> service.getCsrAttributes(LABEL);

        // then
        assertThatThrownBy(getCsrAttributes).isInstanceOf(EstException.class);
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage())
                    .contains(RA_PROFILE_UUID.toString())
                    .contains(connectorFailure.getClass().getName());
            assertThat(event.getThrowableProxy()).isNull();
        });
    }

    @ParameterizedTest
    @MethodSource("connectorFailures")
    void logsNoTextOfTheConnector_whenTheConnectorFails(Exception connectorFailure) throws Exception {
        // given
        stubRouteFor(LABEL);
        when(csrAttrsService.buildCsrAttrs(raProfile)).thenThrow(connectorFailure);

        // when
        ThrowingCallable getCsrAttributes = () -> service.getCsrAttributes(LABEL);

        // then
        assertThatThrownBy(getCsrAttributes).isInstanceOf(EstException.class);
        SecretLeakProbe.assertNoneReveals(loggedText(), CONNECTOR_TEXT);
    }

    @ParameterizedTest
    @MethodSource("otherFailures")
    void throwsServiceUnavailableWithTheRealm_whenTheAttributesFailInAnyOtherWay(Exception failure) throws Exception {
        // given
        stubRouteFor(LABEL);
        when(csrAttrsService.buildCsrAttrs(raProfile)).thenThrow(failure);

        // when
        ThrowingCallable getCsrAttributes = () -> service.getCsrAttributes(LABEL);

        // then
        assertThatThrownBy(getCsrAttributes)
                .isInstanceOf(EstException.class)
                .hasMessageContaining(EstError.SERVICE_UNAVAILABLE.text())
                .satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE, LABEL));
    }

    @ParameterizedTest
    @MethodSource("otherFailures")
    void logsErrorWithTheException_whenTheAttributesFailInAnyOtherWay(Exception failure) throws Exception {
        // given
        stubRouteFor(LABEL);
        when(csrAttrsService.buildCsrAttrs(raProfile)).thenThrow(failure);

        // when
        ThrowingCallable getCsrAttributes = () -> service.getCsrAttributes(LABEL);

        // then
        assertThatThrownBy(getCsrAttributes).isInstanceOf(EstException.class);
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage()).contains(RA_PROFILE_UUID.toString());
            assertThat(event.getThrowableProxy().getClassName()).isEqualTo(failure.getClass().getName());
        });
    }

    @Test
    void throwsServiceUnavailableWithTheDefaultRealm_whenTheRouteHasNoLabel() throws Exception {
        // given
        String noLabel = null;
        stubRouteFor(noLabel);
        when(csrAttrsService.buildCsrAttrs(raProfile)).thenThrow(new ConnectorException(CONNECTOR_TEXT));

        // when
        ThrowingCallable getCsrAttributes = () -> service.getCsrAttributes(noLabel);

        // then
        assertThatThrownBy(getCsrAttributes)
                .satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE, EstResponses.DEFAULT_REALM));
    }

    // ── SimpleEnrollment ──────────────────────────────────────────────────────

    @Nested
    class SimpleEnrollment {

        private static final String PASSWORD = "p4ssw0rd-that-must-not-be-logged";

        private final EstClientCredentials credentials = basicCredentials("device-owner", PASSWORD);

        @ParameterizedTest
        @MethodSource("bodiesTheDecoderRefuses")
        void throwsBadRequestWithTheRealmBeforeAuthentication_whenTheBodyIsNotAnAcceptableRequest(byte[] body) {
            // given
            stubRouteFor(LABEL);

            // when
            ThrowingCallable simpleEnroll = () -> service.simpleEnroll(LABEL, body, credentials);

            // then
            assertThatThrownBy(simpleEnroll).satisfies(thrown -> assertRefusal(thrown, EstError.BAD_REQUEST, LABEL));
            verifyNoInteractions(authenticators);
        }

        @Test
        void throwsTheRefusalOfTheAuthenticator_whenAnUnauthenticatedClientsSignatureDoesNotVerify() throws Exception {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] forgedRequest = EstCsrFixtures.forgedRequestBody();
            EstException unauthorized = new EstException(EstError.UNAUTHORIZED, LABEL);
            when(authenticators.authenticate(eq(route), eq(credentials), any(CertificateRequest.class)))
                    .thenThrow(unauthorized);

            // when
            ThrowingCallable simpleEnroll = () -> service.simpleEnroll(LABEL, forgedRequest, credentials);

            // then
            assertThatThrownBy(simpleEnroll).isSameAs(unauthorized);
        }

        @Test
        void throwsInvalidSignatureWithTheRealm_whenAnAuthenticatedClientsSignatureDoesNotVerify() throws Exception {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] forgedRequest = EstCsrFixtures.forgedRequestBody();
            stubAuthenticationOf(route, aClient());

            // when
            ThrowingCallable simpleEnroll = () -> service.simpleEnroll(LABEL, forgedRequest, credentials);

            // then
            assertThatThrownBy(simpleEnroll)
                    .satisfies(thrown -> assertRefusal(thrown, EstError.INVALID_SIGNATURE, LABEL));
            verify(authenticators).authenticate(eq(route), eq(credentials), any(CertificateRequest.class));
        }

        @Test
        void throwsRegistrationRejectedWithTheRealm_whenARegistrationClientsSignatureDoesNotVerify() throws Exception {
            // given — the policy identified the client by the registration that it completes
            EstRoute route = stubRouteFor(LABEL);
            byte[] forgedRequest = EstCsrFixtures.forgedRequestBody();
            stubAuthenticationOf(route, aRegistrationClient());

            // when
            ThrowingCallable simpleEnroll = () -> service.simpleEnroll(LABEL, forgedRequest, credentials);

            // then
            assertThatThrownBy(simpleEnroll)
                    .satisfies(thrown -> assertRefusal(thrown, EstError.REGISTRATION_REJECTED, LABEL));
            verifyNoInteractions(enrollment);
        }

        @Test
        void authenticatesTheDecodedRequestOnTheRoute_whenTheBodyIsARequest() throws Exception {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] body = EstCsrFixtures.signedRequestBody();
            stubAuthenticationOf(route, aClient());

            // when
            service.simpleEnroll(LABEL, body, credentials);

            // then
            ArgumentCaptor<CertificateRequest> authenticated = ArgumentCaptor.forClass(CertificateRequest.class);
            verify(authenticators).authenticate(eq(route), eq(credentials), authenticated.capture());
            assertThat(authenticated.getValue().getEncoded()).isEqualTo(Base64.getDecoder().decode(body));
        }

        @Test
        void answersWithTheEnrollment_whenTheClientIsAuthenticated() throws Exception {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] body = EstCsrFixtures.signedRequestBody();
            EstClient client = aClient();
            stubAuthenticationOf(route, client);
            ResponseEntity<byte[]> answer = EstResponses.pending(Duration.ofSeconds(30));
            when(enrollment.enroll(eq(route), eq(client), any(Pkcs10CertificateRequest.class), eq(credentials)))
                    .thenReturn(answer);

            // when
            ResponseEntity<byte[]> response = service.simpleEnroll(LABEL, body, credentials);

            // then
            assertThat(response).isSameAs(answer);
        }

        @Test
        void passesTheRefusalOfTheEnrollmentOn_whenTheEnrollmentRefuses() throws Exception {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] body = EstCsrFixtures.signedRequestBody();
            stubAuthenticationOf(route, aClient());
            EstException rejected = new EstException(EstError.REQUEST_REJECTED, LABEL);
            when(enrollment
                    .enroll(eq(route), any(EstClient.class), any(Pkcs10CertificateRequest.class), eq(credentials)))
                    .thenThrow(rejected);

            // when
            ThrowingCallable simpleEnroll = () -> service.simpleEnroll(LABEL, body, credentials);

            // then
            assertThatThrownBy(simpleEnroll).isSameAs(rejected);
        }

        @Test
        void logsNothingAboveDebug_whenThePolicyIdentifiesTheClient() throws Exception {
            // given — the enrolment logs its own answer, so identifying the client says nothing above DEBUG
            EstRoute route = stubRouteFor(LABEL);
            byte[] body = EstCsrFixtures.signedRequestBody();
            UUID registration = UUID.randomUUID();
            stubAuthenticationOf(route, new EstClient(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION,
                    "registration:" + registration, registration));

            // when
            service.simpleEnroll(LABEL, body, credentials);

            // then
            assertThat(logged.list).noneMatch(event -> event.getLevel().isGreaterOrEqual(Level.INFO));
        }

        @Test
        void throwsTheRefusalOfTheAuthenticator_whenTheClientIsNotAuthenticated() throws Exception {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] body = EstCsrFixtures.signedRequestBody();
            EstException unauthorized = new EstException(EstError.UNAUTHORIZED, LABEL);
            when(authenticators.authenticate(eq(route), eq(credentials), any(CertificateRequest.class)))
                    .thenThrow(unauthorized);

            // when
            ThrowingCallable simpleEnroll = () -> service.simpleEnroll(LABEL, body, credentials);

            // then
            assertThatThrownBy(simpleEnroll).isSameAs(unauthorized);
        }

        @Test
        void logsNothingAboveDebug_whenTheClientIsNotAuthenticated() throws Exception {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] body = EstCsrFixtures.signedRequestBody();
            when(authenticators.authenticate(eq(route), eq(credentials), any(CertificateRequest.class)))
                    .thenThrow(new EstException(EstError.UNAUTHORIZED, LABEL));

            // when
            ThrowingCallable simpleEnroll = () -> service.simpleEnroll(LABEL, body, credentials);

            // then
            assertThatThrownBy(simpleEnroll).isInstanceOf(EstException.class);
            assertThat(logged.list).noneMatch(event -> event.getLevel().isGreaterOrEqual(Level.INFO));
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> bodiesTheDecoderRefuses() throws Exception {
            byte[] notARequest = "AAAA".getBytes(StandardCharsets.US_ASCII);
            byte[] requestForANameThatCannotBeRendered = EstCsrFixtures
                    .signedRequestBodyWithNames("CN=device-1", EstCsrFixtures.otherNameWithoutAValue());
            byte[] requestWithAnRsaKeyOf16384Bits = EstCsrFixtures
                    .requestBodyWithRsaPublicKey(PKCSObjectIdentifiers.rsaEncryption, 16384, F4);
            return Stream
                    .of(arguments(named("a body that is not a request", notARequest)),
                            arguments(named("a request for a name that cannot be rendered",
                                    requestForANameThatCannotBeRendered)),
                            arguments(
                                    named("a request with an RSA key of 16384 bits", requestWithAnRsaKeyOf16384Bits)));
        }

        private void stubAuthenticationOf(EstRoute route, EstClient client) {
            when(authenticators.authenticate(eq(route), eq(credentials), any(CertificateRequest.class)))
                    .thenReturn(client);
        }

        private static EstClient aClient() {
            return new EstClient(EstAuthenticationPolicy.RA_BASIC, "secret:" + UUID.randomUUID(), null);
        }

        private static EstClient aRegistrationClient() {
            UUID registration = UUID.randomUUID();
            return new EstClient(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, "registration:" + registration,
                    registration);
        }
    }

    // ── SimpleReenrollment ────────────────────────────────────────────────────

    @Nested
    class SimpleReenrollment {

        private final EstClientCredentials credentials = EstClientCredentialsFixtures
                .certificateCredentials(PkiFixtures.clientCertificate(PkiFixtures.rootCa("EST Issuing CA")));

        @Test
        void delegatesToReenrollment_whenTheBodyIsARequest() throws Exception {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] body = EstCsrFixtures.signedRequestBody();
            ResponseEntity<byte[]> answer = EstResponses.pending(Duration.ofSeconds(30));
            when(reenrollment.reenroll(eq(route), any(Pkcs10CertificateRequest.class), eq(credentials)))
                    .thenReturn(answer);

            // when
            ResponseEntity<byte[]> response = service.simpleReenroll(LABEL, body, credentials);

            // then
            assertThat(response).isSameAs(answer);
            ArgumentCaptor<Pkcs10CertificateRequest> reenrolled = ArgumentCaptor
                    .forClass(Pkcs10CertificateRequest.class);
            verify(reenrollment).reenroll(eq(route), reenrolled.capture(), eq(credentials));
            assertThat(reenrolled.getValue().getEncoded()).isEqualTo(Base64.getDecoder().decode(body));
            verifyNoInteractions(authenticators, enrollment);
        }

        @ParameterizedTest
        @EnumSource(EstAuthenticationPolicy.class)
        void delegatesToReenrollment_whenTheSignatureDoesNotVerify(EstAuthenticationPolicy policy) throws Exception {
            // given — the re-enrolment verifies the signature only once the certificate of the client is accepted
            EstRoute route = stubRouteUnder(policy);
            byte[] forgedRequest = EstCsrFixtures.forgedRequestBody();

            // when
            service.simpleReenroll(LABEL, forgedRequest, credentials);

            // then
            verify(reenrollment).reenroll(eq(route), any(Pkcs10CertificateRequest.class), eq(credentials));
            verifyNoInteractions(authenticators, enrollment);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private EstRoute stubRouteUnder(EstAuthenticationPolicy policy) {
            EstProfile estProfile = anEstProfile().withUuid(UUID.randomUUID()).withAuthenticationPolicy(policy).build();
            EstRoute route = new EstRoute(estProfile, raProfile, false, LABEL);
            when(routeResolver.resolve(LABEL)).thenReturn(Optional.of(route));
            return route;
        }
    }

    // ── ServerKeyGeneration ───────────────────────────────────────────────────

    @Nested
    class ServerKeyGeneration {

        private final EstClientCredentials credentials = basicCredentials("device-owner", "p4ssw0rd");

        @Test
        void throwsTheRefusalOfTheRouteBeforeDecoding_whenTheRouteCannotGenerateKeys() {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] notARequest = "AAAA".getBytes(StandardCharsets.US_ASCII);
            EstException disabled = new EstException(EstError.SERVER_KEYGEN_DISABLED, LABEL);
            doThrow(disabled).when(serverKeyGeneration).requireAvailable(route);

            // when
            ThrowingCallable generate = () -> service.serverKeyGeneration(LABEL, notARequest, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(disabled);
            verifyNoInteractions(authenticators);
        }

        @Test
        void throwsBadRequestWithTheRealmBeforeAuthentication_whenTheBodyIsNotARequest() {
            // given
            stubRouteFor(LABEL);
            byte[] notARequest = "AAAA".getBytes(StandardCharsets.US_ASCII);

            // when
            ThrowingCallable generate = () -> service.serverKeyGeneration(LABEL, notARequest, credentials);

            // then
            assertThatThrownBy(generate).satisfies(thrown -> assertRefusal(thrown, EstError.BAD_REQUEST, LABEL));
            verifyNoInteractions(authenticators);
        }

        @Test
        void throwsEncryptedDeliveryUnsupportedWithTheRealmBeforeAuthentication_whenTheClientAsksForEncryption()
                throws Exception {
            // given
            stubRouteFor(LABEL);
            var decryptKeyIdentifier = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.37");
            byte[] askingForEncryption = EstCsrFixtures
                    .signedRequestBodyWithAttribute("CN=device-1", "device-1.example", decryptKeyIdentifier,
                            new DEROctetString(new byte[]{1, 2, 3}));

            // when
            ThrowingCallable generate = () -> service.serverKeyGeneration(LABEL, askingForEncryption, credentials);

            // then
            assertThatThrownBy(generate)
                    .satisfies(thrown -> assertRefusal(thrown, EstError.ENCRYPTED_KEY_DELIVERY_UNSUPPORTED, LABEL));
            verifyNoInteractions(authenticators);
        }

        @Test
        void throwsTheRefusalOfTheAuthenticatorWithoutGenerating_whenTheClientIsNotAuthenticated() throws Exception {
            // given
            EstRoute route = stubRouteFor(LABEL);
            byte[] body = EstCsrFixtures.signedRequestBody();
            EstException unauthorized = new EstException(EstError.UNAUTHORIZED, LABEL);
            when(authenticators.authenticate(eq(route), eq(credentials), any(CertificateRequest.class)))
                    .thenThrow(unauthorized);

            // when
            ThrowingCallable generate = () -> service.serverKeyGeneration(LABEL, body, credentials);

            // then
            assertThatThrownBy(generate).isSameAs(unauthorized);
            verify(serverKeyGeneration, never()).generate(any(), any(), any(), any());
        }

        @Test
        void answersWithTheGeneratedKey_whenTheClientsSignatureDoesNotVerify() throws Exception {
            // given — the client's key is not used, so its signature is not checked
            EstRoute route = stubRouteFor(LABEL);
            byte[] forgedRequest = EstCsrFixtures.forgedRequestBody();
            var client = new EstClient(EstAuthenticationPolicy.RA_BASIC, "secret:" + UUID.randomUUID(), null);
            when(authenticators.authenticate(eq(route), eq(credentials), any(CertificateRequest.class)))
                    .thenReturn(client);
            ResponseEntity<byte[]> answer = ResponseEntity.ok(new byte[]{1});
            when(serverKeyGeneration
                    .generate(eq(route), eq(client), any(Pkcs10CertificateRequest.class), eq(credentials)))
                    .thenReturn(answer);

            // when
            ResponseEntity<byte[]> response = service.serverKeyGeneration(LABEL, forgedRequest, credentials);

            // then
            assertThat(response).isSameAs(answer);
            ArgumentCaptor<Pkcs10CertificateRequest> generatedFor = ArgumentCaptor
                    .forClass(Pkcs10CertificateRequest.class);
            verify(serverKeyGeneration).generate(eq(route), eq(client), generatedFor.capture(), eq(credentials));
            assertThat(generatedFor.getValue().getEncoded()).isEqualTo(Base64.getDecoder().decode(forgedRequest));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> connectorFailures() {
        return Stream
                .of(arguments(named("a connector error", new ConnectorException(CONNECTOR_TEXT))),
                        arguments(named("a server error whose cause carries the text too",
                                new ConnectorServerException(CONNECTOR_TEXT, new IllegalStateException(CONNECTOR_TEXT),
                                        HttpStatus.INTERNAL_SERVER_ERROR))),
                        arguments(named("a refusal of the connector", new ValidationException(CONNECTOR_TEXT))),
                        arguments(named("an answer that cannot be decoded", decodeFailure(CONNECTOR_TEXT))),
                        arguments(named("a request that gets no answer", requestFailure(CONNECTOR_TEXT))));
    }

    static Stream<Arguments> otherFailures() {
        return Stream
                .of(arguments(named("a connector that is no longer there", new NotFoundException("no connector"))),
                        arguments(named("a failure to encode the attributes", new IOException("cannot encode"))),
                        arguments(named("an answer without a body, as the v3 client reads it",
                                new IllegalStateException("Connector returned an empty body"))),
                        arguments(named("an RDN code that no OID belongs to",
                                new IllegalArgumentException("Unknown RDN code/OID"))));
    }

    private EstRoute stubRouteFor(String label) {
        EstProfile estProfile = anEstProfile().withUuid(UUID.randomUUID()).build();
        EstRoute route = new EstRoute(estProfile, raProfile, false, label);
        when(routeResolver.resolve(label)).thenReturn(Optional.of(route));
        return route;
    }

    private static EstClientCredentials basicCredentials(String username, String password) {
        byte[] userAndPassword = (username + ":" + password).getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString(userAndPassword));
        return EstClientCredentials.from(request, "ssl-client-cert");
    }

    private static void assertRefusal(Throwable thrown, EstError error, String realm) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(error);
            assertThat(refusal.realm()).contains(realm);
        });
    }

    /** Every captured line, with the stack trace of any exception it carries. */
    private List<String> loggedText() {
        List<String> lines = new ArrayList<>();
        for (ILoggingEvent event : logged.list) {
            lines.add(event.getFormattedMessage());
            if (event.getThrowableProxy() != null) {
                lines.add(ThrowableProxyUtil.asString(event.getThrowableProxy()));
            }
        }
        return lines;
    }
}
