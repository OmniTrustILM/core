package com.otilm.core.integration.service.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.CertificateRegistrationAuthenticator;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstRequestDecoder;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.hibernate.Session;
import org.hibernate.engine.spi.EntityKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicCredentials;
import static com.otilm.core.util.EstClientCredentialsFixtures.malformedBasicCredentials;
import static com.otilm.core.util.EstClientCredentialsFixtures.noCredentials;
import static com.otilm.core.util.EstCsrFixtures.decodedRequest;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class CertificateRegistrationAuthenticatorITest extends BaseSpringBootTest {

    private static final String LABEL = "devices";
    private static final String SUBJECT = "CN=device-1";
    private static final String OTHER_SUBJECT = "CN=device-2";
    private static final String DNS_NAME = "device-1.example";
    private static final String OTHER_DNS_NAME = "device-2.example";
    private static final Map<String, List<String>> REGISTERED_SANS = Map.of("dNSName", List.of(DNS_NAME));
    private static final String NO_USERNAME = "";
    private static final String PASSWORD = "p4ssw0rd";
    private static final String SAN_MISMATCH_RECORD = "EST enrolment subject alternative names do not match the "
            + "registered ones";

    @Autowired
    private CertificateRegistrationAuthenticator authenticator;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private CertificateEventHistoryRepository eventHistory;

    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizations;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private RaProfile raProfile;
    private EstRoute route;

    @BeforeEach
    void seedRoute() {
        raProfile = routes.seedRaProfile("devices-ra");
        route = new EstRoute(anEstProfile().build(), raProfile, false, LABEL);
    }

    @Test
    void matchesRegistration_whenUsernameIsItsReference() throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(registration);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, registration);
    }

    @Test
    void matchesRegistration_whenUsernameIsEmptyAndCsrIdentityMatches() throws Exception {
        // given — another RA Profile holds a registration of the same identity
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT, REGISTERED_SANS);
        RaProfile anotherRaProfile = routes.seedRaProfile("other-ra");
        registrations.seedRegistration(anotherRaProfile, SUBJECT, REGISTERED_SANS);
        EstClientCredentials credentials = presentNoUsername();
        CertificateRequest csr = decodedRequest(SUBJECT, DNS_NAME);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, registration);
    }

    @ParameterizedTest
    @MethodSource("usernamesThatAreNoReference")
    void matchesRegistration_whenUsernameIsNotAReferenceAndCsrIdentityMatches(String username) throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = basicCredentials(username, PASSWORD);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, registration);
    }

    @Test
    void matchesTheReferencedRegistration_whenTwoRegistrationsMatchTheCsr() throws Exception {
        // given — two registrations of one identity, which the request alone cannot tell apart
        registrations.seedRegistration(raProfile, SUBJECT);
        Certificate referenced = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(referenced);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, referenced);
    }

    @Test
    void matchesTheReferencedRegistration_whenUsernameIsItsReferenceInUpperCase() throws Exception {
        // given — two registrations of one identity, which only the reference tells apart
        registrations.seedRegistration(raProfile, SUBJECT);
        Certificate referenced = registrations.seedRegistration(raProfile, SUBJECT);
        var referenceInUpperCase = referenced.getUuid().toString().toUpperCase(Locale.ROOT);
        EstClientCredentials credentials = basicCredentials(referenceInUpperCase, PASSWORD);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, referenced);
    }

    @Test
    void countsNoFailedAttempt_whenPasswordIsNotTheChallenge() throws Exception {
        // given — the password is verified once, when the registration is completed
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(registration);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, registration);
        assertThat(authorizations.findByCertificateUuid(registration.getUuid())).hasValueSatisfying(authorization -> {
            assertThat(authorization.getFailedAttempts()).isZero();
            assertThat(authorization.getState()).isEqualTo(RegistrationState.ACTIVE);
        });
    }

    @Test
    void loadsNoAuthorization_whenRegistrationIsReferenced() throws Exception {
        // given — every entity that authentication reads stays in the bound EntityManager, and the authorization
        // holds the encrypted challenge
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(registration);
        CertificateRequest csr = decodedRequest(SUBJECT);

        try (ThreadBoundEntityManager bound = ThreadBoundEntityManager.open(entityManagerFactory)) {
            // when
            EstClient client = authenticator.authenticate(route, credentials, csr);

            // then
            assertIdentifiesRegistration(client, registration);
            assertThat(bound.managedEntityNames())
                    .contains(X509CertificateEntity.class.getName())
                    .doesNotContain(CertificateRegistrationAuthorization.class.getName());
        }
    }

    @Test
    void throwsRegistrationRejected_whenReferencedRegistrationIsOnAnotherRaProfile() throws Exception {
        // given
        RaProfile anotherRaProfile = routes.seedRaProfile("other-ra");
        Certificate registration = registrations.seedRegistration(anotherRaProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(registration);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
        assertNoEventRecorded(registration);
    }

    @Test
    void throwsRegistrationRejected_whenReferencedRegistrationIsIneligibleAndAnotherMatchesTheCsr() throws Exception {
        // given — the reference names a registration of another RA Profile; one of the route's matches the CSR
        RaProfile anotherRaProfile = routes.seedRaProfile("other-ra");
        Certificate referenced = registrations.seedRegistration(anotherRaProfile, SUBJECT);
        Certificate matchingTheCsr = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(referenced);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
        assertNoEventRecorded(matchingTheCsr);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = "REGISTERED", mode = EnumSource.Mode.EXCLUDE)
    void throwsRegistrationRejected_whenReferencedCertificateIsNotRegistered(CertificateState state) throws Exception {
        // given — the authorization of a certificate outlives its registration
        Certificate certificate = registrations.seedRegistrationInState(raProfile, SUBJECT, state);
        EstClientCredentials credentials = presentReferenceTo(certificate);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
        assertNoEventRecorded(certificate);
    }

    @ParameterizedTest
    @EnumSource(value = RegistrationState.class, names = "ACTIVE", mode = EnumSource.Mode.EXCLUDE)
    void throwsRegistrationRejected_whenAuthorizationIsNotActive(RegistrationState authorizationState)
            throws Exception {
        // given
        Certificate registration = registrations
                .seedRegistrationWithAuthorization(raProfile, SUBJECT, authorizationState);
        EstClientCredentials credentials = presentReferenceTo(registration);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
        assertNoEventRecorded(registration);
    }

    @Test
    void throwsRegistrationRejected_whenReferencedRegistrationIsArchived() throws Exception {
        // given
        Certificate registration = registrations.seedArchivedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(registration);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
        assertNoEventRecorded(registration);
    }

    @Test
    void throwsRegistrationRejected_whenReferencedRegistrationHasNoAuthorization() throws Exception {
        // given
        Certificate registration = registrations.seedRegistrationWithoutAuthorization(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(registration);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
        assertNoEventRecorded(registration);
    }

    @Test
    void throwsRegistrationRejected_whenReferencedCertificateDoesNotExist() throws Exception {
        // given
        var unknownReference = UUID.randomUUID().toString();
        EstClientCredentials credentials = basicCredentials(unknownReference, PASSWORD);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
    }

    @Test
    void throwsRegistrationRejected_whenCsrIdentityDiffersFromTheReferencedRegistration() throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(registration);
        CertificateRequest csrOfAnotherSubject = decodedRequest(OTHER_SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csrOfAnotherSubject);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
        assertNoEventRecorded(registration);
    }

    @Test
    void throwsRegistrationRejected_whenNoRegistrationMatchesTheCsr() throws Exception {
        // given
        Certificate registrationOfAnotherSubject = registrations.seedRegistration(raProfile, OTHER_SUBJECT);
        EstClientCredentials credentials = presentNoUsername();
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
        assertNoEventRecorded(registrationOfAnotherSubject);
    }

    @Test
    void throwsRegistrationRejected_whenTwoRegistrationsMatchTheCsr() throws Exception {
        // given
        Certificate first = registrations.seedRegistration(raProfile, SUBJECT);
        Certificate second = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentNoUsername();
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate)
                .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
        assertNoEventRecorded(first);
        assertNoEventRecorded(second);
    }

    @Test
    void recordsSanMismatch_whenSignatureAndPasswordVerify() throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT, REGISTERED_SANS);
        EstClientCredentials credentials = basicCredentials(NO_USERNAME, CertificateRegistrationSeeder.CHALLENGE);
        CertificateRequest csrOfAnotherName = decodedRequest(SUBJECT, OTHER_DNS_NAME);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csrOfAnotherName);

            // then
            assertThatThrownBy(authenticate)
                    .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
            assertThat(eventHistory.findByCertificateOrderByCreatedDesc(registration))
                    .singleElement()
                    .satisfies(event -> {
                        assertThat(event.getEvent()).isEqualTo(CertificateEvent.ISSUE);
                        assertThat(event.getStatus()).isEqualTo(CertificateEventStatus.FAILED);
                        assertThat(event.getMessage()).isEqualTo(SAN_MISMATCH_RECORD);
                    });
            assertThat(failedAttemptsOf(registration)).isZero();
            assertNoCredentialLogged(probe, NO_USERNAME);
        }
    }

    @Test
    void recordsNoSanMismatch_whenPasswordIsWrong() throws Exception {
        // given — the password is verified as completing the registration verifies it
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT, REGISTERED_SANS);
        EstClientCredentials credentials = presentNoUsername();
        CertificateRequest csrOfAnotherName = decodedRequest(SUBJECT, OTHER_DNS_NAME);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csrOfAnotherName);

            // then
            assertThatThrownBy(authenticate)
                    .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
            assertThat(eventHistory.findByCertificateOrderByCreatedDesc(registration))
                    .singleElement()
                    .extracting(CertificateEventHistory::getMessage)
                    .isEqualTo("Certificate registration challenge verification failed (attempt 1)");
            assertThat(failedAttemptsOf(registration)).isEqualTo(1);
            assertNoCredentialLogged(probe, NO_USERNAME);
        }
    }

    @Test
    void recordsNoSanMismatch_whenSignatureDoesNotVerify() throws Exception {
        // given — a forged request of the registered subject that asks for none of its names
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT, REGISTERED_SANS);
        EstClientCredentials credentials = basicCredentials(NO_USERNAME, CertificateRegistrationSeeder.CHALLENGE);
        CertificateRequest forgedCsr = EstRequestDecoder.decode(EstCsrFixtures.forgedRequestBody(SUBJECT));

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, forgedCsr);

            // then
            assertThatThrownBy(authenticate)
                    .satisfies(CertificateRegistrationAuthenticatorITest::assertRegistrationRejected);
            assertNoEventRecorded(registration);
            assertThat(failedAttemptsOf(registration)).isZero();
            assertNoCredentialLogged(probe, NO_USERNAME);
        }
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"PENDING_ISSUE", "PENDING_APPROVAL", "ISSUED", "FAILED"})
    void identifiesRegistrationByItsRequest_whenUsernameIsItsReference(CertificateState stateOfItsCertificate)
            throws Exception {
        // given — the request completed the registration, whose certificate has moved on since
        CertificateRequest csr = decodedRequest(SUBJECT);
        Certificate registration = registrations
                .seedCompletion(registrations.seedRegistration(raProfile, SUBJECT), csr.getEncoded(),
                        stateOfItsCertificate);
        EstClientCredentials credentials = presentReferenceTo(registration);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, registration);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"PENDING_ISSUE", "PENDING_APPROVAL", "ISSUED", "FAILED"})
    void identifiesRegistrationByItsRequest_whenUsernameIsEmpty(CertificateState stateOfItsCertificate)
            throws Exception {
        // given — the request completed the registration, whose certificate has moved on since
        CertificateRequest csr = decodedRequest(SUBJECT);
        Certificate registration = registrations
                .seedCompletion(registrations.seedRegistration(raProfile, SUBJECT), csr.getEncoded(),
                        stateOfItsCertificate);
        EstClientCredentials credentials = presentNoUsername();

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, registration);
    }

    @Test
    void identifiesTheReferencedRegistration_whenTheRequestCompletedAnother() throws Exception {
        // given — the request completed one registration, and the reference names another of the same subject
        CertificateRequest csr = decodedRequest(SUBJECT);
        registrations
                .seedCompletion(registrations.seedRegistration(raProfile, SUBJECT), csr.getEncoded(),
                        CertificateState.ISSUED);
        Certificate referenced = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(referenced);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, referenced);
    }

    @Test
    void countsNoAttempt_whenRegistrationIsIdentifiedByItsRequest() throws Exception {
        // given — the password is not the challenge, and repeating a request is not asked for it
        CertificateRequest csr = decodedRequest(SUBJECT);
        Certificate registration = registrations
                .seedCompletion(registrations.seedRegistration(raProfile, SUBJECT), csr.getEncoded(),
                        CertificateState.ISSUED);
        EstClientCredentials credentials = presentReferenceTo(registration);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertIdentifiesRegistration(client, registration);
        assertNoEventRecorded(registration);
        assertThat(failedAttemptsOf(registration)).isZero();
    }

    @Test
    void throwsUnauthorized_whenCsrCarriesOnlyAChallengePassword() throws Exception {
        // given — a registration whose challenge is the one that the request carries
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        byte[] body = EstCsrFixtures
                .signedRequestBodyWithChallengePassword(SUBJECT, CertificateRegistrationSeeder.CHALLENGE);
        CertificateRequest csr = EstRequestDecoder.decode(body);
        EstClientCredentials credentials = noCredentials();

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate).satisfies(CertificateRegistrationAuthenticatorITest::assertUnauthorized);
        assertNoEventRecorded(registration);
    }

    @ParameterizedTest
    @MethodSource("blankPasswords")
    void throwsUnauthorized_whenBasicPasswordIsBlank(String blankPassword) throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = basicCredentials(registration.getUuid().toString(), blankPassword);
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate).satisfies(CertificateRegistrationAuthenticatorITest::assertUnauthorized);
    }

    @Test
    void throwsUnauthorized_whenBasicCredentialsAreMalformed() throws Exception {
        // given
        registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = malformedBasicCredentials();
        CertificateRequest csr = decodedRequest(SUBJECT);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate).satisfies(CertificateRegistrationAuthenticatorITest::assertUnauthorized);
    }

    @Test
    void logsTheRefusalOnlyAtDebug_whenRegistrationIsRejected() throws Exception {
        // given
        registrations.seedRegistration(raProfile, SUBJECT, REGISTERED_SANS);
        EstClientCredentials credentials = presentNoUsername();
        CertificateRequest csr = decodedRequest(SUBJECT, OTHER_DNS_NAME);

        try (AuthenticatorLog logged = AuthenticatorLog.capture()) {
            // when
            ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

            // then
            assertThatThrownBy(authenticate).isInstanceOf(EstException.class);
            assertThat(logged.events())
                    .isNotEmpty()
                    .allSatisfy(event -> assertThat(event.getLevel()).isEqualTo(Level.DEBUG));
            assertThat(logged.events())
                    .anySatisfy(event -> assertThat(event.getFormattedMessage()).contains("SAN_MISMATCH"));
        }
    }

    @Test
    void logsNoCredential_whenRegistrationMatches() throws Exception {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);
        EstClientCredentials credentials = presentReferenceTo(registration);
        CertificateRequest csr = decodedRequest(SUBJECT);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            EstClient client = authenticator.authenticate(route, credentials, csr);

            // then
            assertIdentifiesRegistration(client, registration);
            assertNoCredentialLogged(probe, registration.getUuid().toString());
        }
    }

    @Test
    void logsNoCredential_whenRegistrationIsRejected() throws Exception {
        // given
        EstClientCredentials credentials = presentNoUsername();
        CertificateRequest csr = decodedRequest(SUBJECT);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

            // then
            assertThatThrownBy(authenticate).isInstanceOf(EstException.class);
            assertNoCredentialLogged(probe, NO_USERNAME);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> usernamesThatAreNoReference() {
        return Stream
                .of(arguments(named("a name", "device-1")),
                        arguments(named("a UUID in short groups, which the JDK parses as one", "1-1-1-1-1")));
    }

    static Stream<Arguments> blankPasswords() {
        return Stream
                .of(arguments(named("an empty password", "")), arguments(named("a password of spaces", "   ")),
                        arguments(named("a password of a tab and a space", "\t ")));
    }

    /** Presents the registration the way a client names it, by its reference as the Basic user name. */
    private static EstClientCredentials presentReferenceTo(Certificate registration) {
        return basicCredentials(registration.getUuid().toString(), PASSWORD);
    }

    /** Presents the empty user name, which leaves the registration to be found by the request. */
    private static EstClientCredentials presentNoUsername() {
        return basicCredentials(NO_USERNAME, PASSWORD);
    }

    private static void assertIdentifiesRegistration(EstClient client, Certificate registration) {
        UUID uuid = registration.getUuid();
        assertThat(client)
                .isEqualTo(
                        new EstClient(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, "registration:" + uuid, uuid));
    }

    private void assertNoEventRecorded(Certificate registration) {
        assertThat(eventHistory.findByCertificateOrderByCreatedDesc(registration)).isEmpty();
    }

    private int failedAttemptsOf(Certificate registration) {
        return authorizations.findByCertificateUuid(registration.getUuid()).orElseThrow().getFailedAttempts();
    }

    /** Neither the password, nor the challenge of the registration, nor the base64 of the credentials was logged. */
    private static void assertNoCredentialLogged(SecretLeakProbe probe, String username) {
        String basicCredentials = Base64
                .getEncoder()
                .encodeToString((username + ":" + PASSWORD).getBytes(StandardCharsets.UTF_8));
        SecretLeakProbe
                .assertNoneReveals(probe.logged(), PASSWORD, CertificateRegistrationSeeder.CHALLENGE, basicCredentials);
    }

    private static void assertRegistrationRejected(Throwable thrown) {
        assertRefusal(thrown, EstError.REGISTRATION_REJECTED);
    }

    private static void assertUnauthorized(Throwable thrown) {
        assertRefusal(thrown, EstError.UNAUTHORIZED);
    }

    private static void assertRefusal(Throwable thrown, EstError error) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(error);
            assertThat(refusal.error().challenges()).isTrue();
            assertThat(refusal.realm()).contains(LABEL);
        });
    }

    /**
     * What the authenticator logs while it is captured, at DEBUG so that its refusal reasons are included. The logger
     * is a process-wide singleton, so closing the capture takes off what was set on it.
     */
    private static final class AuthenticatorLog implements AutoCloseable {

        private final Logger logger = (Logger) LoggerFactory.getLogger(CertificateRegistrationAuthenticator.class);
        private final Level previousLevel = logger.getLevel();
        private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

        private AuthenticatorLog() {
            appender.start();
            logger.setLevel(Level.DEBUG);
            logger.addAppender(appender);
        }

        static AuthenticatorLog capture() {
            return new AuthenticatorLog();
        }

        List<ILoggingEvent> events() {
            return appender.list;
        }

        @Override
        public void close() {
            logger.detachAppender(appender);
            logger.setLevel(previousLevel);
            appender.stop();
        }
    }

    /**
     * An EntityManager bound to the thread, so that every entity a repository reads during the call stays managed in
     * it, where the test can list it, until it is closed; a transaction that a repository starts runs on it.
     */
    private static final class ThreadBoundEntityManager implements AutoCloseable {

        private final EntityManagerFactory factory;
        private final EntityManager entityManager;

        private ThreadBoundEntityManager(EntityManagerFactory factory) {
            this.factory = factory;
            this.entityManager = factory.createEntityManager();
            TransactionSynchronizationManager.bindResource(factory, new EntityManagerHolder(entityManager));
        }

        static ThreadBoundEntityManager open(EntityManagerFactory factory) {
            return new ThreadBoundEntityManager(factory);
        }

        List<String> managedEntityNames() {
            return entityManager
                    .unwrap(Session.class)
                    .getStatistics()
                    .getEntityKeys()
                    .stream()
                    .map(key -> ((EntityKey) key).getEntityName())
                    .toList();
        }

        @Override
        public void close() {
            TransactionSynchronizationManager.unbindResource(factory);
            entityManager.close();
        }
    }
}
