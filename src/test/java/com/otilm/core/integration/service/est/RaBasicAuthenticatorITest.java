package com.otilm.core.integration.service.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.security.authn.ForwardedCertificateFixtures;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.authentication.RaBasicAuthenticator;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.SqlCapture;
import com.otilm.core.util.seeders.SecretSeeder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;

class RaBasicAuthenticatorITest extends BaseSpringBootTest {

    private static final String LABEL = "devices";
    private static final String CERTIFICATE_HEADER = "ssl-client-cert";
    private static final String CREDENTIAL_NAME = "ra-credential";
    private static final String USERNAME = "alice";
    private static final String PASSWORD = "s3cret";
    private static final String WRONG_PASSWORD = "wr0ng";
    private static final String ROTATED_PASSWORD = "r0tated-s3cret";

    @Autowired
    private RaBasicAuthenticator authenticator;

    @Autowired
    private SecretSeeder seeder;

    private final CertificateRequest csr = mock(CertificateRequest.class);
    private final Logger authenticatorLogger = (Logger) LoggerFactory.getLogger(RaBasicAuthenticator.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private Level previousLevel;
    private boolean previousAdditive;

    /**
     * The logger is a process-wide singleton, so what is set on it here is taken off again after each test. While it is
     * captured, its lines reach no other appender.
     */
    @BeforeEach
    void captureTheAuthenticatorLog() {
        previousLevel = authenticatorLogger.getLevel();
        previousAdditive = authenticatorLogger.isAdditive();
        authenticatorLogger.setLevel(Level.DEBUG);
        authenticatorLogger.setAdditive(false);
        logged.start();
        authenticatorLogger.addAppender(logged);
    }

    @AfterEach
    void releaseTheAuthenticatorLog() {
        authenticatorLogger.detachAppender(logged);
        logged.stop();
        authenticatorLogger.setLevel(previousLevel);
        authenticatorLogger.setAdditive(previousAdditive);
    }

    @Test
    void authenticatesAsSecret_whenCredentialsMatchAReferencedSecret() {
        // given
        Secret otherCredential = seeder.seedBasicAuthSecret("other-credential", "bob", "an0ther-s3cret");
        Secret matchingCredential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        EstRoute route = routeReferencing(otherCredential, matchingCredential);
        EstClientCredentials credentials = basicCredentials(USERNAME, PASSWORD);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertThat(client)
                .isEqualTo(new EstClient(EstAuthenticationPolicy.RA_BASIC, secretIdentity(matchingCredential), null));
    }

    @Test
    void authenticates_whenPasswordContainsColons() {
        // given
        var passwordWithColons = "pa:ss:wo:rd:";
        Secret credential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, passwordWithColons);
        EstRoute route = routeReferencing(credential);
        EstClientCredentials credentials = basicCredentials(USERNAME, passwordWithColons);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertThat(client.identity()).isEqualTo(secretIdentity(credential));
    }

    @ParameterizedTest
    @MethodSource("credentialsThatDoNotMatch")
    void throwsUnauthorizedWithChallenge_whenCredentialsDoNotMatch(Stored stored, EstClientCredentials credentials) {
        // given
        Secret secret = seeder
                .seedSecret(CREDENTIAL_NAME, stored.type(), stored.state(), stored.enabled(),
                        SecretSeeder.fingerprintOf(USERNAME, PASSWORD));
        seeder.setSourceVaultProfileEnabled(secret, stored.vaultProfileEnabled());
        EstRoute route = stored.referenced() ? routeReferencing(secret) : routeReferencing();

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate).satisfies(RaBasicAuthenticatorITest::assertUnauthorizedWithChallenge);
    }

    @Test
    void authenticatesWithNewPassword_whenSecretContentWasUpdated() {
        // given
        Secret credential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        EstRoute route = routeReferencing(credential);
        // a first success, so that no answer of an earlier request can be reused
        authenticator.authenticate(route, basicCredentials(USERNAME, PASSWORD), csr);
        seeder.replaceBasicAuthContent(credential, USERNAME, ROTATED_PASSWORD);

        // when
        EstClient client = authenticator.authenticate(route, basicCredentials(USERNAME, ROTATED_PASSWORD), csr);

        // then
        assertThat(client.identity()).isEqualTo(secretIdentity(credential));
    }

    @Test
    void throwsUnauthorizedWithChallenge_whenOldPasswordIsPresentedAfterSecretContentWasUpdated() {
        // given
        Secret credential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        EstRoute route = routeReferencing(credential);
        seeder.replaceBasicAuthContent(credential, USERNAME, ROTATED_PASSWORD);
        EstClientCredentials oldCredentials = basicCredentials(USERNAME, PASSWORD);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, oldCredentials, csr);

        // then
        assertThatThrownBy(authenticate).satisfies(RaBasicAuthenticatorITest::assertUnauthorizedWithChallenge);
    }

    @Test
    void authenticatesAgain_whenSourceVaultProfileIsEnabledAgain() {
        // given
        Secret credential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        seeder.setSourceVaultProfileEnabled(credential, false);
        EstRoute route = routeReferencing(credential);
        EstClientCredentials credentials = basicCredentials(USERNAME, PASSWORD);
        // refused first, so that no answer of an earlier request can be reused
        ThrowingCallable authenticateWhileDisabled = () -> authenticator.authenticate(route, credentials, csr);
        assertThatThrownBy(authenticateWhileDisabled).isInstanceOf(EstException.class);
        seeder.setSourceVaultProfileEnabled(credential, true);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertThat(client.identity()).isEqualTo(secretIdentity(credential));
    }

    @Test
    void throwsUnauthorizedWithChallenge_whenSourceVaultProfileWasDisabledAfterAnAuthentication() {
        // given
        Secret credential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        EstRoute route = routeReferencing(credential);
        EstClientCredentials credentials = basicCredentials(USERNAME, PASSWORD);
        // accepted first, so that no answer of an earlier request can be reused
        authenticator.authenticate(route, credentials, csr);
        seeder.setSourceVaultProfileEnabled(credential, false);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

        // then
        assertThatThrownBy(authenticate).satisfies(RaBasicAuthenticatorITest::assertUnauthorizedWithChallenge);
    }

    @Test
    void readsTheSecretsInOneQuery_whenSeveralAreReferenced() throws Exception {
        // given
        Secret first = seeder.seedBasicAuthSecret("first-credential", "bob", "an0ther-s3cret");
        Secret second = seeder.seedBasicAuthSecret("second-credential", "carol", "y3t-an0ther");
        Secret matching = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        EstRoute route = routeReferencing(first, second, matching);
        EstClientCredentials credentials = basicCredentials(USERNAME, PASSWORD);

        // when
        SqlCapture.Captured<EstClient> authenticated = SqlCapture
                .during(() -> authenticator.authenticate(route, credentials, csr));

        // then
        assertThat(authenticated.result().identity()).isEqualTo(secretIdentity(matching));
        assertThat(authenticated.statements()).hasSize(1);
    }

    @ParameterizedTest
    @MethodSource("listingOrders")
    void authenticatesAsTheFirstListedSecret_whenTwoReferencedSecretsMatch(boolean listedInReverse) {
        // given
        Secret stored = seeder.seedBasicAuthSecret("stored-first", USERNAME, PASSWORD);
        Secret storedSecond = seeder.seedBasicAuthSecret("stored-second", USERNAME, PASSWORD);
        Secret listedFirst = listedInReverse ? storedSecond : stored;
        Secret listedSecond = listedInReverse ? stored : storedSecond;
        EstRoute route = routeReferencing(listedFirst, listedSecond);
        EstClientCredentials credentials = basicCredentials(USERNAME, PASSWORD);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertThat(client.identity()).isEqualTo(secretIdentity(listedFirst));
    }

    @ParameterizedTest
    @MethodSource("clientCertificateHeaders")
    void ignoresClientCertificate_whenProfilePolicyIsRaBasic(String certificateHeader) {
        // given
        Secret credential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        EstRoute route = routeReferencing(credential);
        EstClientCredentials credentials = credentialsOf(basic(USERNAME, PASSWORD), certificateHeader);

        // when
        EstClient client = authenticator.authenticate(route, credentials, csr);

        // then
        assertThat(client.identity()).isEqualTo(secretIdentity(credential));
    }

    @Test
    void logsTheRefusalOnlyAtDebug_whenCredentialsDoNotMatch() {
        // given
        Secret credential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        EstRoute route = routeReferencing(credential);
        EstClientCredentials wrongCredentials = basicCredentials(USERNAME, WRONG_PASSWORD);

        // when
        ThrowingCallable authenticate = () -> authenticator.authenticate(route, wrongCredentials, csr);

        // then
        assertThatThrownBy(authenticate).isInstanceOf(EstException.class);
        assertThat(logged.list).isNotEmpty().allSatisfy(event -> assertThat(event.getLevel()).isEqualTo(Level.DEBUG));
    }

    @Test
    void logsNoCredential_whenCredentialsMatch() {
        // given
        Secret credential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        EstRoute route = routeReferencing(credential);
        EstClientCredentials credentials = basicCredentials(USERNAME, PASSWORD);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            EstClient client = authenticator.authenticate(route, credentials, csr);

            // then
            assertThat(client.identity()).isEqualTo(secretIdentity(credential));
            assertNoCredentialLogged(probe, PASSWORD);
        }
    }

    @Test
    void logsNoCredential_whenCredentialsDoNotMatch() {
        // given
        Secret credential = seeder.seedBasicAuthSecret(CREDENTIAL_NAME, USERNAME, PASSWORD);
        EstRoute route = routeReferencing(credential);
        EstClientCredentials credentials = basicCredentials(USERNAME, WRONG_PASSWORD);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            ThrowingCallable authenticate = () -> authenticator.authenticate(route, credentials, csr);

            // then
            assertThatThrownBy(authenticate).isInstanceOf(EstException.class);
            assertNoCredentialLogged(probe, WRONG_PASSWORD);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> credentialsThatDoNotMatch() {
        Stored usable = Stored.usable();
        Named<Stored> usableSecret = named("a usable Secret", usable);
        Named<EstClientCredentials> matchingCredentials = named("matching credentials",
                basicCredentials(USERNAME, PASSWORD));
        Stream<Arguments> presentedWrongly = Stream
                .of(arguments(usableSecret, named("no credentials", credentialsOf(null, null))),
                        arguments(usableSecret,
                                named("only a client certificate",
                                        credentialsOf(null, ForwardedCertificateFixtures.LEAF_DER))),
                        arguments(usableSecret,
                                named("only a malformed client certificate", credentialsOf(null, "not a certificate"))),
                        arguments(usableSecret,
                                named("malformed Basic credentials", credentialsOf("Basic !!!not-base64!!!", null))),
                        arguments(usableSecret, named("a wrong password", basicCredentials(USERNAME, WRONG_PASSWORD))),
                        arguments(usableSecret, named("an empty username", basicCredentials("", PASSWORD))));
        Stream<Arguments> unusableSecrets = Stream
                .of(arguments(named("an unreferenced Secret", usable.unreferenced()), matchingCredentials),
                        arguments(named("a disabled Secret", usable.disabled()), matchingCredentials),
                        arguments(named("a Secret whose source vault profile is disabled",
                                usable.withDisabledVaultProfile()), matchingCredentials),
                        arguments(named("a Secret of another type", usable.ofType(SecretType.KEY_VALUE)),
                                matchingCredentials));
        Stream<Arguments> inactiveSecrets = Arrays
                .stream(SecretState.values())
                .filter(state -> state != SecretState.ACTIVE)
                .map(state -> arguments(named("a Secret in the state " + state, usable.inState(state)),
                        matchingCredentials));
        return Stream.of(presentedWrongly, unusableSecrets, inactiveSecrets).flatMap(Function.identity());
    }

    static Stream<Arguments> listingOrders() {
        return Stream
                .of(arguments(named("listed in the order they were stored", false)),
                        arguments(named("listed in the reverse order", true)));
    }

    static Stream<Arguments> clientCertificateHeaders() {
        return Stream
                .of(arguments(named("a valid client certificate", ForwardedCertificateFixtures.LEAF_DER)),
                        arguments(named("a malformed client certificate", "not a certificate")));
    }

    /**
     * The one Secret that the profile may reference, what is stored about it and its source vault profile, and whether
     * the profile references it. It starts as a Secret that can authenticate; each method changes one thing.
     */
    private record Stored(SecretType type, SecretState state, boolean enabled, boolean vaultProfileEnabled,
            boolean referenced) {

        static Stored usable() {
            return new Stored(SecretType.BASIC_AUTH, SecretState.ACTIVE, true, true, true);
        }

        Stored ofType(SecretType otherType) {
            return new Stored(otherType, state, enabled, vaultProfileEnabled, referenced);
        }

        Stored inState(SecretState otherState) {
            return new Stored(type, otherState, enabled, vaultProfileEnabled, referenced);
        }

        Stored disabled() {
            return new Stored(type, state, false, vaultProfileEnabled, referenced);
        }

        Stored withDisabledVaultProfile() {
            return new Stored(type, state, enabled, false, referenced);
        }

        Stored unreferenced() {
            return new Stored(type, state, enabled, vaultProfileEnabled, false);
        }
    }

    private static EstRoute routeReferencing(Secret... credentialSecrets) {
        UUID[] secretUuids = Arrays.stream(credentialSecrets).map(Secret::getUuid).toArray(UUID[]::new);
        EstProfile estProfile = anEstProfile()
                .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                .withBasicCredentialSecrets(secretUuids)
                .build();
        return new EstRoute(estProfile, null, false, LABEL);
    }

    private static String secretIdentity(Secret secret) {
        return "secret:" + secret.getUuid();
    }

    private static EstClientCredentials basicCredentials(String username, String password) {
        return credentialsOf(basic(username, password), null);
    }

    private static String basic(String username, String password) {
        return "Basic " + encodedCredentials(username, password);
    }

    private static String encodedCredentials(String username, String password) {
        byte[] userAndPassword = (username + ":" + password).getBytes(StandardCharsets.UTF_8);
        return Base64.getEncoder().encodeToString(userAndPassword);
    }

    /** What a client presented; a {@code null} header is not sent. */
    private static EstClientCredentials credentialsOf(String authorization, String certificateHeader) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (authorization != null) {
            request.addHeader(HttpHeaders.AUTHORIZATION, authorization);
        }
        if (certificateHeader != null) {
            request.addHeader(CERTIFICATE_HEADER, certificateHeader);
        }
        return EstClientCredentials.from(request, CERTIFICATE_HEADER);
    }

    /**
     * Neither the stored password nor the presented one, nor what encodes or fingerprints either, was logged: not in
     * what the probe caught, nor in the lines of the authenticator, which its capture keeps from the probe.
     */
    private void assertNoCredentialLogged(SecretLeakProbe probe, String presentedPassword) {
        List<String> everythingLogged = new ArrayList<>(probe.logged());
        logged.list.forEach(event -> everythingLogged.add(event.getFormattedMessage()));
        SecretLeakProbe
                .assertNoneReveals(everythingLogged, PASSWORD, presentedPassword,
                        encodedCredentials(USERNAME, presentedPassword), SecretSeeder.fingerprintOf(USERNAME, PASSWORD),
                        SecretSeeder.fingerprintOf(USERNAME, presentedPassword));
    }

    private static void assertUnauthorizedWithChallenge(Throwable thrown) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(EstError.UNAUTHORIZED);
            assertThat(refusal.error().challenges()).isTrue();
            assertThat(refusal.realm()).contains(LABEL);
        });
    }
}
