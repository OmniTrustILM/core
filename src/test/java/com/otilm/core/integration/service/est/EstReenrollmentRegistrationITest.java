package com.otilm.core.integration.service.est;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.core.api.est.EstExceptionHandlingAdvice;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.enrollment.EstReenrollmentKind;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.builders.V3ConnectorStubs;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.CertificateRequestPolicySeeder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.util.EstClientCredentialsFixtures.certificateAndBasicCredentials;
import static com.otilm.core.util.EstClientCredentialsFixtures.certificateCredentials;
import static com.otilm.core.util.mocks.AuthorityV2ConnectorStubs.RENEW_PATH;
import static com.otilm.core.util.seeders.CertificateRegistrationSeeder.CHALLENGE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code /simplereenroll} through the service for a client whose certificate a registration guards, as completing a
 * pre-registration through the {@code certificateRegistration} EST Profile leaves the certificate that it issued: the
 * client renews or rekeys it only with the password of the registration, which it sends as its Basic password, and the
 * Basic credentials that a client of another policy sends count for nothing.
 */
class EstReenrollmentRegistrationITest extends AbstractEstReenrollmentITest {

    private static final String CLIENT_USERNAME = "device-1";
    private static final String WRONG_PASSWORD = "not-the-challenge";
    private static final String RA_USERNAME = "ra-operator";
    private static final String RA_PASSWORD = "ra-password";
    private static final String RENEW_ATTRIBUTES_RA_PROFILE_NAME = "devices-ra-requiring-renew-attributes";

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizations;

    @Autowired
    private RegistrationChallengeStore challengeStore;

    @Autowired
    private CertificateEventHistoryRepository eventHistory;

    @Autowired
    private CertificateRequestPolicySeeder requestPolicies;

    private WireMockServer renewAttributeAuthority;

    @AfterEach
    void stopTheAuthorityThatRequiresRenewAttributes() {
        if (renewAttributeAuthority != null) {
            renewAttributeAuthority.stop();
        }
    }

    @ParameterizedTest
    @EnumSource(EstReenrollmentKind.class)
    void renewsSource_whenRegistrationPasswordIsPresented(EstReenrollmentKind kind) throws Exception {
        // given
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.ACTIVE);
        KeyPair requestKeys = chooseKeysFor(kind);
        X509Certificate issuedForTheRequest = issueFreshCertificate(requestKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(issuedForTheRequest);
        byte[] request = signRequest(requestKeys);
        EstClientCredentials withThePassword = certificateAndBasicCredentials(source, CLIENT_USERNAME, CHALLENGE);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            ResponseEntity<byte[]> response = reenroll(request, withThePassword);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(readCertificate(response)).isEqualTo(issuedForTheRequest);
            Certificate successor = findInInventory(issuedForTheRequest);
            assertSuccessorOf(seededSource, successor);
            assertThat(authorizations.findByCertificateUuid(successor.getUuid())).hasValueSatisfying(copy -> {
                assertThat(copy.getState()).isEqualTo(RegistrationState.ACTIVE);
                assertThat(challengeStore.verify(copy, CHALLENGE)).isTrue();
            });
            assertNoPasswordLogged(probe, CHALLENGE);
        }
    }

    @Test
    void answersSuccessor_whenRetriedWithoutPassword() throws Exception {
        // given — the first request presented the password, and the certificate that it created answers the retry
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.ACTIVE);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
        byte[] request = signRequest(deviceKeys);
        reenroll(request, certificateAndBasicCredentials(source, CLIENT_USERNAME, CHALLENGE));

        // when
        ResponseEntity<byte[]> retry = reenroll(request, certificateCredentials(source));

        // then — the platform was not asked for the registration again, which records each refusal on the source
        assertThat(retry.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(retry)).isEqualTo(renewed);
        assertThat(eventHistory.findByCertificateOrderByCreatedDesc(seededSource))
                .extracting(CertificateEventHistory::getStatus)
                .doesNotContain(CertificateEventStatus.FAILED);
        connector.verify(1, WireMock.postRequestedFor(WireMock.urlPathMatching(RENEW_PATH)));
    }

    @Test
    void asksForPassword_whenNoneIsPresented() throws Exception {
        // given
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.ACTIVE);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials withoutPassword = certificateCredentials(source);

        // when
        ThrowingCallable reenroll = () -> reenroll(request, withoutPassword);

        // then
        assertThatThrownBy(reenroll).satisfies(EstReenrollmentRegistrationITest::assertAskedForPassword);
        assertThat(findAuthorizationOf(seededSource)).satisfies(unchanged -> {
            assertThat(unchanged.getState()).isEqualTo(RegistrationState.ACTIVE);
            assertThat(unchanged.getFailedAttempts()).isZero();
        });
        assertThat(certificateRepository.count()).isOne();
    }

    @Test
    void asksForPassword_whenPasswordIsWrong() throws Exception {
        // given
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.ACTIVE);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials withAWrongPassword = certificateAndBasicCredentials(source, CLIENT_USERNAME,
                WRONG_PASSWORD);

        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            ThrowingCallable reenroll = () -> reenroll(request, withAWrongPassword);

            // then
            assertThatThrownBy(reenroll).satisfies(EstReenrollmentRegistrationITest::assertAskedForPassword);
            assertThat(findAuthorizationOf(seededSource).getFailedAttempts()).isOne();
            assertThat(certificateRepository.count()).isOne();
            assertNoPasswordLogged(probe, WRONG_PASSWORD);
        }
    }

    @Test
    void asksForPassword_whenAuthorizationIsLocked() throws Exception {
        // given — the password is right, but too many wrong ones locked the registration
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.LOCKED);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials withThePassword = certificateAndBasicCredentials(source, CLIENT_USERNAME, CHALLENGE);

        // when
        ThrowingCallable reenroll = () -> reenroll(request, withThePassword);

        // then
        assertThatThrownBy(reenroll).satisfies(EstReenrollmentRegistrationITest::assertAskedForPassword);
        assertThat(findAuthorizationOf(seededSource).getState()).isEqualTo(RegistrationState.LOCKED);
        assertThat(certificateRepository.count()).isOne();
    }

    @Test
    void asksForPassword_whenAuthorizationHasExpired() throws Exception {
        // given — the password is right, but the registration has expired
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.EXPIRED);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials withThePassword = certificateAndBasicCredentials(source, CLIENT_USERNAME, CHALLENGE);

        // when
        ThrowingCallable reenroll = () -> reenroll(request, withThePassword);

        // then
        assertThatThrownBy(reenroll).satisfies(EstReenrollmentRegistrationITest::assertAskedForPassword);
        assertThat(findAuthorizationOf(seededSource).getState()).isEqualTo(RegistrationState.EXPIRED);
        assertThat(certificateRepository.count()).isOne();
    }

    @Test
    void answersServiceUnavailable_whenAuthorityRequiresRenewAttributes() throws Exception {
        // given — the password is right, and the authority wants a renew attribute, which a re-enrolment never sends,
        // so the platform refuses the renewal as invalid after the registration has let it through
        RaProfile requiringRenewAttributes = routeThroughAnAuthorityThatRequiresRenewAttributes();
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, requiringRenewAttributes, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.ACTIVE);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials withThePassword = certificateAndBasicCredentials(source, CLIENT_USERNAME, CHALLENGE);

        // when
        ThrowingCallable reenroll = () -> reenroll(request, withThePassword);

        // then
        assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(EstError.SERVICE_UNAVAILABLE);
            assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
        });
        assertThat(findAuthorizationOf(seededSource)).satisfies(verified -> {
            assertThat(verified.getState()).isEqualTo(RegistrationState.ACTIVE);
            assertThat(verified.getFailedAttempts()).isZero();
        });
        assertThat(certificateRepository.count()).isOne();
    }

    @Test
    void refusesWithPolicyText_whenRequestAttributePolicyIsViolated() throws Exception {
        // given — the password is right, and the default request-attribute set wants a common name, which neither the
        // source nor the request has
        requestPolicies.requireStrictRequestAttributes();
        var subjectWithoutCommonName = "O=Acme";
        X509Certificate source = issueDueCertificate(deviceKeys, subjectWithoutCommonName);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.ACTIVE);
        byte[] requestWithoutCommonName = EstCsrFixtures.signedRequestBody(deviceKeys, subjectWithoutCommonName);
        EstClientCredentials withThePassword = certificateAndBasicCredentials(source, CLIENT_USERNAME, CHALLENGE);

        // when
        ThrowingCallable reenroll = () -> reenroll(requestWithoutCommonName, withThePassword);

        // then
        assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(EstError.POLICY_VIOLATION);
            assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
            assertThat(refusal.detail()).hasValueSatisfying(detail -> assertThat(detail).contains(RA_PROFILE_NAME));
        });
        assertThat(certificateRepository.count()).isOne();
    }

    @Test
    void asksForPassword_whenRouteAuthenticatesByRaCredentials() throws Exception {
        // given — the profile no longer authenticates by registrations but by the Basic credentials of an RA, which the
        // device sends along, while a registration still guards its certificate
        authenticateBy(EstAuthenticationPolicy.RA_BASIC);
        X509Certificate source = issueDueCertificate(deviceKeys);
        Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
        registrations.seedRetainedAuthorization(seededSource, RegistrationState.ACTIVE);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials withTheRaPassword = certificateAndBasicCredentials(source, RA_USERNAME, RA_PASSWORD);

        // when
        ThrowingCallable reenroll = () -> reenroll(request, withTheRaPassword);

        // then — the registration was asked without a password, which counts no failed attempt
        assertThatThrownBy(reenroll).satisfies(EstReenrollmentRegistrationITest::assertAskedForPassword);
        assertThat(findAuthorizationOf(seededSource)).satisfies(unchanged -> {
            assertThat(unchanged.getState()).isEqualTo(RegistrationState.ACTIVE);
            assertThat(unchanged.getFailedAttempts()).isZero();
        });
    }

    @ParameterizedTest
    @EnumSource(EstAuthenticationPolicy.class)
    void ignoresBasicHeader_whenSourceHasNoAuthorization(EstAuthenticationPolicy policy) throws Exception {
        // given — the profile authenticates enrolments by the policy, and the device sends Basic credentials along
        authenticateBy(policy);
        X509Certificate source = issueDueCertificate(deviceKeys);
        routes.seedIssuedCertificate(source, raProfile, estProfile);
        X509Certificate renewed = issueFreshCertificate(deviceKeys);
        AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
        byte[] request = signRequest(deviceKeys);
        EstClientCredentials withTheRaPassword = certificateAndBasicCredentials(source, RA_USERNAME, RA_PASSWORD);

        // when
        ResponseEntity<byte[]> response = reenroll(request, withTheRaPassword);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readCertificate(response)).isEqualTo(renewed);
        assertThat(authorizations.findAll()).isEmpty();
        assertThat(eventHistory.findAll())
                .extracting(CertificateEventHistory::getStatus)
                .doesNotContain(CertificateEventStatus.FAILED);
        assertThat(captureQueuedActionData())
                .isInstanceOfSatisfying(ClientCertificateRenewRequestDto.class,
                        renewal -> assertThat(renewal.getAuthorizationSecret()).isNull());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** The key that a request asks for the kind with: the key of the device to renew, a new key to rekey. */
    private KeyPair chooseKeysFor(EstReenrollmentKind kind) {
        return kind == EstReenrollmentKind.RENEWAL ? deviceKeys : PkiFixtures.keyPair();
    }

    /**
     * Moves the route to an RA Profile whose authority wants a renew attribute for every renewal and rekey: a v3
     * authority with a renew schema, on a connector of its own, as a connector serves one authority.
     */
    private RaProfile routeThroughAnAuthorityThatRequiresRenewAttributes() {
        renewAttributeAuthority = LoopbackWireMock.start();
        V3ConnectorStubs.stubRenewSchemaRequiringAnAttribute(renewAttributeAuthority);
        return routeThroughV3Authority(renewAttributeAuthority, RENEW_ATTRIBUTES_RA_PROFILE_NAME);
    }

    private CertificateRegistrationAuthorization findAuthorizationOf(Certificate certificate) {
        return authorizations.findByCertificateUuid(certificate.getUuid()).orElseThrow();
    }

    /** What the action that the platform queued for the new certificate hands to the listener. */
    private Object captureQueuedActionData() {
        ArgumentCaptor<ActionMessage> queued = ArgumentCaptor.forClass(ActionMessage.class);
        Mockito.verify(actionProducer).produceMessage(queued.capture());
        return queued.getValue().getData();
    }

    /**
     * The client is asked for the password as it is asked for any credential: 401 with the Basic challenge of the realm
     * of the route and the sentence that asks for authentication, and nothing more.
     */
    private static void assertAskedForPassword(Throwable thrown) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            ResponseEntity<byte[]> answer = new EstExceptionHandlingAdvice().handleEstException(refusal);
            assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(answer.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + EST_PROFILE_NAME + "\"");
            assertThat(new String(answer.getBody(), StandardCharsets.UTF_8)).isEqualTo(EstError.UNAUTHORIZED.text());
        });
    }

    /**
     * Neither the password, nor the challenge of the registration, nor the Basic credentials that carried it were
     * logged.
     */
    private static void assertNoPasswordLogged(SecretLeakProbe probe, String password) {
        String basicCredentials = Base64
                .getEncoder()
                .encodeToString((CLIENT_USERNAME + ":" + password).getBytes(StandardCharsets.UTF_8));
        SecretLeakProbe.assertNoneReveals(probe.logged(), password, CHALLENGE, basicCredentials);
    }
}
