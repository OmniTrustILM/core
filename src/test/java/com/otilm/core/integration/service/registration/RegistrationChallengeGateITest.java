package com.otilm.core.integration.service.registration;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.service.registration.RegistrationChallengeException;
import com.otilm.core.service.registration.RegistrationChallengeGate;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.seeders.CertificateRegistrationSeeder.CHALLENGE;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The refusals of the registration challenge gate, against authorizations in the database: each is a
 * {@link RegistrationChallengeException} with the fixed text of the gate, which a caller that answers an invalid
 * request still catches as a {@code ValidationException}.
 */
class RegistrationChallengeGateITest extends BaseSpringBootTest {

    private static final String SUBJECT = "CN=device-1";
    private static final String WRONG_CHALLENGE = "not-the-challenge";

    @Autowired
    private RegistrationChallengeGate gate;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private EstRouteSeeder routes;

    private RaProfile raProfile;

    @BeforeEach
    void seedRaProfile() {
        raProfile = routes.seedRaProfile("registrations-ra");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void throwsChallengeException_whenNoSecretIsPresented(String missingSecret) {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);

        // when
        ThrowingCallable verify = () -> gate.verify(registration.getUuid(), missingSecret, CertificateEvent.RENEW);

        // then
        assertThatThrownBy(verify)
                .isInstanceOf(RegistrationChallengeException.class)
                .hasMessageContaining("The certificate registration challenge is required.");
    }

    @Test
    void throwsChallengeException_whenSecretIsWrong() {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);

        // when
        ThrowingCallable verify = () -> gate.verify(registration.getUuid(), WRONG_CHALLENGE, CertificateEvent.RENEW);

        // then
        assertThatThrownBy(verify)
                .isInstanceOf(RegistrationChallengeException.class)
                .hasMessageContaining("The certificate registration challenge is invalid.");
    }

    @Test
    void throwsChallengeException_whenPredicateRefusesTheChallenge() {
        // given
        Certificate registration = registrations.seedRegistration(raProfile, SUBJECT);

        // when
        ThrowingCallable verify = () -> gate.verify(registration.getUuid(), CertificateEvent.ISSUE, challenge -> false);

        // then
        assertThatThrownBy(verify)
                .isInstanceOf(RegistrationChallengeException.class)
                .hasMessageContaining("The certificate registration challenge is invalid.");
    }

    @Test
    void throwsChallengeException_whenAuthorizationIsLocked() {
        // given
        Certificate registration = registrations
                .seedRegistrationWithAuthorization(raProfile, SUBJECT, RegistrationState.LOCKED);

        // when
        ThrowingCallable verify = () -> gate.verify(registration.getUuid(), CHALLENGE, CertificateEvent.RENEW);

        // then
        assertThatThrownBy(verify)
                .isInstanceOf(RegistrationChallengeException.class)
                .hasMessageContaining(
                        "The certificate registration authorization is locked after too many failed attempts.");
    }

    @Test
    void throwsChallengeException_whenAuthorizationHasExpired() {
        // given
        Certificate registration = registrations
                .seedRegistrationWithAuthorization(raProfile, SUBJECT, RegistrationState.EXPIRED);

        // when
        ThrowingCallable verify = () -> gate.verify(registration.getUuid(), CHALLENGE, CertificateEvent.RENEW);

        // then
        assertThatThrownBy(verify)
                .isInstanceOf(RegistrationChallengeException.class)
                .hasMessageContaining("The certificate registration issuance window has expired.");
    }

    @Test
    void throwsChallengeException_whenIssuanceWindowHasPassed() {
        // given
        Certificate registration = registrations.seedRegistrationWithPassedWindow(raProfile, SUBJECT);

        // when
        ThrowingCallable verify = () -> gate.verify(registration.getUuid(), CHALLENGE, CertificateEvent.ISSUE);

        // then
        assertThatThrownBy(verify)
                .isInstanceOf(RegistrationChallengeException.class)
                .hasMessageContaining("The certificate registration issuance window has expired.");
    }
}
