package com.otilm.core.integration.service.registration;

import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Boots the full context so {@code SecretsUtil}'s static encryption key is injected from
 * {@code secrets.encryption.key} in the test {@code application.yml}.
 */
class RegistrationChallengeStoreITest extends BaseSpringBootTest {

    private static final String PLAINTEXT = "s3cr3t-challenge-value";

    @Autowired
    private RegistrationChallengeStore challengeStore;

    @Test
    void storeEncryptsThenVerifyAndResolveRoundTrip() {
        CertificateRegistrationAuthorization row = new CertificateRegistrationAuthorization();

        challengeStore.store(row, PLAINTEXT);

        assertThat(row.getChallenge()).isNotNull().isNotEqualTo(PLAINTEXT);
        assertThat(challengeStore.verify(row, PLAINTEXT)).isTrue();
        assertThat(challengeStore.resolvePlaintext(row)).isEqualTo(PLAINTEXT);
    }

    @Test
    void verifyRejectsWrongValue() {
        CertificateRegistrationAuthorization row = new CertificateRegistrationAuthorization();
        challengeStore.store(row, PLAINTEXT);

        assertThat(challengeStore.verify(row, "not-the-challenge")).isFalse();
    }

    @Test
    void verifyRejectsNullPresentedValue() {
        CertificateRegistrationAuthorization row = new CertificateRegistrationAuthorization();
        challengeStore.store(row, PLAINTEXT);

        assertThat(challengeStore.verify(row, null)).isFalse();
    }

    @Test
    void verifyRejectsWhenNoStoredChallenge() {
        assertThat(challengeStore.verify(new CertificateRegistrationAuthorization(), PLAINTEXT)).isFalse();
    }

    @Test
    void storeRejectsMissingChallenge() {
        CertificateRegistrationAuthorization row = new CertificateRegistrationAuthorization();
        assertThatThrownBy(() -> challengeStore.store(row, null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> challengeStore.store(row, "   ")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void resolvePlaintextRejectsUnpopulatedRow() {
        CertificateRegistrationAuthorization row = new CertificateRegistrationAuthorization();
        assertThatThrownBy(() -> challengeStore.resolvePlaintext(row))
                .isInstanceOf(IllegalStateException.class);
    }
}
