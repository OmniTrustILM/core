package com.otilm.core.integration.service.writer.registration;

import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.registration.CertificateRegistrationAuthorizationWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration coverage for the successor copy on {@link CertificateRegistrationAuthorizationWriter}: the challenge
 * credential follows the certificate lineage on renew/rekey without ever being decrypted.
 */
class CertificateRegistrationAuthorizationWriterITest extends BaseSpringBootTest {

    private static final String CIPHERTEXT = "v1|ciphertext|salt|1000";

    @Autowired
    private CertificateRegistrationAuthorizationWriter authorizationWriter;
    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizationRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    private UUID predecessorUuid;
    private UUID successorUuid;

    @BeforeEach
    void createCertificates() {
        predecessorUuid = certificateRepository.save(aCertificate().build()).getUuid();
        successorUuid = certificateRepository.save(aCertificate().build()).getUuid();
    }

    private CertificateRegistrationAuthorization persistPredecessorAuthorization(RegistrationState state,
            int failedAttempts, OffsetDateTime expiresAt) {
        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(predecessorUuid);
        authorization.setChallenge(CIPHERTEXT);
        authorization.setState(state);
        authorization.setFailedAttempts(failedAttempts);
        authorization.setExpiresAt(expiresAt);
        return authorizationRepository.save(authorization);
    }

    @Test
    void copyToSuccessorReusesCiphertextAndResetsCounters() {
        OffsetDateTime window = OffsetDateTime.now().plusDays(1);
        persistPredecessorAuthorization(RegistrationState.ACTIVE, 3, window);

        authorizationWriter.copyToSuccessor(predecessorUuid, successorUuid);

        CertificateRegistrationAuthorization copied = authorizationRepository
                .findByCertificateUuid(successorUuid)
                .orElseThrow();
        assertThat(copied.getChallenge()).isEqualTo(CIPHERTEXT);
        assertThat(copied.getState()).isEqualTo(RegistrationState.ACTIVE);
        assertThat(copied.getFailedAttempts()).isZero();
        assertThat(copied.getExpiresAt()).isNull();

        CertificateRegistrationAuthorization predecessor = authorizationRepository
                .findByCertificateUuid(predecessorUuid)
                .orElseThrow();
        assertThat(predecessor.getFailedAttempts())
                .as("the predecessor's own authorization is left untouched by the copy")
                .isEqualTo(3);
    }

    @Test
    void copyToSuccessorCarriesNullIssuanceWindow() {
        // Post-issuance the predecessor's window is cleared; the copy must not invent a new deadline.
        persistPredecessorAuthorization(RegistrationState.ACTIVE, 0, null);

        authorizationWriter.copyToSuccessor(predecessorUuid, successorUuid);

        assertThat(authorizationRepository.findByCertificateUuid(successorUuid).orElseThrow().getExpiresAt()).isNull();
    }

    @Test
    void copyToSuccessorIsNoOpWithoutPredecessorAuthorization() {
        authorizationWriter.copyToSuccessor(predecessorUuid, successorUuid);

        assertThat(authorizationRepository.count()).isZero();
    }

    @Test
    void copyToSuccessorIsNoOpForNonActivePredecessorAuthorization() {
        // Only a live credential follows the lineage; a locked/expired/closed one must not be resurrected
        // as a fresh ACTIVE authorization on the successor.
        persistPredecessorAuthorization(RegistrationState.LOCKED, 5, null);

        authorizationWriter.copyToSuccessor(predecessorUuid, successorUuid);

        assertThat(authorizationRepository.findByCertificateUuid(successorUuid)).isEmpty();
    }
}
