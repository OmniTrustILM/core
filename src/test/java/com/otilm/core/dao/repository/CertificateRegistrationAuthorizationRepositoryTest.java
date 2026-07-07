package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.util.UUID;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration coverage for the durable registration-authorization persistence against a real PostgreSQL.
 */
class CertificateRegistrationAuthorizationRepositoryTest extends BaseSpringBootTest {

    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizationRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    private UUID certificateUuid;

    @BeforeEach
    void createCertificate() {
        certificateUuid = certificateRepository.save(aCertificate().build()).getUuid();
    }

    private CertificateRegistrationAuthorization persistAuthorization() {
        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(certificateUuid);
        authorization.setChallenge("v1|ciphertext|salt|1000");
        authorization.setExpiresAt(OffsetDateTime.now().plusDays(1));
        authorization.setState(RegistrationState.ACTIVE);
        return authorizationRepository.save(authorization);
    }

    @Test
    void findByCertificateUuidReturnsThePersistedRow() {
        UUID persistedUuid = persistAuthorization().getUuid();

        CertificateRegistrationAuthorization found =
                authorizationRepository.findByCertificateUuid(certificateUuid).orElseThrow();

        assertThat(found.getUuid()).isEqualTo(persistedUuid);
        assertThat(found.getCertificateUuid()).isEqualTo(certificateUuid);
        assertThat(found.getState()).isEqualTo(RegistrationState.ACTIVE);
    }

    @Test
    void lockedFinderReturnsRowInsideTransaction() {
        persistAuthorization();

        // SELECT ... FOR UPDATE requires an active transaction.
        CertificateRegistrationAuthorization locked = new TransactionTemplate(transactionManager).execute(
                status -> authorizationRepository.findAndLockByCertificateUuid(certificateUuid).orElseThrow());

        assertThat(locked).isNotNull();
        assertThat(locked.getCertificateUuid()).isEqualTo(certificateUuid);
    }

    @Test
    void deleteByCertificateUuidRemovesRow() {
        persistAuthorization();

        // The @Modifying delete needs an ambient transaction; the repository carries none by convention.
        new TransactionTemplate(transactionManager).executeWithoutResult(
                status -> authorizationRepository.deleteByCertificateUuid(certificateUuid));

        assertThat(authorizationRepository.findByCertificateUuid(certificateUuid)).isEmpty();
    }

    @Test
    void deletingParentCertificateCascadesTheAuthorization() {
        // The certificate_uuid association is intentionally unmapped, so Hibernate's create-drop test schema omits
        // the ON DELETE CASCADE foreign key that the migration ships. Recreate it here to exercise the cascade.
        jdbcTemplate.execute("ALTER TABLE core.certificate_registration_authorization "
                + "DROP CONSTRAINT IF EXISTS fk_certificate_registration_authorization_certificate");
        jdbcTemplate.execute("ALTER TABLE core.certificate_registration_authorization "
                + "ADD CONSTRAINT fk_certificate_registration_authorization_certificate "
                + "FOREIGN KEY (certificate_uuid) REFERENCES core.certificate (uuid) ON DELETE CASCADE");
        persistAuthorization();

        certificateRepository.deleteById(certificateUuid);

        assertThat(authorizationRepository.findByCertificateUuid(certificateUuid)).isEmpty();
    }
}
