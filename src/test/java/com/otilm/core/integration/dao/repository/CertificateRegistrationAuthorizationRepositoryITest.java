package com.otilm.core.integration.dao.repository;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration coverage for the durable registration-authorization persistence against a real PostgreSQL.
 */
class CertificateRegistrationAuthorizationRepositoryITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizationRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;

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
    void findsOnlyRegisteredCertificatesWithActiveAuthorizationUnderRaProfile() {
        UUID raProfileUuid = persistRaProfile();
        UUID otherRaProfileUuid = persistRaProfile();

        Certificate match = persistCertificate(CertificateState.REGISTERED, raProfileUuid);
        persistAuthorizationFor(match.getUuid(), RegistrationState.ACTIVE);

        Certificate lockedAuthorization = persistCertificate(CertificateState.REGISTERED, raProfileUuid);
        persistAuthorizationFor(lockedAuthorization.getUuid(), RegistrationState.LOCKED);

        // REGISTERED without any authorization row: not challenge-protected, must not match.
        persistCertificate(CertificateState.REGISTERED, raProfileUuid);

        Certificate issued = persistCertificate(CertificateState.ISSUED, raProfileUuid);
        persistAuthorizationFor(issued.getUuid(), RegistrationState.ACTIVE);

        Certificate underOtherProfile = persistCertificate(CertificateState.REGISTERED, otherRaProfileUuid);
        persistAuthorizationFor(underOtherProfile.getUuid(), RegistrationState.ACTIVE);

        assertThat(certificateRepository
                .findRegisteredWithActiveRegistrationAuthorizationByRaProfileUuidAndSubjectDnNormalized(raProfileUuid,
                        CertificateUtil.normalizeStoredSubjectDn("CN=lookup-subject")))
                .extracting(Certificate::getUuid)
                .containsExactly(match.getUuid());
    }

    @Test
    void registrationLookupExcludesOtherSubjects() {
        UUID raProfileUuid = persistRaProfile();
        Certificate match = persistCertificate(CertificateState.REGISTERED, raProfileUuid, "CN=lookup-subject");
        persistAuthorizationFor(match.getUuid(), RegistrationState.ACTIVE);
        Certificate otherSubject = persistCertificate(CertificateState.REGISTERED, raProfileUuid, "CN=other-subject");
        persistAuthorizationFor(otherSubject.getUuid(), RegistrationState.ACTIVE);

        assertThat(certificateRepository
                .findRegisteredWithActiveRegistrationAuthorizationByRaProfileUuidAndSubjectDnNormalized(raProfileUuid,
                        CertificateUtil.normalizeStoredSubjectDn("CN=lookup-subject")))
                .extracting(Certificate::getUuid)
                .containsExactly(match.getUuid());
    }

    @Test
    void registrationLookupFindsSanOnlyRegistrationsByTheEmptyNormalizedSubject() {
        UUID raProfileUuid = persistRaProfile();
        Certificate sanOnly = persistCertificate(CertificateState.REGISTERED, raProfileUuid, null);
        persistAuthorizationFor(sanOnly.getUuid(), RegistrationState.ACTIVE);

        assertThat(certificateRepository
                .findRegisteredWithActiveRegistrationAuthorizationByRaProfileUuidAndSubjectDnNormalized(raProfileUuid,
                        ""))
                .extracting(Certificate::getUuid)
                .containsExactly(sanOnly.getUuid());
    }

    @Test
    void registrationLookupIncludesRowsWithNoNormalizedSubject() {
        UUID raProfileUuid = persistRaProfile();
        // A placeholder written by an old instance during a rolling upgrade (after the one-shot backfill)
        // carries no normalized subject; the lookup must still surface it for the caller's identity match
        // rather than leave it permanently unmatchable, even when the presented subject differs.
        Certificate legacyNullNormalized = aCertificate().withState(CertificateState.REGISTERED).build();
        legacyNullNormalized.setRaProfileUuid(raProfileUuid);
        legacyNullNormalized.setSubjectDn("CN=lookup-subject");
        legacyNullNormalized.setSubjectDnNormalized(null);
        legacyNullNormalized = certificateRepository.save(legacyNullNormalized);
        persistAuthorizationFor(legacyNullNormalized.getUuid(), RegistrationState.ACTIVE);

        assertThat(certificateRepository
                .findRegisteredWithActiveRegistrationAuthorizationByRaProfileUuidAndSubjectDnNormalized(raProfileUuid,
                        CertificateUtil.normalizeStoredSubjectDn("CN=different-subject")))
                .extracting(Certificate::getUuid)
                .containsExactly(legacyNullNormalized.getUuid());
    }

    private UUID persistRaProfile() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("rp-" + UUID.randomUUID());
        raProfile.setEnabled(true);
        return raProfileRepository.save(raProfile).getUuid();
    }

    private Certificate persistCertificate(CertificateState state, UUID raProfileUuid) {
        return persistCertificate(state, raProfileUuid, "CN=lookup-subject");
    }

    private Certificate persistCertificate(CertificateState state, UUID raProfileUuid, String subjectDn) {
        Certificate certificate = aCertificate().withState(state).build();
        certificate.setRaProfileUuid(raProfileUuid);
        certificate.setSubjectDn(subjectDn);
        certificate.setSubjectDnNormalized(CertificateUtil.normalizeStoredSubjectDn(subjectDn));
        return certificateRepository.save(certificate);
    }

    private void persistAuthorizationFor(UUID forCertificateUuid, RegistrationState state) {
        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(forCertificateUuid);
        authorization.setChallenge("v1|ciphertext|salt|1000");
        authorization.setExpiresAt(OffsetDateTime.now().plusDays(1));
        authorization.setState(state);
        authorizationRepository.save(authorization);
    }

    @Test
    void findByCertificateUuidReturnsThePersistedRow() {
        UUID persistedUuid = persistAuthorization().getUuid();

        CertificateRegistrationAuthorization found = authorizationRepository
                .findByCertificateUuid(certificateUuid)
                .orElseThrow();

        assertThat(found.getUuid()).isEqualTo(persistedUuid);
        assertThat(found.getCertificateUuid()).isEqualTo(certificateUuid);
        assertThat(found.getState()).isEqualTo(RegistrationState.ACTIVE);
    }

    @Test
    void lockedFinderReturnsRowInsideTransaction() {
        persistAuthorization();

        // SELECT ... FOR UPDATE requires an active transaction.
        CertificateRegistrationAuthorization locked = new TransactionTemplate(transactionManager)
                .execute(status -> authorizationRepository.findAndLockByCertificateUuid(certificateUuid).orElseThrow());

        assertThat(locked).isNotNull();
        assertThat(locked.getCertificateUuid()).isEqualTo(certificateUuid);
    }

    @Test
    void deleteByCertificateUuidRemovesRow() {
        persistAuthorization();

        // The @Modifying delete needs an ambient transaction; the repository carries none by convention.
        new TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> authorizationRepository.deleteByCertificateUuid(certificateUuid));

        assertThat(authorizationRepository.findByCertificateUuid(certificateUuid)).isEmpty();
    }
}
