package com.otilm.core.integration.repository;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

class EstRegistrationRequestLookupITest extends BaseSpringBootTest {

    private static final String SUBJECT = "CN=device-1";
    private static final byte[] REQUEST_BYTES = "the request".getBytes(StandardCharsets.UTF_8);
    private static final byte[] OTHER_REQUEST_BYTES = "another request".getBytes(StandardCharsets.UTF_8);

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private RaProfile raProfile;

    @BeforeEach
    void seedRaProfile() {
        raProfile = routes.seedRaProfile("devices-ra");
    }

    @Test
    void findsRegistration_whenItsRequestHasTheFingerprint() throws Exception {
        // given
        Certificate registration = completedWithTheRequest(registrations.seedRegistration(raProfile, SUBJECT));

        // when
        List<UUID> found = certificateRepository
                .findRegistrationsRequestedWith(raProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).containsExactly(registration.getUuid());
    }

    @ParameterizedTest
    @EnumSource(RegistrationState.class)
    void findsRegistration_whenItsAuthorizationIsInAnyState(RegistrationState authorizationState) throws Exception {
        // given
        Certificate registration = completedWithTheRequest(
                registrations.seedRegistrationWithAuthorization(raProfile, SUBJECT, authorizationState));

        // when
        List<UUID> found = certificateRepository
                .findRegistrationsRequestedWith(raProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).containsExactly(registration.getUuid());
    }

    @Test
    void findsNewestFirst_whenTwoRegistrationsHaveTheRequest() throws Exception {
        // given
        Certificate older = completedWithTheRequest(registrations.seedRegistration(raProfile, SUBJECT));
        Certificate newer = completedWithTheRequest(registrations.seedRegistration(raProfile, SUBJECT));
        createdAnHourEarlier(older);

        // when
        List<UUID> found = certificateRepository
                .findRegistrationsRequestedWith(raProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).containsExactly(newer.getUuid(), older.getUuid());
    }

    @Test
    void findsNothing_whenFingerprintDiffers() throws Exception {
        // given
        completedWithTheRequest(registrations.seedRegistration(raProfile, SUBJECT));
        var otherFingerprint = fingerprintOf(OTHER_REQUEST_BYTES);

        // when
        List<UUID> found = certificateRepository.findRegistrationsRequestedWith(raProfile.getUuid(), otherFingerprint);

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void findsNothing_whenCertificateHasNoRegistrationAuthorization() throws Exception {
        // given
        completedWithTheRequest(registrations.seedRegistrationWithoutAuthorization(raProfile, SUBJECT));

        // when
        List<UUID> found = certificateRepository
                .findRegistrationsRequestedWith(raProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void findsNothing_whenRegistrationIsArchived() throws Exception {
        // given
        completedWithTheRequest(registrations.seedArchivedRegistration(raProfile, SUBJECT));

        // when
        List<UUID> found = certificateRepository
                .findRegistrationsRequestedWith(raProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void findsNothing_whenRegistrationBelongsToAnotherRaProfile() throws Exception {
        // given
        RaProfile anotherRaProfile = routes.seedRaProfile("other-ra");
        completedWithTheRequest(registrations.seedRegistration(anotherRaProfile, SUBJECT));

        // when
        List<UUID> found = certificateRepository
                .findRegistrationsRequestedWith(raProfile.getUuid(), fingerprintOf(REQUEST_BYTES));

        // then
        assertThat(found).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Certificate completedWithTheRequest(Certificate registration) {
        return registrations.seedCompletion(registration, REQUEST_BYTES, CertificateState.ISSUED);
    }

    /** Two saves in a row can be stamped with the same instant, so the order is made explicit. */
    private void createdAnHourEarlier(Certificate certificate) {
        Timestamp anHourEarlier = Timestamp.from(Instant.now().minus(1, ChronoUnit.HOURS));
        jdbcTemplate
                .update("UPDATE " + dbSchema + ".certificate SET i_cre = ? WHERE uuid = ?", anHourEarlier,
                        certificate.getUuid());
    }

    private static String fingerprintOf(byte[] requestBytes) throws NoSuchAlgorithmException {
        return CertificateUtil.getThumbprint(requestBytes);
    }
}
