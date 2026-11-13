package com.otilm.core.integration.service.writer.est;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.service.writer.est.EstProfileWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;

class EstProfileWriterITest extends BaseSpringBootTest {

    private static final OffsetDateTime LONG_AGO = OffsetDateTime.parse("2000-01-01T00:00:00Z");

    @Autowired
    private EstProfileWriter estProfileWriter;

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void removesCertificateKeepingTheRestInOrder_whenProfileTrustsIt() {
        // given
        var first = UUID.randomUUID();
        var removed = UUID.randomUUID();
        var last = UUID.randomUUID();
        var trustedByNoProfile = UUID.randomUUID();
        UUID listing = saveProfileTrusting("est-a", first, removed, last);

        // when
        estProfileWriter.removeTrustedCaCertificates(List.of(removed, trustedByNoProfile));

        // then
        assertThat(loadTrustedCaCertificates(listing)).containsExactly(first, last);
        assertThat(loadUpdatedAt(listing)).isAfter(LONG_AGO);
    }

    @Test
    void leavesProfileUntouched_whenItDoesNotTrustTheRemovedCertificate() {
        // given
        var removed = UUID.randomUUID();
        var trustedByNoProfile = UUID.randomUUID();
        var otherCertificate = UUID.randomUUID();
        saveProfileTrusting("est-a", UUID.randomUUID(), removed, UUID.randomUUID());
        UUID other = saveProfileTrusting("est-b", otherCertificate);

        // when
        estProfileWriter.removeTrustedCaCertificates(List.of(removed, trustedByNoProfile));

        // then
        assertThat(loadTrustedCaCertificates(other)).containsExactly(otherCertificate);
        assertThat(loadUpdatedAt(other)).isAtSameInstantAs(LONG_AGO);
    }

    @Test
    void leavesEmptyList_whenTheOnlyTrustedCertificateIsRemoved() {
        // given
        var onlyCertificate = UUID.randomUUID();
        UUID profile = saveProfileTrusting("est-a", onlyCertificate);

        // when
        estProfileWriter.removeTrustedCaCertificates(List.of(onlyCertificate));

        // then
        assertThat(loadTrustedCaColumnAsText(profile)).describedAs("an empty array, not NULL").isEqualTo("{}");
        assertThat(loadUpdatedAt(profile)).isAfter(LONG_AGO);
    }

    @Test
    void changesNothing_whenNoCertificatesAreGiven() {
        // given
        var trustedCertificate = UUID.randomUUID();
        UUID profile = saveProfileTrusting("est-a", trustedCertificate);

        // when
        estProfileWriter.removeTrustedCaCertificates(List.of());

        // then
        assertThat(loadTrustedCaCertificates(profile)).containsExactly(trustedCertificate);
        assertThat(loadUpdatedAt(profile)).isAtSameInstantAs(LONG_AGO);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Pins the last update long ago, so whether a write touched the row shows whatever the clocks say. */
    private UUID saveProfileTrusting(String name, UUID... certificateUuids) {
        EstProfile profile = anEstProfile()
                .withName(name)
                .withAuthenticationPolicy(EstAuthenticationPolicy.VENDOR_MTLS)
                .withTrustedCaCertificates(certificateUuids)
                .build();
        UUID uuid = estProfileRepository.save(profile).getUuid();
        jdbcTemplate.update("UPDATE " + dbSchema + ".est_profile SET i_upd = ? WHERE uuid = ?", LONG_AGO, uuid);
        return uuid;
    }

    private List<UUID> loadTrustedCaCertificates(UUID uuid) {
        return estProfileRepository.findById(uuid).orElseThrow().getTrustedCaCertificateUuids();
    }

    private String loadTrustedCaColumnAsText(UUID uuid) {
        return jdbcTemplate
                .queryForObject(
                        "SELECT trusted_ca_certificate_uuids::text FROM " + dbSchema + ".est_profile WHERE uuid = ?",
                        String.class, uuid);
    }

    private OffsetDateTime loadUpdatedAt(UUID uuid) {
        return jdbcTemplate
                .queryForObject("SELECT i_upd FROM " + dbSchema + ".est_profile WHERE uuid = ?", OffsetDateTime.class,
                        uuid);
    }
}
