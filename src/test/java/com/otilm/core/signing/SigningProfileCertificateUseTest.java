package com.otilm.core.signing;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SigningProfileCertificateUseTest {

    private static final UUID CERTIFICATE_UUID = UUID.fromString("6f1c2a4e-0b7d-4c1e-9a53-2d8e7f6a1b90");

    // ── ByCertificate ─────────────────────────────────────────────────────────
    @Nested
    class ByCertificate {

        @Test
        void splitsProfilesIntoCurrentAndSupersededOnly_whenVersionsOfSeveralProfilesHoldTheCertificate() {
            // given
            var currentVersion = new CertificateHoldingVersion(CERTIFICATE_UUID, "signing-profile", 2, 2);
            var supersededVersion = new CertificateHoldingVersion(CERTIFICATE_UUID, "renewed-profile", 1, 3);

            // when
            Map<UUID, SigningProfileCertificateUse> uses = SigningProfileCertificateUse
                    .byCertificate(List.of(currentVersion, supersededVersion));

            // then
            assertThat(uses).containsOnlyKeys(CERTIFICATE_UUID);
            assertThat(uses.get(CERTIFICATE_UUID).currentVersionProfiles()).containsExactly("signing-profile");
            assertThat(uses.get(CERTIFICATE_UUID).supersededOnlyProfiles()).containsExactly("renewed-profile");
        }

        @Test
        void namesProfileOnlyAsCurrent_whenItsCurrentAndSupersededVersionsBothHoldTheCertificate() {
            // given
            var supersededVersion = new CertificateHoldingVersion(CERTIFICATE_UUID, "signing-profile", 1, 2);
            var currentVersion = new CertificateHoldingVersion(CERTIFICATE_UUID, "signing-profile", 2, 2);

            // when
            Map<UUID, SigningProfileCertificateUse> uses = SigningProfileCertificateUse
                    .byCertificate(List.of(supersededVersion, currentVersion));

            // then
            assertThat(uses.get(CERTIFICATE_UUID).currentVersionProfiles()).containsExactly("signing-profile");
            assertThat(uses.get(CERTIFICATE_UUID).supersededOnlyProfiles()).isEmpty();
        }

        @Test
        void namesEachProfileOnceAlphabetically_whenSeveralVersionsOfAProfileHoldTheCertificate() {
            // given
            var laterVersionOfZulu = new CertificateHoldingVersion(CERTIFICATE_UUID, "zulu", 2, 3);
            var alpha = new CertificateHoldingVersion(CERTIFICATE_UUID, "alpha", 1, 3);
            var earlierVersionOfZulu = new CertificateHoldingVersion(CERTIFICATE_UUID, "zulu", 1, 3);

            // when
            Map<UUID, SigningProfileCertificateUse> uses = SigningProfileCertificateUse
                    .byCertificate(List.of(laterVersionOfZulu, alpha, earlierVersionOfZulu));

            // then
            assertThat(uses.get(CERTIFICATE_UUID).supersededOnlyProfiles()).containsExactly("alpha", "zulu");
        }

        @Test
        void keepsEachCertificateApart_whenVersionsHoldSeveral() {
            // given
            var otherCertificateUuid = UUID.fromString("0b7d6f1c-2a4e-4c1e-9a53-7f6a1b902d8e");
            var holdingThisCertificate = new CertificateHoldingVersion(CERTIFICATE_UUID, "signing-profile", 1, 1);
            var holdingOtherCertificate = new CertificateHoldingVersion(otherCertificateUuid, "other-profile", 1, 1);

            // when
            Map<UUID, SigningProfileCertificateUse> uses = SigningProfileCertificateUse
                    .byCertificate(List.of(holdingThisCertificate, holdingOtherCertificate));

            // then
            assertThat(uses.get(CERTIFICATE_UUID).currentVersionProfiles()).containsExactly("signing-profile");
            assertThat(uses.get(otherCertificateUuid).currentVersionProfiles()).containsExactly("other-profile");
        }

        @Test
        void returnsNoUse_whenNoVersionHoldsACertificate() {
            // given — no stored version holds any of the certificates

            // when
            Map<UUID, SigningProfileCertificateUse> uses = SigningProfileCertificateUse.byCertificate(List.of());

            // then
            assertThat(uses).isEmpty();
        }
    }

    // ── DeleteRefusal ─────────────────────────────────────────────────────────
    @Nested
    class DeleteRefusal {

        @Test
        void namesCurrentVersionProfiles_whenOnlyCurrentVersionsHoldTheCertificate() {
            // given
            var use = new SigningProfileCertificateUse(List.of("alpha", "beta"), List.of());

            // when
            String refusal = use.deleteRefusal("signer.example.com", CERTIFICATE_UUID);

            // then
            assertThat(refusal)
                    .isEqualTo("Could not delete certificate signer.example.com with UUID " + CERTIFICATE_UUID
                            + ": it is used by the current version of Signing Profile(s): alpha, beta.");
        }

        @Test
        void saysOnlyDeletingTheProfileReleasesIt_whenOnlySupersededVersionsHoldTheCertificate() {
            // given
            var use = new SigningProfileCertificateUse(List.of(), List.of("renewed-profile"));

            // when
            String refusal = use.deleteRefusal("signer.example.com", CERTIFICATE_UUID);

            // then
            assertThat(refusal)
                    .isEqualTo("Could not delete certificate signer.example.com with UUID " + CERTIFICATE_UUID
                            + ": it is kept by superseded versions of Signing Profile(s)"
                            + " (released only by deleting the Signing Profile, which first requires deleting its signing records): renewed-profile.");
        }

        @Test
        void namesBothGroups_whenCurrentAndSupersededVersionsHoldTheCertificate() {
            // given
            var use = new SigningProfileCertificateUse(List.of("signing-profile"), List.of("renewed-profile"));

            // when
            String refusal = use.deleteRefusal("signer.example.com", CERTIFICATE_UUID);

            // then
            assertThat(refusal)
                    .isEqualTo("Could not delete certificate signer.example.com with UUID " + CERTIFICATE_UUID
                            + ": it is used by the current version of Signing Profile(s): signing-profile;"
                            + " kept by superseded versions of Signing Profile(s)"
                            + " (released only by deleting the Signing Profile, which first requires deleting its signing records): renewed-profile.");
        }
    }
}
