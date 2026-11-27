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
            var currentVersion = new CertificateHold(CERTIFICATE_UUID, "signing-profile", true);
            var supersededVersion = new CertificateHold(CERTIFICATE_UUID, "renewed-profile", false);

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
            var supersededVersion = new CertificateHold(CERTIFICATE_UUID, "signing-profile", false);
            var currentVersion = new CertificateHold(CERTIFICATE_UUID, "signing-profile", true);

            // when
            Map<UUID, SigningProfileCertificateUse> uses = SigningProfileCertificateUse
                    .byCertificate(List.of(supersededVersion, currentVersion));

            // then
            assertThat(uses.get(CERTIFICATE_UUID).currentVersionProfiles()).containsExactly("signing-profile");
            assertThat(uses.get(CERTIFICATE_UUID).supersededOnlyProfiles()).isEmpty();
        }

        @Test
        void sortsProfileNames_whenHoldsArriveInReverseOrder() {
            // given
            var zuluCurrent = new CertificateHold(CERTIFICATE_UUID, "zulu-current", true);
            var alphaCurrent = new CertificateHold(CERTIFICATE_UUID, "alpha-current", true);
            var zuluSuperseded = new CertificateHold(CERTIFICATE_UUID, "zulu-superseded", false);
            var alphaSuperseded = new CertificateHold(CERTIFICATE_UUID, "alpha-superseded", false);

            // when
            Map<UUID, SigningProfileCertificateUse> uses = SigningProfileCertificateUse
                    .byCertificate(List.of(zuluCurrent, alphaCurrent, zuluSuperseded, alphaSuperseded));

            // then
            assertThat(uses.get(CERTIFICATE_UUID).currentVersionProfiles())
                    .containsExactly("alpha-current", "zulu-current");
            assertThat(uses.get(CERTIFICATE_UUID).supersededOnlyProfiles())
                    .containsExactly("alpha-superseded", "zulu-superseded");
        }

        @Test
        void keepsEachCertificateApart_whenVersionsHoldSeveral() {
            // given
            var otherCertificateUuid = UUID.fromString("0b7d6f1c-2a4e-4c1e-9a53-7f6a1b902d8e");
            var holdingThisCertificate = new CertificateHold(CERTIFICATE_UUID, "signing-profile", true);
            var holdingOtherCertificate = new CertificateHold(otherCertificateUuid, "other-profile", true);

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
