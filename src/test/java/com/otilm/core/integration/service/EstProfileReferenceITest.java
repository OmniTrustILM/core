package com.otilm.core.integration.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.RemoveCertificateDto;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.SecretExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.writer.TokenProfileWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CommentableHostObjects;
import com.otilm.core.util.seeders.TokenProfileSeeder;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** What deleting an object an EST Profile refers to does to the profile. */
class EstProfileReferenceITest extends BaseSpringBootTest {

    @Autowired
    private SecretExternalService secretService;

    @Autowired
    private CertificateExternalService certificateService;

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private SecretRepository secretRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private TokenProfileSeeder tokenProfiles;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private TokenProfileExternalService tokenProfileService;

    @Autowired
    private TokenProfileWriter tokenProfileWriter;

    // ── DeleteSecret ──────────────────────────────────────────────────────────

    @Nested
    class DeleteSecret {

        @Test
        void throwsValidation_whenEstProfileReferencesTheSecret() {
            // given
            UUID referencedSecret = new CommentableHostObjects(applicationContext).create(Resource.SECRET);
            var profileName = "est-devices";
            estProfileRepository
                    .save(anEstProfile()
                            .withName(profileName)
                            .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                            .withBasicCredentialSecrets(referencedSecret)
                            .build());

            // when
            ThrowingCallable deleteReferencedSecret = () -> secretService.deleteSecret(referencedSecret, false);

            // then
            assertThatThrownBy(deleteReferencedSecret)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("EST Profile '" + profileName + "' (EST RA basic credential)");
            assertThat(secretRepository.existsById(referencedSecret)).isTrue();
        }
    }

    // ── DeleteTokenProfile ────────────────────────────────────────────────────

    @Nested
    class DeleteTokenProfile {

        @Test
        void throwsValidationNamingTheEstProfile_whenItRecoversKeysOnTheTokenProfile() {
            // given
            TokenProfile tokenProfile = tokenProfiles.seedTokenProfile();
            var estProfileName = "est-recovery";
            saveProfileRecoveringOn(estProfileName, tokenProfile);

            // when
            ThrowingCallable deleteReferenced = () -> tokenProfileService
                    .deleteTokenProfile(tokenOf(tokenProfile), tokenProfile.getSecuredUuid());

            // then
            assertThatThrownBy(deleteReferenced)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Cannot delete Token Profile '" + tokenProfile.getName() + "'")
                    .hasMessageContaining("EST Profile '" + estProfileName + "' (EST key recovery token profile)")
                    .hasMessageNotContaining("dependent Key");
            assertThat(tokenProfileRepository.existsById(tokenProfile.getUuid())).isTrue();
        }

        @Test
        void keepsTheTokenProfile_whenBulkDeleteMeetsAnEstReference() {
            // given
            TokenProfile tokenProfile = tokenProfiles.seedTokenProfile();
            saveProfileRecoveringOn("est-recovery", tokenProfile);

            // when
            tokenProfileService.deleteTokenProfile(List.of(tokenProfile.getSecuredUuid()));

            // then
            assertThat(tokenProfileRepository.existsById(tokenProfile.getUuid())).isTrue();
        }

        @Test
        void deletesTheTokenProfile_whenNoEstProfileUsesIt() throws Exception {
            // given
            TokenProfile tokenProfile = tokenProfiles.seedTokenProfile();
            saveProfileRecoveringOn("est-other", tokenProfiles.seedTokenProfile());

            // when
            tokenProfileService.deleteTokenProfile(tokenOf(tokenProfile), tokenProfile.getSecuredUuid());

            // then
            assertThat(tokenProfileRepository.existsById(tokenProfile.getUuid())).isFalse();
        }
    }

    // ── DisableTokenProfile ───────────────────────────────────────────────────

    @Nested
    class DisableTokenProfile {

        @Test
        void throwsValidationNamingTheEstProfile_whenItRecoversKeysOnTheTokenProfile() {
            // given
            TokenProfile tokenProfile = tokenProfiles.seedTokenProfile();
            var estProfileName = "est-recovery";
            saveProfileRecoveringOn(estProfileName, tokenProfile);

            // when
            ThrowingCallable disableReferenced = () -> tokenProfileService
                    .disableTokenProfile(tokenOf(tokenProfile), tokenProfile.getSecuredUuid());

            // then
            assertThatThrownBy(disableReferenced)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Cannot disable Token Profile '" + tokenProfile.getName() + "'")
                    .hasMessageContaining("EST Profile '" + estProfileName + "' (EST key recovery token profile)");
            assertThat(isEnabled(tokenProfile)).isTrue();
        }

        @Test
        void throwsValidation_whenAnEditDisablesTheReferencedTokenProfile() {
            // given
            TokenProfile tokenProfile = tokenProfiles.seedTokenProfile();
            saveProfileRecoveringOn("est-recovery", tokenProfile);
            EditTokenProfileRequestDto edit = new EditTokenProfileRequestDto();
            edit.setEnabled(false);

            // when
            ThrowingCallable disableByEdit = () -> tokenProfileWriter
                    .update(tokenProfile.getTokenInstanceReferenceUuid(), tokenProfile.getUuid(), edit);

            // then
            assertThatThrownBy(disableByEdit)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Cannot disable Token Profile");
            assertThat(isEnabled(tokenProfile)).isTrue();
        }

        @Test
        void acceptsAnEditThatDisables_whenTheReferencedTokenProfileIsAlreadyDisabled() throws Exception {
            // given
            TokenProfile tokenProfile = tokenProfiles.seedTokenProfile();
            saveProfileRecoveringOn("est-recovery", tokenProfile);
            tokenProfile.setEnabled(false);
            tokenProfileRepository.saveAndFlush(tokenProfile);
            EditTokenProfileRequestDto edit = new EditTokenProfileRequestDto();
            edit.setEnabled(false);

            // when
            tokenProfileWriter.update(tokenProfile.getTokenInstanceReferenceUuid(), tokenProfile.getUuid(), edit);

            // then
            assertThat(isEnabled(tokenProfile)).isFalse();
        }

        @Test
        void keepsTheTokenProfileEnabled_whenBulkDisableMeetsAnEstReference() {
            // given
            TokenProfile tokenProfile = tokenProfiles.seedTokenProfile();
            saveProfileRecoveringOn("est-recovery", tokenProfile);

            // when
            tokenProfileService.disableTokenProfile(List.of(tokenProfile.getSecuredUuid()));

            // then
            assertThat(isEnabled(tokenProfile)).isTrue();
        }

        @Test
        void disablesTheTokenProfile_whenNoEstProfileUsesIt() throws Exception {
            // given
            TokenProfile tokenProfile = tokenProfiles.seedTokenProfile();

            // when
            tokenProfileService.disableTokenProfile(tokenOf(tokenProfile), tokenProfile.getSecuredUuid());

            // then
            assertThat(isEnabled(tokenProfile)).isFalse();
        }

        private boolean isEnabled(TokenProfile tokenProfile) {
            return tokenProfileRepository.findById(tokenProfile.getUuid()).orElseThrow().getEnabled();
        }
    }

    // ── DeleteCertificate ─────────────────────────────────────────────────────

    @Nested
    class DeleteCertificate {

        @Test
        void removesCertificateFromTrustedCas_whenProfileTrustsIt() throws Exception {
            // given
            UUID deleted = saveCaCertificate("Vendor Root CA");
            UUID kept = saveCaCertificate("Vendor Issuing CA");
            UUID profile = saveProfileTrusting(deleted, kept);

            // when
            certificateService.deleteCertificate(SecuredUUID.fromUUID(deleted));

            // then
            assertThat(loadTrustedCaCertificates(profile)).containsExactly(kept);
        }
    }

    // ── BulkDeleteCertificate ─────────────────────────────────────────────────

    @Nested
    class BulkDeleteCertificate {

        @Test
        void removesCertificatesFromTrustedCas_whenProfileTrustsThem() throws Exception {
            // given
            UUID firstDeleted = saveCaCertificate("Vendor Root CA");
            UUID kept = saveCaCertificate("Vendor Issuing CA");
            UUID secondDeleted = saveCaCertificate("Vendor Legacy CA");
            UUID profile = saveProfileTrusting(firstDeleted, kept, secondDeleted);
            RemoveCertificateDto request = new RemoveCertificateDto();
            request.setUuids(List.of(firstDeleted.toString(), secondDeleted.toString()));

            // when
            certificateService.bulkDeleteCertificate(SecurityFilter.create(), request);

            // then
            assertThat(loadTrustedCaCertificates(profile)).containsExactly(kept);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static SecuredParentUUID tokenOf(TokenProfile tokenProfile) {
        return SecuredParentUUID.fromUUID(tokenProfile.getTokenInstanceReferenceUuid());
    }

    private void saveProfileRecoveringOn(String name, TokenProfile tokenProfile) {
        estProfileRepository
                .save(anEstProfile()
                        .withName(name)
                        .withServerKeyGeneration(true)
                        .withKeyRecovery(true)
                        .withKeyRecoveryTokenProfile(tokenProfile)
                        .build());
    }

    private UUID saveProfileTrusting(UUID... certificateUuids) {
        EstProfile profile = anEstProfile()
                .withAuthenticationPolicy(EstAuthenticationPolicy.VENDOR_MTLS)
                .withTrustedCaCertificates(certificateUuids)
                .build();
        return estProfileRepository.save(profile).getUuid();
    }

    private List<UUID> loadTrustedCaCertificates(UUID profileUuid) {
        return estProfileRepository.findById(profileUuid).orElseThrow().getTrustedCaCertificateUuids();
    }

    private UUID saveCaCertificate(String commonName) {
        return certificateRepository
                .save(aCertificate().withCommonName(commonName).withSubjectType(CertificateSubjectType.ROOT_CA).build())
                .getUuid();
    }
}
