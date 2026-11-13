package com.otilm.core.integration.repository;

import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;

class EstProfileRepositoryITest extends BaseSpringBootTest {

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private ProtocolCertificateAssociationsRepository protocolCertificateAssociationsRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateProtocolAssociationRepository certificateProtocolAssociationRepository;

    @Autowired
    private EntityManager entityManager;

    // ── EstProfileFinders ─────────────────────────────────────────────────────

    @Nested
    class EstProfileFinders {

        @Test
        void returnsOnlyProfilesReferencingTheSecret_whenSearchingBySecret() {
            // given
            var firstSecret = UUID.randomUUID();
            var searchedSecret = UUID.randomUUID();
            EstProfile referencing = saveProfileReferencingSecrets("est-devices", firstSecret, searchedSecret);
            saveProfileReferencingSecrets("est-other", UUID.randomUUID());
            saveProfile("est-without-secrets");

            // when
            List<EstProfile> found = estProfileRepository.findByBasicCredentialSecretUuid(searchedSecret);

            // then
            assertThat(found).extracting(EstProfile::getUuid).containsExactly(referencing.getUuid());
        }

        @Test
        void returnsNothing_whenNoProfileReferencesTheSecret() {
            // given
            var unreferencedSecret = UUID.randomUUID();
            saveProfileReferencingSecrets("est-devices", UUID.randomUUID(), UUID.randomUUID());
            saveProfileReferencingSecrets("est-other", UUID.randomUUID());
            saveProfile("est-without-secrets");

            // when
            List<EstProfile> found = estProfileRepository.findByBasicCredentialSecretUuid(unreferencedSecret);

            // then
            assertThat(found).isEmpty();
        }

        @Test
        void returnsTheSystemDefaultProfile() {
            // given
            var systemDefaultName = "est-default";
            saveProfile("est-devices");
            estProfileRepository.save(anEstProfile().withName(systemDefaultName).withSystemDefault(true).build());

            // when
            Optional<EstProfile> found = estProfileRepository.findBySystemDefaultTrue();

            // then
            assertThat(found).get().extracting(EstProfile::getName).isEqualTo(systemDefaultName);
        }

        @Test
        void returnsProfilesWhoseDefaultRaProfileIsTheGivenOne_whenSearchingByRaProfile() {
            // given
            RaProfile raProfile = saveRaProfile("devices-ra");
            EstProfile usingIt = estProfileRepository
                    .save(anEstProfile().withName("est-devices").withRaProfile(raProfile).build());
            saveProfile("est-without-default");

            // when
            List<EstProfile> found = estProfileRepository.findAllByRaProfileUuid(raProfile.getUuid());

            // then
            assertThat(found).extracting(EstProfile::getUuid).containsExactly(usingIt.getUuid());
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private EstProfile saveProfileReferencingSecrets(String name, UUID... secretUuids) {
            return estProfileRepository
                    .save(anEstProfile().withName(name).withBasicCredentialSecrets(secretUuids).build());
        }
    }

    // ── EstProfileStorage ─────────────────────────────────────────────────────

    @Nested
    class EstProfileStorage {

        @Test
        void returnsSavedFields_whenFoundByName() {
            // given
            var profileName = "est-devices";
            var authenticationPolicy = EstAuthenticationPolicy.VENDOR_MTLS;
            var secret = UUID.randomUUID();
            var trustedCa = UUID.randomUUID();
            var renewalThreshold = 30;
            var keyRecoveryKeyAttributes = "[]";
            EstProfile profile = anEstProfile()
                    .withName(profileName)
                    .withAuthenticationPolicy(authenticationPolicy)
                    .withBasicCredentialSecrets(secret)
                    .withTrustedCaCertificates(trustedCa)
                    .withRenewalThreshold(renewalThreshold)
                    .withKeyRecoveryKeyAttributes(keyRecoveryKeyAttributes)
                    .build();
            UUID uuid = estProfileRepository.save(profile).getUuid();

            // when
            EstProfile stored = estProfileRepository.findByName(profileName).orElseThrow();

            // then
            assertThat(stored.getUuid()).isEqualTo(uuid);
            assertThat(stored.getAuthenticationPolicy()).isEqualTo(authenticationPolicy);
            assertThat(stored.getBasicCredentialSecretUuids()).containsExactly(secret);
            assertThat(stored.getTrustedCaCertificateUuids()).containsExactly(trustedCa);
            assertThat(stored.getRenewalThreshold()).isEqualTo(renewalThreshold);
            assertThat(stored.getKeyRecoveryKeyAttributes()).isEqualTo(keyRecoveryKeyAttributes);
        }

        @Test
        void appliesDefaults_whenOnlyNameAndPolicyAreSet() {
            // given
            var profileName = "est-devices";
            saveProfile(profileName);

            // when
            EstProfile stored = estProfileRepository.findByName(profileName).orElseThrow();

            // then
            assertThat(stored.isEnabled()).isFalse();
            assertThat(stored.isSystemDefault()).isFalse();
            assertThat(stored.isAllowRenewal()).isTrue();
            assertThat(stored.isAllowRekey()).isTrue();
            assertThat(stored.isServerKeyGeneration()).isFalse();
            assertThat(stored.isKeyRecovery()).isFalse();
            assertThat(stored.getRenewalThreshold()).isNull();
            assertThat(stored.getBasicCredentialSecretUuids()).isEmpty();
            assertThat(stored.getTrustedCaCertificateUuids()).isEmpty();
        }

        @Test
        void exposesUuidsOfReferencedObjects_whenProfileIsReloaded() {
            // given
            var profileName = "est-devices";
            RaProfile raProfile = saveRaProfile("devices-ra");
            TokenProfile tokenProfile = tokenProfileRepository.save(new TokenProfile());
            ProtocolCertificateAssociations associations = protocolCertificateAssociationsRepository
                    .save(new ProtocolCertificateAssociations());
            saveProfileReferencingObjects(profileName, raProfile, tokenProfile, associations);

            // when
            EstProfile stored = estProfileRepository.findByName(profileName).orElseThrow();

            // then
            assertThat(stored.getRaProfileUuid()).isEqualTo(raProfile.getUuid());
            assertThat(stored.getKeyRecoveryTokenProfileUuid()).isEqualTo(tokenProfile.getUuid());
            assertThat(stored.getCertificateAssociationsUuid()).isEqualTo(associations.getUuid());
        }

        @Test
        void clearsUuidsOfReferencedObjects_whenReferencesAreRemoved() {
            // given
            var profileName = "est-devices";
            RaProfile raProfile = saveRaProfile("devices-ra");
            TokenProfile tokenProfile = tokenProfileRepository.save(new TokenProfile());
            ProtocolCertificateAssociations associations = protocolCertificateAssociationsRepository
                    .save(new ProtocolCertificateAssociations());
            saveProfileReferencingObjects(profileName, raProfile, tokenProfile, associations);
            EstProfile stored = estProfileRepository.findByName(profileName).orElseThrow();

            // when
            stored.setRaProfile(null);
            stored.setKeyRecoveryTokenProfile(null);
            stored.setCertificateAssociations(null);

            // then
            assertThat(stored.getRaProfileUuid()).isNull();
            assertThat(stored.getKeyRecoveryTokenProfileUuid()).isNull();
            assertThat(stored.getCertificateAssociationsUuid()).isNull();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void saveProfileReferencingObjects(String name, RaProfile raProfile, TokenProfile tokenProfile,
                ProtocolCertificateAssociations associations) {
            estProfileRepository
                    .save(anEstProfile()
                            .withName(name)
                            .withRaProfile(raProfile)
                            .withKeyRecoveryTokenProfile(tokenProfile)
                            .withCertificateAssociations(associations)
                            .build());
        }
    }

    // ── RaProfileActivation ───────────────────────────────────────────────────

    @Nested
    class RaProfileActivation {

        @Test
        void returnsEveryRaProfileWithTheEstProfileActivated_whenSearchingByEstProfile() {
            // given
            EstProfile estProfile = saveProfile("est-devices");
            RaProfile first = saveRaProfileActivating("first-ra", estProfile);
            RaProfile second = saveRaProfileActivating("second-ra", estProfile);
            saveRaProfile("without-est");

            // when
            List<RaProfile> found = raProfileRepository.findAllByEstProfileUuid(estProfile.getUuid());

            // then
            assertThat(found)
                    .describedAs("one EST Profile can be activated on many RA Profiles")
                    .extracting(RaProfile::getUuid)
                    .containsExactlyInAnyOrder(first.getUuid(), second.getUuid());
        }

        @Test
        void reportsEstAmongEnabledProtocols_whenEstProfileIsActivated() {
            // given
            EstProfile estProfile = saveProfile("est-devices");
            RaProfile withEst = saveRaProfileActivating("devices-ra", estProfile);

            // when
            RaProfile reloaded = raProfileRepository.findByUuid(withEst.getUuid()).orElseThrow();

            // then
            assertThat(reloaded.getEstProfileUuid()).isEqualTo(estProfile.getUuid());
            assertThat(reloaded.mapToDtoSimple().getEnabledProtocols()).containsExactly("EST");
        }

        @Test
        void reportsNoEnabledProtocols_whenEstProfileIsNotActivated() {
            // given
            saveRaProfileActivating("devices-ra", saveProfile("est-devices"));
            RaProfile withoutEst = saveRaProfile("plain-ra");

            // when
            RaProfile reloaded = raProfileRepository.findByUuid(withoutEst.getUuid()).orElseThrow();

            // then
            assertThat(reloaded.mapToDtoSimple().getEnabledProtocols()).isEmpty();
        }

        @Test
        void reportsNoEnabledProtocols_whenEstProfileIsDeactivated() {
            // given
            RaProfile withEst = saveRaProfileActivating("devices-ra", saveProfile("est-devices"));
            RaProfile reloaded = raProfileRepository.findByUuid(withEst.getUuid()).orElseThrow();

            // when
            reloaded.setEstProfile(null);

            // then
            assertThat(reloaded.getEstProfileUuid()).isNull();
            assertThat(reloaded.mapToDtoSimple().getEnabledProtocols()).isEmpty();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private RaProfile saveRaProfileActivating(String name, EstProfile estProfile) {
            RaProfile raProfile = saveRaProfile(name);
            raProfile.setEstProfile(estProfile);
            return raProfileRepository.save(raProfile);
        }
    }

    // ── CertificateAssociations ───────────────────────────────────────────────

    @Nested
    class CertificateAssociations {

        @Test
        void returnsTheAssociationsOfTheProfile_whenSearchingByEstProfile() {
            // given
            var owner = UUID.randomUUID();
            ProtocolCertificateAssociations associations = saveAssociationsOwnedBy(owner);
            EstProfile withAssociations = saveProfileWithAssociations("est-devices", associations);
            saveProfile("est-plain");

            // when
            ProtocolCertificateAssociations found = protocolCertificateAssociationsRepository
                    .findByEstProfileUuid(withAssociations.getUuid());

            // then
            assertThat(found).isNotNull();
            assertThat(found.getUuid()).isEqualTo(associations.getUuid());
            assertThat(found.getOwnerUuid()).isEqualTo(owner);
        }

        @Test
        void returnsNothing_whenTheEstProfileHasNoAssociations() {
            // given
            ProtocolCertificateAssociations associations = saveAssociationsOwnedBy(UUID.randomUUID());
            saveProfileWithAssociations("est-devices", associations);
            EstProfile withoutAssociations = saveProfile("est-plain");

            // when
            ProtocolCertificateAssociations found = protocolCertificateAssociationsRepository
                    .findByEstProfileUuid(withoutAssociations.getUuid());

            // then
            assertThat(found).isNull();
        }

        @Test
        void resolvesTheEstProfileName_whenProtocolAssociationRefersToTheProfile() {
            // given
            var estProfileName = "est-devices";
            EstProfile profile = saveProfile(estProfileName);
            CertificateProtocolAssociation withProfile = saveEstAssociation(profile.getUuid());

            // when
            String resolvedName = findEstProfileNameOf(withProfile);

            // then
            assertThat(resolvedName).isEqualTo(estProfileName);
        }

        @Test
        void resolvesNoEstProfileName_whenProtocolAssociationRefersToNoProfile() {
            // given
            saveProfile("est-devices");
            CertificateProtocolAssociation withoutProfile = saveEstAssociation(null);

            // when
            String resolvedName = findEstProfileNameOf(withoutProfile);

            // then
            assertThat(resolvedName).isNull();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private ProtocolCertificateAssociations saveAssociationsOwnedBy(UUID owner) {
            ProtocolCertificateAssociations associations = new ProtocolCertificateAssociations();
            associations.setOwnerUuid(owner);
            return protocolCertificateAssociationsRepository.save(associations);
        }

        private EstProfile saveProfileWithAssociations(String name, ProtocolCertificateAssociations associations) {
            return estProfileRepository
                    .save(anEstProfile().withName(name).withCertificateAssociations(associations).build());
        }

        private CertificateProtocolAssociation saveEstAssociation(UUID protocolProfileUuid) {
            UUID certificateUuid = certificateRepository.save(aCertificate().build()).getUuid();
            CertificateProtocolAssociation association = new CertificateProtocolAssociation();
            association.setCertificateUuid(certificateUuid);
            association.setProtocol(CertificateProtocol.EST);
            association.setProtocolProfileUuid(protocolProfileUuid);
            return certificateProtocolAssociationRepository.save(association);
        }

        private String findEstProfileNameOf(CertificateProtocolAssociation association) {
            return entityManager.createQuery("""
                    SELECT p.name
                      FROM CertificateProtocolAssociation a
                      LEFT JOIN a.estProfile p
                     WHERE a.uuid = :uuid
                    """, String.class).setParameter("uuid", association.getUuid()).getResultList().getFirst();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private EstProfile saveProfile(String name) {
        return estProfileRepository.save(anEstProfile().withName(name).build());
    }

    private RaProfile saveRaProfile(String name) {
        RaProfile raProfile = new RaProfile();
        raProfile.setName(name);
        return raProfileRepository.save(raProfile);
    }
}
