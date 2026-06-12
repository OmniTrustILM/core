package com.otilm.core.mapper.signing;

import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.api.model.core.vaultprofile.VaultProfileDto;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.model.signing.TspProfileModel.BasicCredentialRef;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class TspProfileMapperTest {

    private static final UUID TSP_PROFILE_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID SIGNING_PROFILE_UUID = UUID.fromString("22222222-2222-2222-2222-222222222222");

    private static final String BASE_URL = "http://localhost/api";
    private static final String TSP_PROFILE_NAME = "tsp-profile-x";
    private static final String EXPECTED_SIGNING_URL =
            BASE_URL + "/v1/protocols/tsp/" + TSP_PROFILE_NAME;
    private static final Map<UUID, String> FINGERPRINTS_BY_SECRET = Map.of();




    // ── toDto ─────────────────────────────────────────────────────────────────

    @Nested
    class ToDto {

        @Test
        void mapsAllFields_whenDefaultSigningProfilePresent() {
            // given
            var description = "production timestamping";
            var enabled = true;
            List<ResponseAttribute> customAttributes = List.of(mock(ResponseAttribute.class));
            TspProfile profile = newTspProfile(description, enabled, newSigningProfile("signing-profile-x", true));

            // when
            TspProfileDto dto = TspProfileMapper.toDto(profile, customAttributes, BASE_URL);

            // then
            assertThat(dto.getUuid()).isEqualTo(TSP_PROFILE_UUID.toString());
            assertThat(dto.getName()).isEqualTo(TSP_PROFILE_NAME);
            assertThat(dto.getDescription()).isEqualTo(description);
            assertThat(dto.isEnabled()).isEqualTo(enabled);
            assertThat(dto.getSigningUrl()).isEqualTo(EXPECTED_SIGNING_URL);
            assertThat(dto.getCustomAttributes()).isEqualTo(customAttributes);
            assertThat(dto.getDefaultSigningProfile()).satisfies(simple -> {
                assertThat(simple.getUuid()).isEqualTo(SIGNING_PROFILE_UUID.toString());
                assertThat(simple.getName()).isEqualTo("signing-profile-x");
                assertThat(simple.isEnabled()).isTrue();
            });
        }

        @Test
        void leavesSigningUrlAndDefaultProfileNull_whenNoDefaultSigningProfile() {
            // given
            TspProfile profile = newTspProfile("desc", true, null);

            // when
            TspProfileDto dto = TspProfileMapper.toDto(profile, List.of(), BASE_URL);

            // then
            assertThat(dto.getSigningUrl()).isNull();
            assertThat(dto.getDefaultSigningProfile()).isNull();
        }

        @Test
        void leavesVaultProfileNull_whenNoVaultProfile() {
            // given
            TspProfile profile = newTspProfile("desc", true, null);

            // when
            TspProfileDto dto = TspProfileMapper.toDto(profile, List.of(), BASE_URL);

            // then
            assertThat(dto.getVaultProfile()).isNull();
        }

        @Test
        void populatesVaultProfileDto_whenVaultProfilePresent() {
            // given
            var vaultInstanceUuid = UUID.randomUUID();
            var vaultInstanceName = "prod-vault";
            var vaultProfileName = "basic-creds";
            var vaultProfileDescription = "creds for prod";
            var vaultProfileEnabled = true;
            VaultProfile vaultProfile = newVaultProfile(
                    vaultProfileName, vaultProfileDescription, vaultProfileEnabled,
                    newVaultInstance(vaultInstanceUuid, vaultInstanceName));
            TspProfile profile = newTspProfile("desc", true, null);
            profile.setVaultProfile(vaultProfile);

            // when
            TspProfileDto dto = TspProfileMapper.toDto(profile, List.of(), BASE_URL);

            // then
            VaultProfileDto nested = dto.getVaultProfile();
            assertThat(nested).isNotNull();
            assertThat(nested.getUuid()).isEqualTo(vaultProfile.getUuid().toString());
            assertThat(nested.getName()).isEqualTo(vaultProfileName);
            assertThat(nested.getDescription()).isEqualTo(vaultProfileDescription);
            assertThat(nested.isEnabled()).isEqualTo(vaultProfileEnabled);
            assertThat(nested.getVaultInstance()).isNotNull();
            assertThat(nested.getVaultInstance().getUuid()).isEqualTo(vaultInstanceUuid.toString());
            assertThat(nested.getVaultInstance().getName()).isEqualTo(vaultInstanceName);
        }
    }

    // ── toListDto ───────────────────────────────────────────────────────────────

    @Nested
    class ToListDto {

        @Test
        void mapsAllFields_whenDefaultSigningProfilePresent() {
            // given
            var description = "production timestamping";
            var enabled = false;
            TspProfile profile = newTspProfile(description, enabled, newSigningProfile("signing-profile-x", true));

            // when
            TspProfileListDto dto = TspProfileMapper.toListDto(profile, BASE_URL);

            // then
            assertThat(dto.getUuid()).isEqualTo(TSP_PROFILE_UUID.toString());
            assertThat(dto.getName()).isEqualTo(TSP_PROFILE_NAME);
            assertThat(dto.getDescription()).isEqualTo(description);
            assertThat(dto.isEnabled()).isEqualTo(enabled);
            assertThat(dto.getSigningUrl()).isEqualTo(EXPECTED_SIGNING_URL);
            assertThat(dto.getDefaultSigningProfile()).satisfies(simple -> {
                assertThat(simple.getUuid()).isEqualTo(SIGNING_PROFILE_UUID.toString());
                assertThat(simple.getName()).isEqualTo("signing-profile-x");
                assertThat(simple.isEnabled()).isTrue();
            });
        }

        @Test
        void leavesSigningUrlAndDefaultProfileNull_whenNoDefaultSigningProfile() {
            // given
            TspProfile profile = newTspProfile("desc", true, null);

            // when
            TspProfileListDto dto = TspProfileMapper.toListDto(profile, BASE_URL);

            // then
            assertThat(dto.getSigningUrl()).isNull();
            assertThat(dto.getDefaultSigningProfile()).isNull();
        }
    }

    // ── toModel ───────────────────────────────────────────────────────────────

    @Nested
    class ToModel {

        @Test
        void mapsAllFields_whenDefaultSigningProfilePresent() {
            // given
            var description = "production timestamping";
            var enabled = true;
            var defaultSigningProfileName = "signing-profile-x";
            List<ResponseAttribute> customAttributes = List.of(mock(ResponseAttribute.class));
            TspProfile profile = newTspProfile(description, enabled, newSigningProfile(defaultSigningProfileName, true));

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, customAttributes, FINGERPRINTS_BY_SECRET);

            // then
            assertThat(model.uuid()).isEqualTo(TSP_PROFILE_UUID);
            assertThat(model.name()).isEqualTo(TSP_PROFILE_NAME);
            assertThat(model.description()).isEqualTo(description);
            assertThat(model.enabled()).isEqualTo(enabled);
            assertThat(model.defaultSigningProfileUuid()).isEqualTo(SIGNING_PROFILE_UUID);
            assertThat(model.defaultSigningProfileName()).isEqualTo(defaultSigningProfileName);
            assertThat(model.customAttributes()).isEqualTo(customAttributes);
        }

        @Test
        void leavesSigningProfileReferencesNull_whenNoDefaultSigningProfile() {
            // given
            TspProfile profile = newTspProfile("desc", true, null);

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), FINGERPRINTS_BY_SECRET);

            // then
            assertThat(model.defaultSigningProfileUuid()).isNull();
            assertThat(model.defaultSigningProfileName()).isNull();
        }

        @Test
        void populatesFingerprintFromLookup() {
            // given
            var username = "alice";
            var secretUuid = UUID.randomUUID();
            var mappedUserUuid = UUID.randomUUID();
            var fingerprint = "deadbeef";
            TspProfile profile = newTspProfile("desc", true, null);
            profile.getBasicCredentials().add(newBasicCredential(username, secretUuid, mappedUserUuid));
            Map<UUID, String> fingerprintsBySecret = Map.of(secretUuid, fingerprint);

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), fingerprintsBySecret);

            // then
            BasicCredentialRef ref = model.basicCredentials().getFirst();
            assertThat(ref.username()).isEqualTo(username);
            assertThat(ref.secretUuid()).isEqualTo(secretUuid);
            assertThat(ref.mappedUserUuid()).isEqualTo(mappedUserUuid);
            assertThat(ref.fingerprint()).isEqualTo(fingerprint);
        }

        @Test
        void leavesFingerprintNull_whenSecretAbsentFromLookup() {
            // given
            var secretUuid = UUID.randomUUID();
            TspProfile profile = newTspProfile("desc", true, null);
            profile.getBasicCredentials().add(newBasicCredential("alice", secretUuid, UUID.randomUUID()));

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), FINGERPRINTS_BY_SECRET);

            // then
            assertThat(model.basicCredentials().getFirst().fingerprint()).isNull();
        }

        @Test
        void copiesAllowedAuthenticationMethodsAndCredentialRefs() {
            // given
            var authenticationMethod = TspAuthenticationMethod.BASIC_PASSWORD;
            var username = "svc";
            TspProfile profile = newTspProfile("desc", true, null);
            profile.setAllowedAuthenticationMethods(List.of(authenticationMethod));
            profile.getBasicCredentials().add(newBasicCredential(username, UUID.randomUUID(), UUID.randomUUID()));

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), FINGERPRINTS_BY_SECRET);

            // then
            assertThat(model.allowedAuthenticationMethods()).containsExactly(authenticationMethod);
            assertThat(model.basicCredentials()).hasSize(1);
            assertThat(model.basicCredentials().getFirst().username()).isEqualTo(username);
        }

        @Test
        void yieldsEmptyLists_whenNoMethodsOrCredentials() {
            // given
            TspProfile profile = newTspProfile("desc", true, null);

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), FINGERPRINTS_BY_SECRET);

            // then
            assertThat(model.allowedAuthenticationMethods()).isEmpty();
            assertThat(model.basicCredentials()).isEmpty();
        }

        @Test
        void mapsAllCredentialsWithCorrectFields_whenMultiple() {
            // given
            var secretUuidAlice = UUID.randomUUID();
            var mappedUserUuidAlice = UUID.randomUUID();
            var secretUuidBob = UUID.randomUUID();
            var mappedUserUuidBob = UUID.randomUUID();
            TspProfile profile = newTspProfile("desc", true, null);
            profile.getBasicCredentials().add(newBasicCredential("alice", secretUuidAlice, mappedUserUuidAlice));
            profile.getBasicCredentials().add(newBasicCredential("bob", secretUuidBob, mappedUserUuidBob));

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), FINGERPRINTS_BY_SECRET);

            // then
            assertThat(model.basicCredentials()).hasSize(2);
            BasicCredentialRef alice = credentialOf(model, "alice");
            assertThat(alice.secretUuid()).isEqualTo(secretUuidAlice);
            assertThat(alice.mappedUserUuid()).isEqualTo(mappedUserUuidAlice);
            BasicCredentialRef bob = credentialOf(model, "bob");
            assertThat(bob.secretUuid()).isEqualTo(secretUuidBob);
            assertThat(bob.mappedUserUuid()).isEqualTo(mappedUserUuidBob);
        }
    }

    // ── toSimpleDto (via SigningProfileMapper, exercised by every toDto/toListDto) ──

    @Nested
    class SimpleDtoMapping {

        @Test
        void carriesUuidNameAndEnabled() {
            // given
            var name = "signing-profile-x";
            var enabled = false;
            TspProfile profile = newTspProfile("desc", true, newSigningProfile(name, enabled));

            // when
            SimplifiedSigningProfileDto simple = TspProfileMapper.toDto(profile, List.of(), BASE_URL).getDefaultSigningProfile();

            // then
            assertThat(simple.getUuid()).isEqualTo(SIGNING_PROFILE_UUID.toString());
            assertThat(simple.getName()).isEqualTo(name);
            assertThat(simple.isEnabled()).isEqualTo(enabled);
        }
    }

    private static TspProfile newTspProfile(String description, boolean enabled, SigningProfile defaultSigningProfile) {
        TspProfile profile = new TspProfile();
        profile.setUuid(TSP_PROFILE_UUID);
        profile.setName(TSP_PROFILE_NAME);
        profile.setDescription(description);
        profile.setEnabled(enabled);
        profile.setDefaultSigningProfile(defaultSigningProfile);
        return profile;
    }

    private static SigningProfile newSigningProfile(String name, boolean enabled) {
        SigningProfile profile = new SigningProfile();
        profile.setUuid(SIGNING_PROFILE_UUID);
        profile.setName(name);
        profile.setEnabled(enabled);
        return profile;
    }

    private static TspProfileBasicCredential newBasicCredential(String username, UUID secretUuid, UUID mappedUserUuid) {
        TspProfileBasicCredential credential = new TspProfileBasicCredential();
        credential.setUsername(username);
        credential.setSecretUuid(secretUuid);
        credential.setMappedUserUuid(mappedUserUuid);
        return credential;
    }

    private static BasicCredentialRef credentialOf(TspProfileModel model, String username) {
        return model.basicCredentials().stream()
                .filter(ref -> username.equals(ref.username()))
                .findFirst()
                .orElseThrow();
    }

    private static VaultInstance newVaultInstance(UUID uuid, String name) {
        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setUuid(uuid);
        vaultInstance.setName(name);
        return vaultInstance;
    }

    private static VaultProfile newVaultProfile(String name, String description, boolean enabled, VaultInstance vaultInstance) {
        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setUuid(UUID.randomUUID());
        vaultProfile.setName(name);
        vaultProfile.setDescription(description);
        vaultProfile.setEnabled(enabled);
        vaultProfile.setVaultInstance(vaultInstance);
        return vaultProfile;
    }
}
