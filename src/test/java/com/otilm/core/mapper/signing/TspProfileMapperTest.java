package com.otilm.core.mapper.signing;

import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.otilm.api.model.core.vaultprofile.VaultProfileDto;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class TspProfileMapperTest {

    // ── ToModel ───────────────────────────────────────────────────────────────

    @Nested
    class ToModel {

        @Test
        void populatesFingerprintFromLookup() {
            // given
            UUID secretUuid = UUID.randomUUID();
            UUID mappedUser = UUID.randomUUID();

            TspProfile profile = new TspProfile();
            profile.setName("p1");
            TspProfileBasicCredential cred = new TspProfileBasicCredential();
            cred.setUsername("alice");
            cred.setSecretUuid(secretUuid);
            cred.setMappedUserUuid(mappedUser);
            profile.getBasicCredentials().add(cred);

            Map<UUID, String> fingerprints = Map.of(secretUuid, "deadbeef");

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), fingerprints);

            // then
            TspProfileModel.BasicCredentialRef ref = model.basicCredentials().get(0);
            assertThat(ref.username()).isEqualTo("alice");
            assertThat(ref.secretUuid()).isEqualTo(secretUuid);
            assertThat(ref.mappedUserUuid()).isEqualTo(mappedUser);
            assertThat(ref.fingerprint()).isEqualTo("deadbeef");
        }

        @Test
        void copiesMethodsAndCredentialRefs() {
            // given
            TspProfile profile = new TspProfile();
            profile.setName("p");
            profile.setAllowedAuthenticationMethods(List.of(TspAuthenticationMethod.BASIC_PASSWORD));
            TspProfileBasicCredential cred = new TspProfileBasicCredential();
            cred.setUsername("svc");
            cred.setSecretUuid(UUID.randomUUID());
            cred.setMappedUserUuid(UUID.randomUUID());
            profile.getBasicCredentials().add(cred);

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), Map.of());

            // then
            assertThat(model.allowedAuthenticationMethods()).isEqualTo(List.of(TspAuthenticationMethod.BASIC_PASSWORD));
            assertThat(model.basicCredentials()).hasSize(1);
            assertThat(model.basicCredentials().get(0).username()).isEqualTo("svc");
        }

        @Test
        void yieldsEmptyLists_whenProfileEmpty() {
            // given — allowedAuthenticationMethods and basicCredentials both default to empty ArrayList
            TspProfile profile = new TspProfile();
            profile.setName("empty");

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), Map.of());

            // then
            assertThat(model.allowedAuthenticationMethods()).isNotNull();
            assertThat(model.allowedAuthenticationMethods()).isEmpty();
            assertThat(model.basicCredentials()).isNotNull();
            assertThat(model.basicCredentials()).isEmpty();
        }

        @Test
        void mapsAllCredentialsWithCorrectFields_whenMultiple() {
            // given
            TspProfile profile = new TspProfile();
            profile.setName("multi");
            profile.setAllowedAuthenticationMethods(new ArrayList<>(List.of(TspAuthenticationMethod.BASIC_PASSWORD)));

            UUID secretA = UUID.randomUUID();
            UUID mappedA = UUID.randomUUID();
            TspProfileBasicCredential credA = new TspProfileBasicCredential();
            credA.setUsername("alice");
            credA.setSecretUuid(secretA);
            credA.setMappedUserUuid(mappedA);

            UUID secretB = UUID.randomUUID();
            UUID mappedB = UUID.randomUUID();
            TspProfileBasicCredential credB = new TspProfileBasicCredential();
            credB.setUsername("bob");
            credB.setSecretUuid(secretB);
            credB.setMappedUserUuid(mappedB);

            profile.getBasicCredentials().add(credA);
            profile.getBasicCredentials().add(credB);

            // when
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of(), Map.of());

            // then
            assertThat(model.basicCredentials()).hasSize(2);

            TspProfileModel.BasicCredentialRef refA = model.basicCredentials().stream()
                    .filter(r -> "alice".equals(r.username())).findFirst().orElseThrow();
            assertThat(refA.secretUuid()).isEqualTo(secretA);
            assertThat(refA.mappedUserUuid()).isEqualTo(mappedA);

            TspProfileModel.BasicCredentialRef refB = model.basicCredentials().stream()
                    .filter(r -> "bob".equals(r.username())).findFirst().orElseThrow();
            assertThat(refB.secretUuid()).isEqualTo(secretB);
            assertThat(refB.mappedUserUuid()).isEqualTo(mappedB);
        }
    }

    // ── ToDto ─────────────────────────────────────────────────────────────────

    @Nested
    class ToDto {

        @Test
        void leavesNestedNull_whenNoVaultProfile() {
            // given
            TspProfile profile = new TspProfile();
            profile.setUuid(UUID.randomUUID());
            profile.setName("no-vault");

            // when
            TspProfileDto dto = TspProfileMapper.toDto(profile, List.<ResponseAttribute>of());

            // then
            assertThat(dto.getVaultProfile()).isNull();
        }

        @Test
        void populatesNestedDto_whenVaultProfilePresent() {
            // given
            UUID vaultInstanceUuid = UUID.randomUUID();
            VaultInstance vaultInstance = new VaultInstance();
            vaultInstance.setUuid(vaultInstanceUuid);
            vaultInstance.setName("prod-vault");

            VaultProfile vaultProfile = new VaultProfile();
            vaultProfile.setUuid(UUID.randomUUID());
            vaultProfile.setName("basic-creds");
            vaultProfile.setDescription("creds for prod");
            vaultProfile.setEnabled(true);
            vaultProfile.setVaultInstance(vaultInstance); // also sets vaultInstanceUuid

            TspProfile profile = new TspProfile();
            profile.setUuid(UUID.randomUUID());
            profile.setName("with-vault");
            profile.setVaultProfile(vaultProfile);

            // when
            TspProfileDto dto = TspProfileMapper.toDto(profile, List.<ResponseAttribute>of());

            // then
            VaultProfileDto nested = dto.getVaultProfile();
            assertThat(nested).isNotNull();
            assertThat(nested.getUuid()).isEqualTo(vaultProfile.getUuid().toString());
            assertThat(nested.getName()).isEqualTo("basic-creds");
            assertThat(nested.getDescription()).isEqualTo("creds for prod");
            assertThat(nested.isEnabled()).isTrue();
            assertThat(nested.getVaultInstance()).isNotNull();
            assertThat(nested.getVaultInstance().getUuid()).isEqualTo(vaultInstanceUuid.toString());
            assertThat(nested.getVaultInstance().getName()).isEqualTo("prod-vault");
        }
    }
}
