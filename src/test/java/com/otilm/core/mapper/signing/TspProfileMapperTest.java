package com.otilm.core.mapper.signing;

import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.model.signing.TspProfileModel;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
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
            TspProfileModel model = TspProfileMapper.toModel(profile, customAttributes);

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
            TspProfileModel model = TspProfileMapper.toModel(profile, List.of());

            // then
            assertThat(model.defaultSigningProfileUuid()).isNull();
            assertThat(model.defaultSigningProfileName()).isNull();
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
}
