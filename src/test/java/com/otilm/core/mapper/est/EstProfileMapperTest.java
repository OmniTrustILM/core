package com.otilm.core.mapper.est;

import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.raprofile.RaProfileEstDetailResponseDto;
import com.otilm.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.est.EstProfileDetailDto;
import com.otilm.api.model.core.est.EstProfileDto;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.util.builders.EstProfileBuilder;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;

class EstProfileMapperTest {

    private static final String ORIGIN = "https://ilm.example.com";
    private static final String EST_PROFILE_NAME = "est-devices";
    private static final String RA_PROFILE_NAME = "devices-ra";
    private static final String DESCRIPTION = "Devices enrolling with vendor certificates";
    private static final UUID EST_PROFILE_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID RA_PROFILE_UUID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID AUTHORITY_UUID = UUID.fromString("33333333-3333-3333-3333-333333333333");

    // ── ToDto ─────────────────────────────────────────────────────────────────

    @Nested
    class ToDto {

        @Test
        void returnsNoUrl_whenProfileHasNoRaProfile() {
            // given
            EstProfile profileWithoutRaProfile = draftEstProfile().build();

            // when
            EstProfileDto dto = EstProfileMapper.toDto(profileWithoutRaProfile, ORIGIN);

            // then
            assertThat(dto.getLabel()).isEqualTo(EST_PROFILE_NAME);
            assertThat(dto.getEstUrl()).isNull();
            assertThat(dto.getRaProfile()).isNull();
        }

        @Test
        void returnsLabelledUrl_whenProfileHasRaProfile() {
            // given
            EstProfile profile = draftEstProfile().withRaProfile(createRaProfile()).build();

            // when
            EstProfileDto dto = EstProfileMapper.toDto(profile, ORIGIN);

            // then
            assertThat(dto.getLabel()).isEqualTo(EST_PROFILE_NAME);
            assertThat(dto.getEstUrl()).isEqualTo("https://ilm.example.com/.well-known/est/est-devices");
            assertThat(dto.getRaProfile()).isNotNull().satisfies(simple -> {
                assertThat(simple.getUuid()).isEqualTo(RA_PROFILE_UUID.toString());
                assertThat(simple.getName()).isEqualTo(RA_PROFILE_NAME);
                assertThat(simple.getEnabled()).isTrue();
                assertThat(simple.getAuthorityInstanceUuid()).isEqualTo(AUTHORITY_UUID.toString());
            });
        }

        @Test
        void copiesProfileSettings() {
            // given
            EstProfile profile = draftEstProfile()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.VENDOR_MTLS)
                    .withSystemDefault(true)
                    .withServerKeyGeneration(true)
                    .withKeyRecovery(false)
                    .build();

            // when
            EstProfileDto dto = EstProfileMapper.toDto(profile, ORIGIN);

            // then
            assertThat(dto.getAuthenticationPolicy()).isEqualTo(EstAuthenticationPolicy.VENDOR_MTLS);
            assertThat(dto.isSystemDefault()).isTrue();
            assertThat(dto.isServerKeyGeneration()).isTrue();
            assertThat(dto.isKeyRecovery()).isFalse();
        }

        @Test
        void copiesKeyRecovery_whenEnabled() {
            // given
            EstProfile profileWithKeyRecovery = draftEstProfile().withKeyRecovery(true).build();

            // when
            EstProfileDto dto = EstProfileMapper.toDto(profileWithKeyRecovery, ORIGIN);

            // then
            assertThat(dto.isKeyRecovery()).isTrue();
        }

        @Test
        void copiesBasicFields() {
            // given
            EstProfile profile = draftEstProfile().build();

            // when
            EstProfileDto dto = EstProfileMapper.toDto(profile, ORIGIN);

            // then
            assertThat(dto.getUuid()).isEqualTo(EST_PROFILE_UUID.toString());
            assertThat(dto.getName()).isEqualTo(EST_PROFILE_NAME);
            assertThat(dto.getDescription()).isEqualTo(DESCRIPTION);
            assertThat(dto.isEnabled()).isTrue();
        }
    }

    // ── ToDetailDto ───────────────────────────────────────────────────────────

    @Nested
    class ToDetailDto {

        @Test
        void copiesRenewalSettings() {
            // given
            var renewalThreshold = 30;
            EstProfile profile = draftEstProfile()
                    .withAllowRenewal(false)
                    .withAllowRekey(true)
                    .withRenewalThreshold(renewalThreshold)
                    .build();

            // when
            EstProfileDetailDto dto = EstProfileMapper.toDetailDto(profile, ORIGIN);

            // then
            assertThat(dto.isAllowRenewal()).isFalse();
            assertThat(dto.isAllowRekey()).isTrue();
            assertThat(dto.getRenewalThreshold()).isEqualTo(renewalThreshold);
        }

        @Test
        void copiesTimings() {
            // given
            var issueWaitTimeout = 3;
            var retryAfter = 7;
            var serverKeyGenerationTimeout = 45;
            EstProfile profile = draftEstProfile()
                    .withIssueWaitTimeout(issueWaitTimeout)
                    .withRetryAfter(retryAfter)
                    .withServerKeyGenerationTimeout(serverKeyGenerationTimeout)
                    .build();

            // when
            EstProfileDetailDto dto = EstProfileMapper.toDetailDto(profile, ORIGIN);

            // then
            assertThat(dto.getIssueWaitTimeout()).isEqualTo(issueWaitTimeout);
            assertThat(dto.getRetryAfter()).isEqualTo(retryAfter);
            assertThat(dto.getServerKeyGenerationTimeout()).isEqualTo(serverKeyGenerationTimeout);
        }

        @Test
        void copiesRekeyRefusal_whenThresholdIsUnset() {
            // given
            EstProfile profile = draftEstProfile()
                    .withAllowRenewal(true)
                    .withAllowRekey(false)
                    .withRenewalThreshold(null)
                    .build();

            // when
            EstProfileDetailDto dto = EstProfileMapper.toDetailDto(profile, ORIGIN);

            // then
            assertThat(dto.isAllowRenewal()).isTrue();
            assertThat(dto.isAllowRekey()).isFalse();
            assertThat(dto.getRenewalThreshold()).isNull();
        }

        @Test
        void carriesListFields() {
            // given
            EstProfile profile = draftEstProfile()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.RA_MTLS)
                    .withRaProfile(createRaProfile())
                    .build();

            // when
            EstProfileDetailDto dto = EstProfileMapper.toDetailDto(profile, ORIGIN);

            // then
            assertThat(dto.getUuid()).isEqualTo(EST_PROFILE_UUID.toString());
            assertThat(dto.getName()).isEqualTo(EST_PROFILE_NAME);
            assertThat(dto.getLabel()).isEqualTo(EST_PROFILE_NAME);
            assertThat(dto.getEstUrl()).isEqualTo("https://ilm.example.com/.well-known/est/est-devices");
            assertThat(dto.getAuthenticationPolicy()).isEqualTo(EstAuthenticationPolicy.RA_MTLS);
            assertThat(dto.getRaProfile())
                    .isNotNull()
                    .extracting(SimplifiedRaProfileDto::getUuid)
                    .isEqualTo(RA_PROFILE_UUID.toString());
        }
    }

    // ── ToRaProfileDetail ─────────────────────────────────────────────────────

    @Nested
    class ToRaProfileDetail {

        @Test
        void returnsNoUrl_whenEstIsNotActivated() {
            // given
            RaProfile raProfileWithoutEst = createRaProfile();

            // when
            RaProfileEstDetailResponseDto dto = EstProfileMapper
                    .toRaProfileDetail(raProfileWithoutEst, List.of(createIssueAttribute()), ORIGIN);

            // then
            assertThat(dto.isEstAvailable()).isFalse();
            assertThat(dto.getEstUrl()).isNull();
            assertThat(dto.getLabel()).isNull();
            assertThat(dto.getIssueCertificateAttributes()).isNull();
        }

        @Test
        void usesRaProfileNameAsLabel_whenEstIsActivated() {
            // given
            RaProfile raProfile = createRaProfile();
            raProfile.setEstProfile(draftEstProfile().build());
            ResponseAttributeV3 issueAttribute = createIssueAttribute();

            // when
            RaProfileEstDetailResponseDto dto = EstProfileMapper
                    .toRaProfileDetail(raProfile, List.of(issueAttribute), ORIGIN);

            // then
            assertThat(dto.isEstAvailable()).isTrue();
            assertThat(dto.getUuid()).isEqualTo(EST_PROFILE_UUID.toString());
            assertThat(dto.getName()).isEqualTo(EST_PROFILE_NAME);
            assertThat(dto.getLabel()).isEqualTo(RA_PROFILE_NAME);
            assertThat(dto.getEstUrl()).isEqualTo("https://ilm.example.com/.well-known/est/devices-ra");
            assertThat(dto.getIssueCertificateAttributes()).containsExactly(issueAttribute);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** The enabled devices profile every test starts from, still open to the overrides its scenario is about. */
    private static EstProfileBuilder draftEstProfile() {
        return anEstProfile()
                .withUuid(EST_PROFILE_UUID)
                .withName(EST_PROFILE_NAME)
                .withDescription(DESCRIPTION)
                .withEnabled(true);
    }

    private static RaProfile createRaProfile() {
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(AUTHORITY_UUID);
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(RA_PROFILE_UUID);
        raProfile.setName(RA_PROFILE_NAME);
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authority);
        return raProfile;
    }

    private static ResponseAttributeV3 createIssueAttribute() {
        ResponseAttributeV3 attribute = new ResponseAttributeV3();
        attribute.setUuid(UUID.fromString("44444444-4444-4444-4444-444444444444"));
        attribute.setName("validity");
        attribute.setLabel("Validity");
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        return attribute;
    }
}
