package com.otilm.core.mapper.signing;

import com.otilm.api.model.client.signing.profile.SigningProfileListDto;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.SigningRecordPolicyModel;
import com.otilm.core.model.signing.scheme.ManagedSigning;
import com.otilm.core.model.signing.scheme.OneTimeKeyManagedSigning;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningProfileMapperTest {

    private static final UUID PROFILE_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID TQC_UUID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID FORMATTER_UUID = UUID.fromString("33333333-3333-3333-3333-333333333333");
    private static final UUID CERT_UUID = UUID.fromString("44444444-4444-4444-4444-444444444444");
    private static final UUID RA_UUID = UUID.fromString("55555555-5555-5555-5555-555555555555");
    private static final UUID TOKEN_UUID = UUID.fromString("66666666-6666-6666-6666-666666666666");
    private static final UUID CSR_TEMPLATE_UUID = UUID.fromString("77777777-7777-7777-7777-777777777777");
    private static final UUID TSP_UUID = UUID.fromString("88888888-8888-8888-8888-888888888888");

    // ── ToListDto ───────────────────────────────────────────────────────────────

    @Nested
    class ToListDto {

        @Test
        void returnsTspProtocol_whenProfileHasTspProfile() {
            // given
            SigningProfile header = newListHeader();
            header.setTspProfileUuid(TSP_UUID);

            // when
            SigningProfileListDto dto = SigningProfileMapper.toListDto(header);

            // then
            assertThat(dto.getEnabledProtocols()).containsExactly(SigningProtocol.TSP);
        }

        @Test
        void returnsNoProtocols_whenProfileHasNoTspProfile() {
            // given
            SigningProfile header = newListHeader();
            header.setTspProfileUuid(null);

            // when
            SigningProfileListDto dto = SigningProfileMapper.toListDto(header);

            // then
            assertThat(dto.getEnabledProtocols()).isEmpty();
        }

        @Test
        void populatesSigningScheme() {
            // given
            SigningProfile header = newListHeader();
            header.setSigningScheme(SigningScheme.DELEGATED);

            // when
            SigningProfileListDto dto = SigningProfileMapper.toListDto(header);

            // then
            assertThat(dto.getSigningScheme()).isEqualTo(SigningScheme.DELEGATED);
        }

        private static SigningProfile newListHeader() {
            SigningProfile p = new SigningProfile();
            p.setUuid(PROFILE_UUID);
            p.setName("profile-x");
            p.setDescription("desc");
            p.setEnabled(true);
            p.setLatestVersion(1);
            p.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
            p.setSigningScheme(SigningScheme.MANAGED);
            return p;
        }
    }

    // ── ToManagedTimestampingModel ────────────────────────────────────────────────

    @Nested
    class ToManagedTimestampingModel {

        @Test
        void carriesUuidReferences_whenStaticKey() {
            // given
            SigningProfile header = newHeader();
            SigningProfileVersion version = newTimestampingVersion();
            version.setSigningScheme(SigningScheme.MANAGED);
            version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
            version.setCertificateUuid(CERT_UUID);

            // when
            SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                    SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

            // then
            assertThat(model.uuid()).isEqualTo(PROFILE_UUID);
            assertThat(model.name()).isEqualTo("profile-x");
            assertThat(model.version()).isEqualTo(1);
            assertThat(model.enabled()).isTrue();
            assertThat(model.enabledProtocols()).containsExactly(SigningProtocol.TSP);
            assertThat(model.signingScheme())
                    .isInstanceOfSatisfying(StaticKeyManagedSigning.class,
                            scheme -> assertThat(scheme.certificateUuid()).isEqualTo(CERT_UUID));

            ManagedTimestampingWorkflow wf = model.workflow();
            assertThat(wf.timeQualityConfigurationUuid()).isEqualTo(TQC_UUID);
            assertThat(wf.signatureFormatterConnectorUuid()).isEqualTo(FORMATTER_UUID);
            assertThat(wf.defaultPolicyId()).isEqualTo("1.2.3.4.5");
            assertThat(wf.allowedDigestAlgorithms()).containsExactly(DigestAlgorithm.SHA_256);
            assertThat(wf.isQualifiedTimestamp()).isFalse();
        }

        @Test
        void carriesUuidReferences_whenOneTimeKey() {
            // given
            SigningProfile header = newHeader();
            SigningProfileVersion version = newTimestampingVersion();
            version.setSigningScheme(SigningScheme.MANAGED);
            version.setManagedSigningType(ManagedSigningType.ONE_TIME_KEY);
            version.setRaProfileUuid(RA_UUID);
            version.setTokenProfileUuid(TOKEN_UUID);
            version.setCsrTemplateUuid(CSR_TEMPLATE_UUID);

            // when
            SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                    SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

            // then
            assertThat(model.signingScheme())
                    .isInstanceOfSatisfying(OneTimeKeyManagedSigning.class, scheme -> {
                        assertThat(scheme.raProfileUuid()).isEqualTo(RA_UUID);
                        assertThat(scheme.tokenProfileUuid()).isEqualTo(TOKEN_UUID);
                        assertThat(scheme.csrTemplateUuid()).isEqualTo(CSR_TEMPLATE_UUID);
                    });
        }

        @Test
        void carriesNoEnabledProtocols_whenNoTspProfile() {
            // given
            SigningProfile header = newHeader();
            header.setTspProfileUuid(null);
            SigningProfileVersion version = newTimestampingVersion();
            version.setSigningScheme(SigningScheme.MANAGED);
            version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
            version.setCertificateUuid(CERT_UUID);

            // when
            SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                    SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

            // then
            assertThat(model.enabledProtocols()).isEmpty();
        }

        @Test
        void carriesNullUuid_whenNoTimeQualityConfiguration() {
            // given
            SigningProfile header = newHeader();
            header.setTimeQualityConfigurationUuid(null);
            SigningProfileVersion version = newTimestampingVersion();
            version.setSigningScheme(SigningScheme.MANAGED);
            version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
            version.setCertificateUuid(CERT_UUID);

            // when
            SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                    SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

            // then
            assertThat(model.workflow().timeQualityConfigurationUuid()).isNull();
        }

        @Test
        void carriesAllRecordPolicyFields_fromVersion() {
            // given — distinct values so a transposed field would surface; T/F/T/F/T disambiguates the flags
            var retentionDays = 30;
            var persistenceMode = SigningRecordPersistenceMode.IMMEDIATE;
            SigningProfile header = newHeader();
            SigningProfileVersion version = newTimestampingVersion();
            version.setSigningScheme(SigningScheme.MANAGED);
            version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
            version.setCertificateUuid(CERT_UUID);
            version.setRetentionDays(retentionDays);
            version.setDeleteAfterRetrieval(true);
            version.setPersistenceMode(persistenceMode);
            version.setRecordRequestMetadata(false);
            version.setRecordSignature(true);
            version.setRecordSignedDocument(false);
            version.setRecordDtbs(true);

            // when
            SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                    SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

            // then
            SigningRecordPolicyModel policy = model.recordPolicy();
            assertThat(policy.recordRequestMetadata()).isFalse();
            assertThat(policy.recordSignature()).isTrue();
            assertThat(policy.recordSignedDocument()).isFalse();
            assertThat(policy.recordDtbs()).isTrue();
            assertThat(policy.retentionDays()).isEqualTo(retentionDays);
            assertThat(policy.deleteAfterRetrieval()).isTrue();
            assertThat(policy.persistenceMode()).isEqualTo(persistenceMode);
        }

        @Test
        void carriesNullRetentionDays_whenVersionRetentionDaysNull() {
            // given
            SigningProfile header = newHeader();
            SigningProfileVersion version = newTimestampingVersion();
            version.setSigningScheme(SigningScheme.MANAGED);
            version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
            version.setCertificateUuid(CERT_UUID);
            version.setRetentionDays(null);

            // when
            SigningProfileModel<ManagedTimestampingWorkflow, ManagedSigning> model =
                    SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of());

            // then
            assertThat(model.recordPolicy().retentionDays()).isNull();
        }

        @Test
        void throwsIllegalArgument_whenNonTimestampingWorkflow() {
            // given
            SigningProfile header = newHeader();
            SigningProfileVersion version = newTimestampingVersion();
            version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
            version.setSigningScheme(SigningScheme.MANAGED);
            version.setManagedSigningType(ManagedSigningType.STATIC_KEY);

            // when / then
            assertThatThrownBy(() -> SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of()))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void throwsIllegalArgument_whenDelegatedScheme() {
            // given
            SigningProfile header = newHeader();
            SigningProfileVersion version = newTimestampingVersion();
            version.setSigningScheme(SigningScheme.DELEGATED);

            // when / then
            assertThatThrownBy(() -> SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of()))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void throwsIllegalState_whenManagedWithoutSigningType() {
            // given
            SigningProfile header = newHeader();
            SigningProfileVersion version = newTimestampingVersion();
            version.setSigningScheme(SigningScheme.MANAGED);
            version.setManagedSigningType(null);

            // when / then
            assertThatThrownBy(() -> SigningProfileMapper.toManagedTimestampingModel(header, version, List.of(), List.of()))
                    .isInstanceOf(IllegalStateException.class);
        }

        private static SigningProfile newHeader() {
            SigningProfile p = new SigningProfile();
            p.setUuid(PROFILE_UUID);
            p.setName("profile-x");
            p.setDescription("desc");
            p.setEnabled(true);
            p.setTimeQualityConfigurationUuid(TQC_UUID);
            p.setTspProfileUuid(TSP_UUID);
            return p;
        }

        private static SigningProfileVersion newTimestampingVersion() {
            SigningProfileVersion v = new SigningProfileVersion();
            v.setVersion(1);
            v.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
            v.setSignatureFormatterConnectorUuid(FORMATTER_UUID);
            v.setQualifiedTimestamp(false);
            v.setDefaultPolicyId("1.2.3.4.5");
            v.setAllowedPolicyIds(List.of("1.2.3.4.5"));
            v.setAllowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_256.getCode()));
            v.setValidateTokenSignature(false);
            return v;
        }
    }
}
