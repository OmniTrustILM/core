package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.InternalTimestampSourceRequestDto;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ContentSigningWorkflowValidatorTest {

    @Mock
    SigningProfileVersionRepository versionRepository;

    ContentSigningWorkflowValidator validator;

    @BeforeEach
    void createValidator() {
        validator = new ContentSigningWorkflowValidator(versionRepository);
    }

    @Nested
    class FamilyAndCeiling {

        @Test
        void acceptsAProfileWhoseConnectorServesItsFamilyAtItsCeiling() {
            // given: a PAdES connector that reaches TIMESTAMPED, and a compliant TSA profile
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
            UUID tsaProfileUuid = UUID.randomUUID();
            stubTimestampingProfile(tsaProfileUuid, SigningRecordPersistenceMode.DEFERRED_DURABLE, true);
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, tsaProfileUuid), connector,
                            null);

            // when / then
            assertThatCode(call).doesNotThrowAnyException();
        }

        @Test
        void rejectsAConnectorThatDoesNotServeTheProfilesFamily() {
            // given: the flag sits on the XAdES interface, the profile is PAdES
            Connector connector = connectorWith(ConnectorInterface.XADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, null), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("PAdES Formatting");
        }

        @Test
        void rejectsAMaxLevelAboveTheConnectorsDeclaredCeiling() {
            // given: the connector serves PAdES but declares no LEVEL_TIMESTAMPED
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            UUID tsaProfileUuid = UUID.randomUUID();
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, tsaProfileUuid), connector,
                            null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("TIMESTAMPED");
        }

        @Test
        void acceptsASignedOnlyProfileWithNoTimestampSource() {
            // given: SIGNED needs no rung flag beyond contentSigning itself, and embeds no timestamp
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, null), connector, null);

            // when / then
            assertThatCode(call).doesNotThrowAnyException();
        }

        /** A ceiling the engine cannot execute must not be persisted, however far the connector reaches. */
        @Test
        void rejectsALongTermCeilingTheEngineCannotExecute() {
            // given: a connector that does declare LEVEL_LONG_TERM
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED, FeatureFlag.LEVEL_LONG_TERM));
            UUID tsaProfileUuid = UUID.randomUUID();
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.LONG_TERM, tsaProfileUuid), connector,
                            null);

            // when / then
            assertThatThrownBy(call)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("LONG_TERM is not available yet")
                    .hasMessageContaining("TIMESTAMPED");
        }

        @Test
        void rejectsMaxLevelLongTermAboveTheConnectorsDeclaredCeiling() {
            // given: the connector reaches TIMESTAMPED but not LEVEL_LONG_TERM
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
            UUID tsaProfileUuid = UUID.randomUUID();
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.LONG_TERM, tsaProfileUuid), connector,
                            null);

            // when / then
            assertThatThrownBy(call)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not reach level LONG_TERM");
        }

        @Test
        void rejectsAnArchivalCeilingTheEngineCannotExecute() {
            // given: a connector that declares every rung, including LEVEL_ARCHIVAL
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set
                            .of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED, FeatureFlag.LEVEL_LONG_TERM,
                                    FeatureFlag.LEVEL_ARCHIVAL));
            UUID tsaProfileUuid = UUID.randomUUID();
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.ARCHIVAL, tsaProfileUuid), connector, null);

            // when / then
            assertThatThrownBy(call)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("ARCHIVAL is not available yet");
        }

        @Test
        void rejectsMaxLevelArchivalAboveTheConnectorsDeclaredCeiling() {
            // given: the connector reaches LONG_TERM but not LEVEL_ARCHIVAL
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED, FeatureFlag.LEVEL_LONG_TERM));
            UUID tsaProfileUuid = UUID.randomUUID();
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.ARCHIVAL, tsaProfileUuid), connector, null);

            // when / then
            assertThatThrownBy(call)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not reach level ARCHIVAL");
        }

        @Test
        void requiresAFamily() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ThrowingCallable call = () -> validator
                    .validate(request(null, SignatureLevel.SIGNED, null), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("family");
        }

        @Test
        void requiresAMaxLevel() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, null, null), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("maxLevel");
        }
    }

    @Nested
    class TimestampSourceCoherence {

        @Test
        void requiresATimestampSourceFromTimestampedUpwards() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, null), connector, null);

            // when / then
            assertThatThrownBy(call)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("timestamp source is required");
        }

        @Test
        void refusesATimestampSourceOnASignedOnlyProfile() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, UUID.randomUUID()), connector,
                            null);

            // when / then
            assertThatThrownBy(call)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("embeds no timestamp");
        }
    }

    @Nested
    class ReferencedTimestampingProfile {

        @Test
        void refusesAReferencedProfileThatIsNotTimestamping() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
            UUID referenced = UUID.randomUUID();
            SigningProfileVersion version = timestampingVersion(SigningRecordPersistenceMode.IMMEDIATE, true);
            version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.of(version));
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("TIMESTAMPING");
        }

        @Test
        void refusesAReferencedProfileThatIsNotManaged() {
            // given: a delegated signer is not an ILM-managed TSA
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
            UUID referenced = UUID.randomUUID();
            SigningProfileVersion version = timestampingVersion(SigningRecordPersistenceMode.DEFERRED_DURABLE, true);
            version.setSigningScheme(SigningScheme.DELEGATED);
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.of(version));
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("not ILM-managed");
        }

        @Test
        void refusesAReferencedProfileBelowTheRecordFloor() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
            UUID referenced = UUID.randomUUID();
            stubTimestampingProfile(referenced, SigningRecordPersistenceMode.BEST_EFFORT, true);
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("BEST_EFFORT");
        }

        @Test
        void refusesAReferencedProfileThatIsNotStaticKeyManaged() {
            // given: a one-time-key TSA profile, which the scheme resolver cannot resolve
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
            UUID referenced = UUID.randomUUID();
            SigningProfileVersion version = timestampingVersion(SigningRecordPersistenceMode.DEFERRED_DURABLE, true);
            version.setManagedSigningType(ManagedSigningType.ONE_TIME_KEY);
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.of(version));
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("ONE_TIME_KEY");
        }

        @Test
        void refusesAProfileThatNamesItselfAsItsTimestampSource() {
            // given: an edit that repoints the profile's timestamp source at the profile being written
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
            UUID targetProfileUuid = UUID.randomUUID();
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, targetProfileUuid), connector,
                            targetProfileUuid);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("cannot name itself");
        }

        @Test
        void refusesAReferencedProfileThatDoesNotExist() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.LEVEL_TIMESTAMPED));
            UUID referenced = UUID.randomUUID();
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.empty());
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("does not exist");
        }
    }

    private static ContentSigningWorkflowRequestDto request(SignatureFamily family, SignatureLevel maxLevel,
            UUID timestampSourceUuid) {
        ContentSigningWorkflowRequestDto dto = new ContentSigningWorkflowRequestDto();
        dto.setSignatureFormattingConnectorUuid(UUID.randomUUID());
        dto.setFamily(family);
        dto.setMaxLevel(maxLevel);
        if (timestampSourceUuid != null) {
            dto.setTimestampSource(new InternalTimestampSourceRequestDto(timestampSourceUuid));
        }
        return dto;
    }

    private static Connector connectorWith(ConnectorInterface interfaceCode, Set<FeatureFlag> features) {
        Connector connector = new Connector();
        connector.setName("formatting");
        ConnectorInterfaceEntity entity = new ConnectorInterfaceEntity();
        entity.setInterfaceCode(interfaceCode);
        entity.setFeatures(List.copyOf(features));
        connector.setInterfaces(Set.of(entity));
        return connector;
    }

    private void stubTimestampingProfile(UUID profileUuid, SigningRecordPersistenceMode mode, boolean recording) {
        when(versionRepository.findLatestByProfileUuid(profileUuid))
                .thenReturn(Optional.of(timestampingVersion(mode, recording)));
    }

    private static SigningProfileVersion timestampingVersion(SigningRecordPersistenceMode mode, boolean recording) {
        SigningProfileVersion version = new SigningProfileVersion();
        version.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setPersistenceMode(mode);
        version.setRecordingEnabled(recording);
        return version;
    }
}
