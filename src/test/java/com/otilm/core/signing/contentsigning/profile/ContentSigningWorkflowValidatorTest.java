package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.InternalTimestampSourceRequestDto;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.signing.contentsigning.declaration.ContentSigningDeclarations;
import com.otilm.core.util.SignatureFamilyFixtures;
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

import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;
import static com.otilm.core.util.builders.SignatureFamilyDeclarationDtoBuilder.aFamilyDeclaration;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ContentSigningWorkflowValidatorTest {

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.SHA256_WITH_RSA;

    @Mock
    SigningProfileVersionRepository versionRepository;

    @Mock
    ContentSigningDeclarations declarations;

    ContentSigningWorkflowValidator validator;

    @BeforeEach
    void createValidator() {
        validator = new ContentSigningWorkflowValidator(versionRepository, declarations);
    }

    @Nested
    class FamilyAndCeiling {

        @Test
        void accepts_whenTheConnectorServesTheFamilyAtItsCeiling() {
            // given: a PAdES connector that reaches TIMESTAMPED, and a compliant TSA profile
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED);
            UUID tsaProfileUuid = UUID.randomUUID();
            stubTimestampingProfile(tsaProfileUuid, SigningRecordPersistenceMode.DEFERRED_DURABLE, true);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, tsaProfileUuid),
                            connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheConnectorDeclaresAFamilyThePlatformDoesNotKnow() {
            // given
            var connectorDefinedFamily = "mrtd";
            Connector connector = connectorDeclaring(connectorDefinedFamily, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(connectorDefinedFamily, SignatureLevel.SIGNED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void rejects_whenTheConnectorDoesNotServeTheProfilesFamily() {
            // given: the connector declares XAdES, the profile is PAdES
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.XADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not declare the pades family");
        }

        @Test
        void rejects_whenMaxLevelIsAboveTheConnectorsDeclaredCeiling() {
            // given: the connector declares PAdES only up to SIGNED
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, tsaProfileUuid),
                            connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("TIMESTAMPED");
        }

        @Test
        void accepts_whenASignedOnlyProfileHasNoTimestampSource() {
            // given: SIGNED embeds no timestamp
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        /** A ceiling the engine cannot execute must not be persisted, however far the connector reaches. */
        @Test
        void rejects_whenTheLongTermCeilingIsOneTheEngineCannotExecute() {
            // given: a connector that declares LONG_TERM
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.LONG_TERM);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.LONG_TERM, tsaProfileUuid),
                            connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("LONG_TERM is not available yet")
                    .hasMessageContaining("TIMESTAMPED");
        }

        @Test
        void rejects_whenLongTermIsAboveTheConnectorsDeclaredCeiling() {
            // given: the connector reaches TIMESTAMPED but not LONG_TERM
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.LONG_TERM, tsaProfileUuid),
                            connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not reach level LONG_TERM");
        }

        @Test
        void rejects_whenTheArchivalCeilingIsOneTheEngineCannotExecute() {
            // given: a connector that declares every level, including ARCHIVAL
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.ARCHIVAL);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.ARCHIVAL, tsaProfileUuid),
                            connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("ARCHIVAL is not available yet");
        }

        @Test
        void rejects_whenArchivalIsAboveTheConnectorsDeclaredCeiling() {
            // given: the connector reaches LONG_TERM but not ARCHIVAL
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.LONG_TERM);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.ARCHIVAL, tsaProfileUuid),
                            connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not reach level ARCHIVAL");
        }

        @Test
        void rejects_whenNoFamilyIsGiven() {
            // given
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(null, SignatureLevel.SIGNED, null), connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("family");
        }

        @Test
        void rejects_whenNoMaxLevelIsGiven() {
            // given
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, null, null), connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("maxLevel");
        }
    }

    // ── FamilyRestrictions ───────────────────────────────────────────────────

    @Nested
    class FamilyRestrictions {

        @Test
        void rejects_whenTheFamilyListsOnlyOtherAlgorithms() {
            // given
            var listedAlgorithm = SignatureAlgorithm.SHA512_WITH_RSA;
            Connector connector = connectorDeclaring(aFamilyDeclaration(SignatureFamilyFixtures.PADES)
                    .withHighestLevel(SignatureLevel.SIGNED)
                    .withSignatureAlgorithms(Set.of(listedAlgorithm))
                    .build());

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(SIGNATURE_ALGORITHM.getCode())
                    .hasMessageContaining(listedAlgorithm.getCode());
        }

        @Test
        void accepts_whenTheFamilyListsTheAlgorithm() {
            // given
            Connector connector = connectorDeclaring(aFamilyDeclaration(SignatureFamilyFixtures.PADES)
                    .withHighestLevel(SignatureLevel.SIGNED)
                    .withSignatureAlgorithms(Set.of(SignatureAlgorithm.SHA512_WITH_RSA, SIGNATURE_ALGORITHM))
                    .build());

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheFamilyListsNoAlgorithms() {
            // given — the declaration leaves signatureAlgorithms absent
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }
    }

    @Nested
    class TimestampSourceCoherence {

        @Test
        void rejects_whenNoTimestampSourceIsGivenFromTimestampedUpwards() {
            // given
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("timestamp source is required");
        }

        @Test
        void refuses_whenASignedOnlyProfileNamesATimestampSource() {
            // given
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, UUID.randomUUID()),
                            connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("embeds no timestamp");
        }
    }

    @Nested
    class ReferencedTimestampingProfile {

        @Test
        void refuses_whenTheReferencedProfileIsNotTimestamping() {
            // given
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            SigningProfileVersion version = timestampingVersion(SigningRecordPersistenceMode.IMMEDIATE, true);
            version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.of(version));

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("TIMESTAMPING");
        }

        @Test
        void refuses_whenTheReferencedProfileIsNotManaged() {
            // given: a delegated signer is not an ILM-managed TSA
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            SigningProfileVersion version = timestampingVersion(SigningRecordPersistenceMode.DEFERRED_DURABLE, true);
            version.setSigningScheme(SigningScheme.DELEGATED);
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.of(version));

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("not ILM-managed");
        }

        @Test
        void refuses_whenTheReferencedProfileIsBelowTheRecordFloor() {
            // given
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            stubTimestampingProfile(referenced, SigningRecordPersistenceMode.BEST_EFFORT, true);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("BEST_EFFORT");
        }

        @Test
        void refuses_whenTheReferencedProfileIsNotStaticKeyManaged() {
            // given: a one-time-key TSA profile, which the scheme resolver cannot resolve
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            SigningProfileVersion version = timestampingVersion(SigningRecordPersistenceMode.DEFERRED_DURABLE, true);
            version.setManagedSigningType(ManagedSigningType.ONE_TIME_KEY);
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.of(version));

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("ONE_TIME_KEY");
        }

        @Test
        void refuses_whenTheProfileNamesItselfAsItsTimestampSource() {
            // given: an edit that repoints the profile's timestamp source at the profile being written
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED);
            UUID targetProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, targetProfileUuid),
                            connector, SIGNATURE_ALGORITHM, targetProfileUuid);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("cannot name itself");
        }

        @Test
        void refuses_whenTheReferencedProfileDoesNotExist() {
            // given
            Connector connector = connectorDeclaring(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.empty());

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("does not exist");
        }
    }

    private static ContentSigningWorkflowRequestDto request(String family, SignatureLevel maxLevel,
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

    private Connector connectorDeclaring(String family, SignatureLevel highestLevel) {
        return connectorDeclaring(aFamilyDeclaration(family).withHighestLevel(highestLevel).build());
    }

    /** The stub is lenient. Some tests refuse the workflow before it consults the connector's declaration. */
    private Connector connectorDeclaring(SignatureFamilyDeclarationDto declared) {
        Connector connector = aConnector().build();
        lenient().when(declarations.family(connector.getUuid(), declared.getCode())).thenReturn(Optional.of(declared));
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
