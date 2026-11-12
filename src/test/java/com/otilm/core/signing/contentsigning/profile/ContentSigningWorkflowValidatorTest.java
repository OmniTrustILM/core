package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.InternalTimestampSourceRequestDto;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.signing.contentsigning.declaration.ContentSigningDeclarations;
import com.otilm.core.signing.contentsigning.parameters.PadesVisibleSignatureCompleteness;
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

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder.aVisibleSignature;
import static com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder.aPlacement;
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
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED);
            UUID tsaProfileUuid = UUID.randomUUID();
            stubTimestampingProfile(tsaProfileUuid, SigningRecordPersistenceMode.DEFERRED_DURABLE, true);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, tsaProfileUuid), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheConnectorDeclaresAFamilyThePlatformDoesNotKnow() {
            // given
            var connectorDefinedFamily = new SignatureFamily("mrtd");
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
            Connector connector = connectorDeclaring(SignatureFamily.XADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not declare the pades family");
        }

        @Test
        void rejects_whenMaxLevelIsAboveTheConnectorsDeclaredCeiling() {
            // given: the connector declares PAdES only up to SIGNED
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, tsaProfileUuid), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("TIMESTAMPED");
        }

        @Test
        void accepts_whenASignedOnlyProfileHasNoTimestampSource() {
            // given: SIGNED embeds no timestamp
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        /** A ceiling the engine cannot execute must not be persisted, however far the connector reaches. */
        @Test
        void rejects_whenTheLongTermCeilingIsOneTheEngineCannotExecute() {
            // given: a connector that declares LONG_TERM
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.LONG_TERM);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.LONG_TERM, tsaProfileUuid), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("LONG_TERM is not available yet")
                    .hasMessageContaining("TIMESTAMPED");
        }

        @Test
        void rejects_whenLongTermIsAboveTheConnectorsDeclaredCeiling() {
            // given: the connector reaches TIMESTAMPED but not LONG_TERM
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.LONG_TERM, tsaProfileUuid), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not reach level LONG_TERM");
        }

        @Test
        void rejects_whenTheArchivalCeilingIsOneTheEngineCannotExecute() {
            // given: a connector that declares every level, including ARCHIVAL
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.ARCHIVAL);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.ARCHIVAL, tsaProfileUuid), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("ARCHIVAL is not available yet");
        }

        @Test
        void rejects_whenArchivalIsAboveTheConnectorsDeclaredCeiling() {
            // given: the connector reaches LONG_TERM but not ARCHIVAL
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.LONG_TERM);
            UUID tsaProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.ARCHIVAL, tsaProfileUuid), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not reach level ARCHIVAL");
        }

        @Test
        void rejects_whenNoFamilyIsGiven() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(null, SignatureLevel.SIGNED, null), connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("family");
        }

        @Test
        void rejects_whenNoMaxLevelIsGiven() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, null, null), connector, SIGNATURE_ALGORITHM, null);

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
            Connector connector = connectorDeclaring(aFamilyDeclaration(SignatureFamily.PADES)
                    .withHighestLevel(SignatureLevel.SIGNED)
                    .withSignatureAlgorithms(Set.of(listedAlgorithm))
                    .build());

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, null), connector,
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
            Connector connector = connectorDeclaring(aFamilyDeclaration(SignatureFamily.PADES)
                    .withHighestLevel(SignatureLevel.SIGNED)
                    .withSignatureAlgorithms(Set.of(SignatureAlgorithm.SHA512_WITH_RSA, SIGNATURE_ALGORITHM))
                    .build());

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheFamilyListsNoAlgorithms() {
            // given — the declaration leaves signatureAlgorithms absent
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, null), connector,
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
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, null), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("timestamp source is required");
        }

        @Test
        void refuses_whenASignedOnlyProfileNamesATimestampSource() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, UUID.randomUUID()), connector,
                            SIGNATURE_ALGORITHM, null);

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
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            SigningProfileVersion version = timestampingVersion(SigningRecordPersistenceMode.IMMEDIATE, true);
            version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.of(version));

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("TIMESTAMPING");
        }

        @Test
        void refuses_whenTheReferencedProfileIsNotManaged() {
            // given: a delegated signer is not an ILM-managed TSA
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            SigningProfileVersion version = timestampingVersion(SigningRecordPersistenceMode.DEFERRED_DURABLE, true);
            version.setSigningScheme(SigningScheme.DELEGATED);
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.of(version));

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("not ILM-managed");
        }

        @Test
        void refuses_whenTheReferencedProfileIsBelowTheRecordFloor() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            stubTimestampingProfile(referenced, SigningRecordPersistenceMode.BEST_EFFORT, true);

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("BEST_EFFORT");
        }

        @Test
        void refuses_whenTheReferencedProfileIsNotStaticKeyManaged() {
            // given: a one-time-key TSA profile, which the scheme resolver cannot resolve
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            SigningProfileVersion version = timestampingVersion(SigningRecordPersistenceMode.DEFERRED_DURABLE, true);
            version.setManagedSigningType(ManagedSigningType.ONE_TIME_KEY);
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.of(version));

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("ONE_TIME_KEY");
        }

        @Test
        void refuses_whenTheProfileNamesItselfAsItsTimestampSource() {
            // given: an edit that repoints the profile's timestamp source at the profile being written
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED);
            UUID targetProfileUuid = UUID.randomUUID();

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, targetProfileUuid), connector,
                            SIGNATURE_ALGORITHM, targetProfileUuid);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("cannot name itself");
        }

        @Test
        void refuses_whenTheReferencedProfileDoesNotExist() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED);
            UUID referenced = UUID.randomUUID();
            when(versionRepository.findLatestByProfileUuid(referenced)).thenReturn(Optional.empty());

            // when
            ThrowingCallable validate = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, referenced), connector,
                            SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("does not exist");
        }
    }

    @Nested
    class SignatureParameters {

        @Test
        void accepts_whenTheAllowListGroupsApplyToTheFamily() {
            // given: PAdES groups on a PAdES profile
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void deniesAll_whenTheAllowedGroupsFieldIsNull() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            request.setAllowedRequestParameterGroups(null);

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void refuses_whenAGroupDoesNotApplyToTheFamily() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.XADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.XADES, SignatureLevel.SIGNED, null);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("signature_context")
                    .hasMessageContaining("xades");
        }

        @Test
        void refuses_whenTheDefaultsFamilyContradictsTheWorkflow() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.XADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.XADES, SignatureLevel.SIGNED, null);
            request.setDefaultSignatureParameters(aPadesParameters().build());

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("pades")
                    .hasMessageContaining("xades");
        }

        @Test
        void refuses_whenNoAllowedGroupCanCompleteTheVisiblePlacement() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(
                            aVisibleSignature().withVisible(true).withPlacement(aPlacement().withOriginX(20f)))
                    .build();
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visibleSignature.placement.page")
                    .hasMessageContaining("visible_signature_placement");
        }

        /**
         * {@link PadesVisibleSignatureCompleteness} checks a placement that is present whatever {@code visible} says.
         */
        @Test
        void refuses_whenNoAllowedGroupCanCompleteThePlacementAndVisibleIsAbsent() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setVisible(null);
            defaults.getVisibleSignature().getPlacement().setPage(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visibleSignature.placement.page")
                    .hasMessageContaining("visible_signature_placement");
        }

        @Test
        void refuses_whenARequestCouldOnlyCompleteThePlacementBySwitchingTheSignatureOff() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setVisible(null);
            defaults.getVisibleSignature().getPlacement().setPage(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_CONTENT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visibleSignature.placement.page")
                    .hasMessageContaining("visible_signature_placement");
        }

        /** An explicit {@code visible = false} takes the whole container out at merge, so nothing can be incomplete. */
        @Test
        void accepts_whenTheDefaultTurnsTheSignatureOff() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setVisible(false);
            defaults.getVisibleSignature().getPlacement().setPage(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheDefaultHasNeitherTextNorImageAndVisibleIsAbsent() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setVisible(null);
            defaults.getVisibleSignature().setText(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        /**
         * An allow-listed placement group lets a request finish the placement; the default supplies its own content,
         * which placement forgiveness does not cover.
         */
        @Test
        void accepts_whenTheCompletingGroupIsAllowed() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature()
                            .withVisible(true)
                            .withText("Signed by Operator")
                            .withPlacement(aPlacement().withOriginX(20f)))
                    .build();
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void refuses_whenThePlacementIsForgivenButTheContentCannotBeSupplied() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(
                            aVisibleSignature().withVisible(true).withPlacement(aPlacement().withOriginX(20f)))
                    .build();
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visible_signature_content");
        }

        /** A complete default needs no allow-listed group at all: it is an operator-fixed placement. */
        @Test
        void accepts_whenACompleteVisibleDefaultHasNoAllowedGroup() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            request.setDefaultSignatureParameters(completeVisibleDefaults());

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void reportsEveryInapplicableGroupTogether() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.XADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.XADES, SignatureLevel.SIGNED, null);
            request
                    .setAllowedRequestParameterGroups(
                            Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT, SignatureParameterGroup.SIGNER_IDENTITY));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("signature_context")
                    .hasMessageContaining("signer_identity");
        }

        /** No request could ever supply the missing content, so the default is unsatisfiable. */
        @Test
        void refuses_whenTheDefaultHasNoContentAndTheContentGroupIsNotAllowed() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setText(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visible_signature_content");
        }

        @Test
        void accepts_whenTheDefaultHasNoContentAndTheContentGroupIsAllowed() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setText(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_CONTENT));

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheDefaultSuppliesAnImageInsteadOfText() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setText(null);
            defaults.getVisibleSignature().setImage(new byte[]{1, 2, 3});
            defaults.getVisibleSignature().setImageMimeType("image/png");
            request.setDefaultSignatureParameters(defaults);

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheVisibleSignatureIsExplicitlyDisabled() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withVisible(false))
                    .build();
            request.setDefaultSignatureParameters(defaults);

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        /** An empty placement is pruned at merge, so it cannot make an otherwise complete default unsatisfiable. */
        @Test
        void accepts_whenTheDefaultCarriesAnEmptyPlacement() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withReason("Contract approval")
                    .withVisibleSignature(aVisibleSignature().withPlacement(aPlacement()))
                    .build();
            request.setDefaultSignatureParameters(defaults);

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatCode(validate).doesNotThrowAnyException();
        }

        @Test
        void reportsEveryUnsatisfiableGroupTogether() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withVisible(true))
                    .build();
            request.setDefaultSignatureParameters(defaults);

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visible_signature_placement")
                    .hasMessageContaining("visible_signature_content");
        }

        /** The placement message pluralizes correctly: a single missing field reads "field", not "fields". */
        @Test
        void namesTheSingleMissingField_whenExactlyOnePlacementFieldIsMissing() {
            // given
            Connector connector = connectorDeclaring(SignatureFamily.PADES, SignatureLevel.SIGNED);
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().getPlacement().setPage(null);
            request.setDefaultSignatureParameters(defaults);

            // when
            ThrowingCallable validate = () -> validator.validate(request, connector, SIGNATURE_ALGORITHM, null);

            // then
            assertThatThrownBy(validate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("field visibleSignature.placement.page")
                    .hasMessageNotContaining("fields visibleSignature");
        }

        private static PadesSignatureParametersDto completeVisibleDefaults() {
            return aPadesParameters()
                    .withVisibleSignature(aVisibleSignature()
                            .withVisible(true)
                            .withText("Signed by Operator")
                            .withPlacement(aPlacement()
                                    .withPage(1)
                                    .withOriginX(10f)
                                    .withOriginY(10f)
                                    .withWidth(100f)
                                    .withHeight(50f)))
                    .build();
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

    private Connector connectorDeclaring(SignatureFamily family, SignatureLevel highestLevel) {
        return connectorDeclaring(aFamilyDeclaration(family).withHighestLevel(highestLevel).build());
    }

    /** The stub is lenient. Some tests refuse the workflow before it consults the connector's declaration. */
    private Connector connectorDeclaring(SignatureFamilyDeclarationDto declared) {
        Connector connector = new Connector();
        connector.setUuid(UUID.randomUUID());
        connector.setName("formatting");
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
