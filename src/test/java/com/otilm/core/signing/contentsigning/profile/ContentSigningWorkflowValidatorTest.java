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
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.signing.contentsigning.parameters.PadesVisibleSignatureCompleteness;
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

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder.aVisibleSignature;
import static com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder.aPlacement;
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
        void accepts_whenTheConnectorServesTheFamilyAtItsCeiling() {
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
        void rejects_whenTheConnectorDoesNotServeTheProfilesFamily() {
            // given: the flag sits on the XAdES interface, the profile is PAdES
            Connector connector = connectorWith(ConnectorInterface.XADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ThrowingCallable call = () -> validator
                    .validate(request(SignatureFamily.PADES, SignatureLevel.SIGNED, null), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("PAdES Formatting");
        }

        @Test
        void rejects_whenMaxLevelIsAboveTheConnectorsDeclaredCeiling() {
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
        void accepts_whenASignedOnlyProfileHasNoTimestampSource() {
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
        void rejects_whenTheLongTermCeilingIsOneTheEngineCannotExecute() {
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
        void rejects_whenLongTermIsAboveTheConnectorsDeclaredCeiling() {
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
        void rejects_whenTheArchivalCeilingIsOneTheEngineCannotExecute() {
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
        void rejects_whenArchivalIsAboveTheConnectorsDeclaredCeiling() {
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
        void rejects_whenNoFamilyIsGiven() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ThrowingCallable call = () -> validator
                    .validate(request(null, SignatureLevel.SIGNED, null), connector, null);

            // when / then
            assertThatThrownBy(call).isInstanceOf(ValidationException.class).hasMessageContaining("family");
        }

        @Test
        void rejects_whenNoMaxLevelIsGiven() {
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
        void rejects_whenNoTimestampSourceIsGivenFromTimestampedUpwards() {
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
        void refuses_whenASignedOnlyProfileNamesATimestampSource() {
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
        void refuses_whenTheReferencedProfileIsNotTimestamping() {
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
        void refuses_whenTheReferencedProfileIsNotManaged() {
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
        void refuses_whenTheReferencedProfileIsBelowTheRecordFloor() {
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
        void refuses_whenTheReferencedProfileIsNotStaticKeyManaged() {
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
        void refuses_whenTheProfileNamesItselfAsItsTimestampSource() {
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
        void refuses_whenTheReferencedProfileDoesNotExist() {
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

    @Nested
    class SignatureParameters {

        @Test
        void accepts_whenTheAllowListGroupsApplyToTheFamily() {
            // given: PAdES groups on a PAdES profile
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        @Test
        void deniesAll_whenTheAllowedGroupsFieldIsNull() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            request.setAllowedRequestParameterGroups(null);

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        @Test
        void refuses_whenAGroupDoesNotApplyToTheFamily() {
            // given
            Connector connector = connectorWith(ConnectorInterface.XADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.XADES, SignatureLevel.SIGNED, null);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("signature_context")
                    .hasMessageContaining("XADES");
        }

        @Test
        void refuses_whenTheDefaultsFamilyContradictsTheWorkflow() {
            // given
            Connector connector = connectorWith(ConnectorInterface.XADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.XADES, SignatureLevel.SIGNED, null);
            request.setDefaultSignatureParameters(aPadesParameters().build());

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("PADES")
                    .hasMessageContaining("XADES");
        }

        @Test
        void refuses_whenNoAllowedGroupCanCompleteTheVisiblePlacement() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(
                            aVisibleSignature().withVisible(true).withPlacement(aPlacement().withOriginX(20f)))
                    .build();
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
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
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setVisible(null);
            defaults.getVisibleSignature().getPlacement().setPage(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visibleSignature.placement.page")
                    .hasMessageContaining("visible_signature_placement");
        }

        @Test
        void refuses_whenARequestCouldOnlyCompleteThePlacementBySwitchingTheSignatureOff() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setVisible(null);
            defaults.getVisibleSignature().getPlacement().setPage(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_CONTENT));

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visibleSignature.placement.page")
                    .hasMessageContaining("visible_signature_placement");
        }

        /** An explicit {@code visible = false} takes the whole container out at merge, so nothing can be incomplete. */
        @Test
        void accepts_whenTheDefaultTurnsTheSignatureOff() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setVisible(false);
            defaults.getVisibleSignature().getPlacement().setPage(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheDefaultHasNeitherTextNorImageAndVisibleIsAbsent() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setVisible(null);
            defaults.getVisibleSignature().setText(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT));

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        /**
         * An allow-listed placement group lets a request finish the placement; the default supplies its own content,
         * which placement forgiveness does not cover.
         */
        @Test
        void accepts_whenTheCompletingGroupIsAllowed() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature()
                            .withVisible(true)
                            .withText("Signed by Operator")
                            .withPlacement(aPlacement().withOriginX(20f)))
                    .build();
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT));

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        @Test
        void refuses_whenThePlacementIsForgivenButTheContentCannotBeSupplied() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(
                            aVisibleSignature().withVisible(true).withPlacement(aPlacement().withOriginX(20f)))
                    .build();
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT));

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visible_signature_content");
        }

        /** A complete default needs no allow-listed group at all: it is an operator-fixed placement. */
        @Test
        void accepts_whenACompleteVisibleDefaultHasNoAllowedGroup() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            request.setDefaultSignatureParameters(completeVisibleDefaults());

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        @Test
        void reportsEveryInapplicableGroupTogether() {
            // given
            Connector connector = connectorWith(ConnectorInterface.XADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.XADES, SignatureLevel.SIGNED, null);
            request
                    .setAllowedRequestParameterGroups(
                            Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT, SignatureParameterGroup.SIGNER_IDENTITY));

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("signature_context")
                    .hasMessageContaining("signer_identity");
        }

        /** No request could ever supply the missing content, so the default is unsatisfiable. */
        @Test
        void refuses_whenTheDefaultHasNoContentAndTheContentGroupIsNotAllowed() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setText(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT));

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visible_signature_content");
        }

        @Test
        void accepts_whenTheDefaultHasNoContentAndTheContentGroupIsAllowed() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setText(null);
            request.setDefaultSignatureParameters(defaults);
            request.setAllowedRequestParameterGroups(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_CONTENT));

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheDefaultSuppliesAnImageInsteadOfText() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().setText(null);
            defaults.getVisibleSignature().setImage(new byte[]{1, 2, 3});
            defaults.getVisibleSignature().setImageMimeType("image/png");
            request.setDefaultSignatureParameters(defaults);

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        @Test
        void accepts_whenTheVisibleSignatureIsExplicitlyDisabled() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withVisible(false))
                    .build();
            request.setDefaultSignatureParameters(defaults);

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        /** An empty placement is pruned at merge, so it cannot make an otherwise complete default unsatisfiable. */
        @Test
        void accepts_whenTheDefaultCarriesAnEmptyPlacement() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withReason("Contract approval")
                    .withVisibleSignature(aVisibleSignature().withPlacement(aPlacement()))
                    .build();
            request.setDefaultSignatureParameters(defaults);

            // when / then
            assertThatCode(() -> validator.validate(request, connector, null)).doesNotThrowAnyException();
        }

        @Test
        void reportsEveryUnsatisfiableGroupTogether() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withVisible(true))
                    .build();
            request.setDefaultSignatureParameters(defaults);

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("visible_signature_placement")
                    .hasMessageContaining("visible_signature_content");
        }

        /** The placement message pluralizes correctly: a single missing field reads "field", not "fields". */
        @Test
        void namesTheSingleMissingField_whenExactlyOnePlacementFieldIsMissing() {
            // given
            Connector connector = connectorWith(ConnectorInterface.PADES_FORMATTING,
                    Set.of(FeatureFlag.CONTENT_SIGNING));
            ContentSigningWorkflowRequestDto request = request(SignatureFamily.PADES, SignatureLevel.SIGNED, null);
            PadesSignatureParametersDto defaults = completeVisibleDefaults();
            defaults.getVisibleSignature().getPlacement().setPage(null);
            request.setDefaultSignatureParameters(defaults);

            // when / then
            assertThatThrownBy(() -> validator.validate(request, connector, null))
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
