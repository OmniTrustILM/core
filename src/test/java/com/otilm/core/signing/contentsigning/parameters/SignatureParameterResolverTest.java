package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.CommitmentType;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.core.model.signing.SignatureParameterPolicy;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder.aVisibleSignature;
import static com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder.aPlacement;
import static com.otilm.core.util.builders.ResolvedManagedContentSigningProfileBuilder.aResolvedContentSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignatureParameterResolverTest {

    private static final ValidatorFactory VALIDATOR_FACTORY = Validation.buildDefaultValidatorFactory();

    private final SignatureParameterResolver resolver = new SignatureParameterResolver(
            VALIDATOR_FACTORY.getValidator());

    @AfterAll
    static void closeValidatorFactory() {
        VALIDATOR_FACTORY.close();
    }

    @Test
    void mergesRequestOverDefaults_whenTheGroupIsAllowed() {
        // given — a profile allowing SIGNATURE_CONTEXT with a location default
        var profileLocation = "Prague";
        var requestedReason = "Contract approval";
        PadesSignatureParametersDto defaults = aPadesParameters().withLocation(profileLocation).build();
        PadesSignatureParametersDto requested = aPadesParameters().withReason(requestedReason).build();

        // when
        PadesSignatureParametersDto effective = (PadesSignatureParametersDto) resolver
                .effectiveParameters(requested, profile(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT), defaults));

        // then
        assertThat(effective.getReason()).isEqualTo(requestedReason);
        assertThat(effective.getLocation()).isEqualTo(profileLocation);
    }

    @Test
    void refusesRequest_whenItTouchesANonAllowedGroup() {
        // given
        PadesSignatureParametersDto requested = aPadesParameters()
                .withSignerName("Jane Doe")
                .withReason("Contract approval")
                .build();

        // when / then
        assertThatThrownBy(() -> resolver.effectiveParameters(requested, profile(Set.of(), null)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("signer_identity")
                .hasMessageContaining("signerName")
                .hasMessageContaining("signature_context")
                .hasMessageContaining("reason");
    }

    @Test
    void refusesOnlyTheDeniedGroups_whenSomeAreAllowed() {
        // given
        PadesSignatureParametersDto requested = aPadesParameters()
                .withReason("Contract approval")
                .withSignerName("Jane Doe")
                .withCommitmentType(CommitmentType.PROOF_OF_APPROVAL)
                .build();

        // when / then
        assertThatThrownBy(() -> resolver
                .effectiveParameters(requested, profile(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT), null)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("signer_identity")
                .hasMessageContaining("signed_attributes")
                .hasMessageNotContaining("signature_context");
    }

    /** Reject on presence, not difference: an equal value is still a group the request had no right to speak about. */
    @Test
    void refusesOnPresence_whenTheValueEqualsTheProfiles() {
        // given
        var signerName = "Jane Doe";
        PadesSignatureParametersDto defaults = aPadesParameters().withSignerName(signerName).build();
        PadesSignatureParametersDto requested = aPadesParameters().withSignerName(signerName).build();

        // when / then
        assertThatThrownBy(() -> resolver.effectiveParameters(requested, profile(Set.of(), defaults)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("signer_identity");
    }

    /** The merge is programmatic, so the contract's own caps have to be re-applied to the result. */
    @Test
    void refusesMergedObject_whenItBreachesAContractCap() {
        // given
        PadesSignatureParametersDto defaults = aPadesParameters().withReason("x".repeat(513)).build();

        // when / then
        assertThatThrownBy(() -> resolver.effectiveParameters(null, profile(Set.of(), defaults)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("reason");
    }

    @Test
    void namesTheMissingField_whenTheEffectivePlacementIsIncomplete() {
        // given — a visible signature placed by coordinates, but on no page
        PadesSignatureParametersDto defaults = aPadesParameters()
                .withVisibleSignature(aVisibleSignature()
                        .withVisible(true)
                        .withPlacement(aPlacement().withOriginX(20f).withOriginY(30f).withWidth(180f).withHeight(60f)))
                .build();

        // when / then
        assertThatThrownBy(() -> resolver.effectiveParameters(null, profile(Set.of(), defaults)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("visibleSignature.placement.page");
    }

    @Test
    void namesTheContent_whenTheEffectiveSignatureIsDrawnWithNeitherTextNorImage() {
        // given
        PadesSignatureParametersDto defaults = aPadesParameters()
                .withVisibleSignature(aVisibleSignature()
                        .withVisible(true)
                        .withPlacement(aPlacement()
                                .withPage(1)
                                .withOriginX(20f)
                                .withOriginY(30f)
                                .withWidth(180f)
                                .withHeight(60f)))
                .build();

        // when / then
        assertThatThrownBy(() -> resolver.effectiveParameters(null, profile(Set.of(), defaults)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("visibleSignature.text or visibleSignature.image");
    }

    /**
     * The cascade into {@code visibleSignature.placement} is the whole reason this class holds a {@code Validator}:
     * dropping {@code @Valid} from the contract's {@code visibleSignature} field must break here.
     */
    @Test
    void refusesPlacement_whenTheMergedPlacementUsesTwoAddressingModes() {
        // given — a request placing the signature by coordinates and by an anchor at once
        PadesSignatureParametersDto requested = placedBy(
                aPlacement().withPage(1).withOriginX(20f).withOriginY(30f).withZoom(100f));

        // when / then
        assertThatThrownBy(() -> resolver
                .effectiveParameters(requested,
                        profile(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT), null)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("visibleSignature.placement")
                .hasMessageContaining("one addressing mode only");
    }

    /** The image/MIME pairing is a class-level constraint on the nested visible signature, so it needs the cascade. */
    @Test
    void refusesStampImage_whenItsMediaTypeIsMissing() {
        // given — defaults carrying image bytes nobody can decode
        PadesSignatureParametersDto defaults = aPadesParameters()
                .withVisibleSignature(aVisibleSignature().withImage(new byte[]{1, 2, 3, 4}))
                .build();

        // when / then
        assertThatThrownBy(() -> resolver.effectiveParameters(null, profile(Set.of(), defaults)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("visibleSignature.imageMimeType")
                .hasMessageContaining("must be supplied together");
    }

    /** A named field admits nothing beside itself, so the request's page replaces it and must then stand alone. */
    @Test
    void namesTheFieldsThePageStillNeeds_whenTheRequestAddsAPageToTheProfilesNamedField() {
        // given — the profile places the signature in a named field, and the request sends a page instead
        PadesSignatureParametersDto profileDefaults = placedBy(aPlacement().withFieldId("Signature1"));
        PadesSignatureParametersDto requested = placedBy(aPlacement().withPage(2));

        // when / then
        assertThatThrownBy(() -> resolver
                .effectiveParameters(requested,
                        profile(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT), profileDefaults)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("visibleSignature.placement.originX")
                .hasMessageContaining("visibleSignature.placement.height");
    }

    /** When the request names the field itself, the contract's own violation already points at what it sent. */
    @Test
    void keepsTheContractsOwnViolation_whenTheRequestNamesTheFieldItself() {
        // given
        PadesSignatureParametersDto requested = placedBy(aPlacement().withFieldId("Signature1").withPage(2));

        // when / then
        assertThatThrownBy(() -> resolver
                .effectiveParameters(requested,
                        profile(Set.of(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT), null)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("visibleSignature.placement.fieldId")
                .hasMessageContaining("one addressing mode only");
    }

    @Test
    void returnsNothing_whenThereAreNoDefaultsAndNoRequest() {
        // given — a profile carrying no defaults, and no request

        // when / then
        assertThat(resolver.effectiveParameters(null, profile(Set.of(), null))).isNull();
    }

    @Test
    void returnsNothing_whenTheRequestCarriesOnlyTheFamily() {
        // given — an envelope carrying only the discriminator, on a profile that allows nothing
        PadesSignatureParametersDto requested = aPadesParameters().build();

        // when / then
        assertThat(resolver.effectiveParameters(requested, profile(Set.of(), null))).isNull();
    }

    @Test
    void deniesEveryGroup_whenTheAllowListIsNull() {
        // given
        PadesSignatureParametersDto requested = aPadesParameters().withReason("Contract approval").build();

        // when / then
        assertThatThrownBy(() -> resolver.effectiveParameters(requested, profile(null, null)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("signature_context");
    }

    @Test
    void deniesEveryGroup_whenTheProfileWasNeverConfiguredForParameters() {
        // given
        PadesSignatureParametersDto requested = aPadesParameters().withReason("Contract approval").build();

        // when / then
        assertThatThrownBy(() -> resolver
                .effectiveParameters(requested, aResolvedContentSigningProfile().withParameterPolicy(null).build()))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("signature_context");
    }

    @Test
    void refusesByField_whenAListCarriesANullElement() {
        // given
        PadesSignatureParametersDto defaults = aPadesParameters().withClaimedRoles("Head of Legal").build();
        PadesSignatureParametersDto requested = aPadesParameters().withClaimedRoles("Auditor", null).build();

        // when / then
        assertThatThrownBy(() -> resolver
                .effectiveParameters(requested, profile(Set.of(SignatureParameterGroup.SIGNED_ATTRIBUTES), defaults)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("claimedRoles");
    }

    /** The contract documents an empty list as refused, so it must not be read as "inherit the profile's". */
    @Test
    void refusesEmptyList_whenTheRequestSendsOne() {
        // given
        PadesSignatureParametersDto defaults = aPadesParameters().withClaimedRoles("Head of Legal").build();
        PadesSignatureParametersDto requested = aPadesParameters().withClaimedRoles().build();

        // when / then
        assertThatThrownBy(() -> resolver
                .effectiveParameters(requested, profile(Set.of(SignatureParameterGroup.SIGNED_ATTRIBUTES), defaults)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("claimedRoles");
    }

    /** A family the profile does not sign is a permission answer, so it surfaces as a platform validation error. */
    @Test
    void refusesBeforeTheMerge_whenTheRequestNamesAnotherFamily() {
        // given — an XAdES profile allowing SIGNATURE_CONTEXT, and a PAdES request
        PadesSignatureParametersDto requested = aPadesParameters().withReason("Contract approval").build();

        // when / then
        assertThatThrownBy(() -> resolver
                .effectiveParameters(requested, xadesProfile(Set.of(SignatureParameterGroup.SIGNATURE_CONTEXT))))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("PADES")
                .hasMessageContaining("XADES");
    }

    /** Violations are collected, so a mismatched family does not hide the groups the request also could not touch. */
    @Test
    void reportsFamilyMismatchAlongsideDeniedGroups() {
        // given — a request touching a group the profile denies, on the wrong family
        PadesSignatureParametersDto requested = aPadesParameters().withSignerName("Jane Doe").build();

        // when / then
        assertThatThrownBy(() -> resolver.effectiveParameters(requested, xadesProfile(Set.of())))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("signer_identity")
                .hasMessageContaining("XADES");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static PadesSignatureParametersDto placedBy(PadesVisibleSignaturePlacementDtoBuilder placement) {
        return aPadesParameters().withVisibleSignature(aVisibleSignature().withPlacement(placement)).build();
    }

    /** No XAdES parameters subtype exists yet, so the mismatch is staged from the profile's family side. */
    private static ResolvedManagedContentSigningProfile xadesProfile(Set<SignatureParameterGroup> allowedGroups) {
        return aResolvedContentSigningProfile()
                .withFamily(SignatureFamily.XADES)
                .withParameterPolicy(new SignatureParameterPolicy(allowedGroups, null))
                .build();
    }

    private static ResolvedManagedContentSigningProfile profile(Set<SignatureParameterGroup> allowedGroups,
            SignatureParametersDto defaults) {
        return aResolvedContentSigningProfile()
                .withParameterPolicy(new SignatureParameterPolicy(allowedGroups, defaults))
                .build();
    }
}
