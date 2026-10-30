package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder.aVisibleSignature;
import static com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder.aPlacement;
import static com.otilm.core.util.builders.PadesVisibleSignatureStyleDtoBuilder.aStyle;
import static org.assertj.core.api.Assertions.assertThat;

class RequestParameterGroupsTest {

    @Test
    void presentsNoGroup_whenTheObjectIsEmpty() {
        // given — parameters with nothing set
        PadesSignatureParametersDto parameters = aPadesParameters().build();

        // when / then
        assertThat(RequestParameterGroups.presentFieldsByGroup(parameters)).isEmpty();
    }

    @Test
    void presentsNoGroup_whenTheObjectIsAbsent() {
        // given — no parameters at all

        // when / then
        assertThat(RequestParameterGroups.presentFieldsByGroup(null)).isEmpty();
    }

    @Test
    void presentsItsOwnGroupOnly_whenAScalarFieldIsSet() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters().withReason("Contract approval").build();

        // when / then
        assertThat(RequestParameterGroups.presentFieldsByGroup(parameters))
                .containsOnlyKeys(SignatureParameterGroup.SIGNATURE_CONTEXT)
                .containsEntry(SignatureParameterGroup.SIGNATURE_CONTEXT, List.of("reason"));
    }

    /** Nesting is a readability device, so a nested field keeps the group its own declaration names. */
    @Test
    void reportsTheGroupUnderItsDottedPath_whenTheFieldIsNested() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters()
                .withVisibleSignature(aVisibleSignature()
                        .withVisible(true)
                        .withPlacement(aPlacement().withPage(2))
                        .withStyle(aStyle().withDpi(300)))
                .build();

        // when / then
        assertThat(RequestParameterGroups.presentFieldsByGroup(parameters))
                .containsEntry(SignatureParameterGroup.VISIBLE_SIGNATURE_CONTENT, List.of("visibleSignature.visible"))
                .containsEntry(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT,
                        List.of("visibleSignature.placement.page"))
                .containsEntry(SignatureParameterGroup.VISIBLE_SIGNATURE_STYLE, List.of("visibleSignature.style.dpi"));
    }

    /** A container is a readability device, not a parameter, so it carries no group of its own. */
    @Test
    void presentsNoGroup_whenTheContainerIsEmpty() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters().withVisibleSignature(aVisibleSignature()).build();

        // when / then
        assertThat(RequestParameterGroups.presentFieldsByGroup(parameters)).isEmpty();
    }

    /** The discriminator is not a parameter, so setting it explicitly must never make a group look present. */
    @Test
    void presentsNoGroup_whenOnlyTheFamilyDiscriminatorIsSet() {
        // given — the discriminator set through the setter that guards it, which the builder does not expose
        PadesSignatureParametersDto parameters = aPadesParameters().build();
        parameters.setFamily(SignatureFamily.PADES);

        // when / then
        assertThat(RequestParameterGroups.presentFieldsByGroup(parameters)).isEmpty();
    }

    @Test
    void countsAnEmptyListAsAbsent() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters().withClaimedRoles().build();

        // when / then
        assertThat(RequestParameterGroups.presentFieldsByGroup(parameters)).isEmpty();
    }

    @Test
    void presentsItsGroup_whenAListIsNonEmpty() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters().withClaimedRoles("approver").build();

        // when / then
        assertThat(RequestParameterGroups.presentFieldsByGroup(parameters))
                .containsEntry(SignatureParameterGroup.SIGNED_ATTRIBUTES, List.of("claimedRoles"));
    }

    @Test
    void reachesEveryFieldOfThePadesTree() {
        // given
        PadesSignatureParametersDto parameters = FullyPopulatedParameters.pades();

        // when
        Map<SignatureParameterGroup, List<String>> present = RequestParameterGroups.presentFieldsByGroup(parameters);

        // then
        assertThat(present.keySet())
                .containsExactlyInAnyOrderElementsOf(Arrays
                        .stream(SignatureParameterGroup.values())
                        .filter(g -> g.appliesTo(SignatureFamily.PADES))
                        .toList());
        assertThat(present.values().stream().mapToLong(List::size).sum())
                .isEqualTo(ParameterPaths.leafPaths(PadesSignatureParametersDto.class).size());
    }

    @Test
    void suppliesNothing_whenTheEnvelopeCarriesOnlyTheDiscriminator() {
        // given
        PadesSignatureParametersDto requested = aPadesParameters().build();

        // when / then
        assertThat(RequestParameterGroups.suppliesNothing(requested)).isTrue();
    }

    @Test
    void suppliesNothing_whenTheRequestIsAbsent() {
        // given — no request at all

        // when / then
        assertThat(RequestParameterGroups.suppliesNothing(null)).isTrue();
    }

    @Test
    void suppliesSomething_whenOneFieldIsSet() {
        // given
        PadesSignatureParametersDto requested = aPadesParameters().withReason("Contract approval").build();

        // when / then
        assertThat(RequestParameterGroups.suppliesNothing(requested)).isFalse();
    }
}
