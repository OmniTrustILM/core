package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.pades.HorizontalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.VerticalAlignment;
import com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder;
import com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static com.otilm.api.model.common.signature.SignatureParameterGroup.VISIBLE_SIGNATURE_CONTENT;
import static com.otilm.api.model.common.signature.SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT;
import static com.otilm.core.signing.contentsigning.parameters.PadesVisibleSignatureCompleteness.missingFields;
import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder.aVisibleSignature;
import static com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder.aPlacement;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

class PadesVisibleSignatureCompletenessTest {

    @Test
    void needsNothing_whenTheEffectiveObjectIsAbsent() {
        // given — no effective parameters at all

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(null);

        // then
        assertThat(missing).isEmpty();
    }

    @Test
    void needsNothing_whenThereIsNoVisibleSignature() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters().build();

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(parameters);

        // then
        assertThat(missing).isEmpty();
    }

    @Test
    void needsNoPlacement_whenTheSignatureIsInvisible() {
        // given
        PadesSignatureParametersDto parameters = visible(false, null);

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(parameters);

        // then
        assertThat(missing).isEmpty();
    }

    @Test
    void acceptsCompleteCoordinates() {
        // given
        PadesVisibleSignaturePlacementDtoBuilder placement = completeCoordinates();

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(true, placement));

        // then
        assertThat(missing).isEmpty();
    }

    @Test
    void namesEveryMissingField_whenCoordinatesAreIncomplete() {
        // given
        PadesVisibleSignaturePlacementDtoBuilder placement = aPlacement().withOriginX(20f).withWidth(180f);

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(true, placement));

        // then
        assertThat(missing)
                .containsExactly(entry(VISIBLE_SIGNATURE_PLACEMENT,
                        List
                                .of("visibleSignature.placement.page", "visibleSignature.placement.originY",
                                        "visibleSignature.placement.height")));
    }

    @Test
    void acceptsANamedFieldOnItsOwn() {
        // given
        PadesVisibleSignaturePlacementDtoBuilder placement = aPlacement().withFieldId("Signature1");

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(true, placement));

        // then
        assertThat(missing).isEmpty();
    }

    @Test
    void namesThePageAndBothEdges_whenAnAnchorIsIncomplete() {
        // given
        PadesVisibleSignaturePlacementDtoBuilder placement = aPlacement()
                .withAlignmentHorizontal(HorizontalAlignment.RIGHT);

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(true, placement));

        // then
        assertThat(missing)
                .containsExactly(entry(VISIBLE_SIGNATURE_PLACEMENT,
                        List.of("visibleSignature.placement.page", "visibleSignature.placement.alignmentVertical")));
    }

    /** Zoom alone, with no alignment set, still selects anchor mode rather than falling through to coordinate mode. */
    @Test
    void namesTheFullAddress_whenAnAnchorIsDetectedByZoomAlone() {
        // given
        PadesVisibleSignaturePlacementDtoBuilder placement = aPlacement().withZoom(150);

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(true, placement));

        // then
        assertThat(missing)
                .containsExactly(entry(VISIBLE_SIGNATURE_PLACEMENT,
                        List
                                .of("visibleSignature.placement.page", "visibleSignature.placement.alignmentHorizontal",
                                        "visibleSignature.placement.alignmentVertical")));
    }

    @Test
    void namesTheFullAddress_whenAnAnchorIsDetectedByVerticalAlignmentAlone() {
        // given
        PadesVisibleSignaturePlacementDtoBuilder placement = aPlacement()
                .withAlignmentVertical(VerticalAlignment.BOTTOM);

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(true, placement));

        // then
        assertThat(missing)
                .containsExactly(entry(VISIBLE_SIGNATURE_PLACEMENT,
                        List.of("visibleSignature.placement.page", "visibleSignature.placement.alignmentHorizontal")));
    }

    @Test
    void acceptsACompleteAnchor() {
        // given
        PadesVisibleSignaturePlacementDtoBuilder placement = aPlacement()
                .withPage(1)
                .withAlignmentHorizontal(HorizontalAlignment.RIGHT)
                .withAlignmentVertical(VerticalAlignment.BOTTOM);

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(true, placement));

        // then
        assertThat(missing).isEmpty();
    }

    @Test
    void namesThePlacementItself_whenADrawnSignatureHasNone() {
        // given — a signature marked drawn, carrying no placement

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(true, null));

        // then
        assertThat(missing).containsExactly(entry(VISIBLE_SIGNATURE_PLACEMENT, List.of("visibleSignature.placement")));
    }

    @Test
    void refusesIncompletePlacement_whenVisibleIsAbsent() {
        // given
        PadesVisibleSignaturePlacementDtoBuilder placement = aPlacement().withOriginX(20f).withWidth(180f);

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(null, placement));

        // then
        assertThat(missing)
                .containsExactly(entry(VISIBLE_SIGNATURE_PLACEMENT,
                        List
                                .of("visibleSignature.placement.page", "visibleSignature.placement.originY",
                                        "visibleSignature.placement.height")));
    }

    /** With neither, both the draw decision and the box stay the connector's. */
    @Test
    void needsNothing_whenVisibleAndPlacementAreBothAbsent() {
        // given — a container that says neither whether to draw nor where

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(null, null));

        // then
        assertThat(missing).isEmpty();
    }

    /**
     * The merge drops the container when the effective {@code visible} is false, so this shape does not arrive from
     * signing -- but the rule is stated on placement presence, not on {@code visible}, and it holds either way.
     */
    @Test
    void refusesIncompletePlacement_whenTheSignatureIsExplicitlyInvisible() {
        // given
        PadesVisibleSignaturePlacementDtoBuilder placement = aPlacement().withOriginX(20f);

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(visible(false, placement));

        // then
        assertThat(missing)
                .containsExactly(entry(VISIBLE_SIGNATURE_PLACEMENT,
                        List
                                .of("visibleSignature.placement.page", "visibleSignature.placement.originY",
                                        "visibleSignature.placement.width", "visibleSignature.placement.height")));
    }

    @Test
    void namesTheContent_whenADrawnSignatureHasNeitherTextNorImage() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters()
                .withVisibleSignature(aVisibleSignature().withVisible(true).withPlacement(completeCoordinates()))
                .build();

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(parameters);

        // then
        assertThat(missing)
                .containsExactly(
                        entry(VISIBLE_SIGNATURE_CONTENT, List.of("visibleSignature.text or visibleSignature.image")));
    }

    @Test
    void acceptsAnImageInPlaceOfText() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters()
                .withVisibleSignature(aVisibleSignature()
                        .withVisible(true)
                        .withImage(new byte[]{1, 2, 3})
                        .withImageMimeType("image/png")
                        .withPlacement(completeCoordinates()))
                .build();

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(parameters);

        // then
        assertThat(missing).isEmpty();
    }

    @Test
    void needsNoContent_whenVisibleIsAbsent() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters()
                .withVisibleSignature(aVisibleSignature().withPlacement(completeCoordinates()))
                .build();

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(parameters);

        // then
        assertThat(missing).isEmpty();
    }

    @Test
    void namesBothGroups_whenADrawnSignatureLacksPlacementAndContent() {
        // given
        PadesSignatureParametersDto parameters = aPadesParameters()
                .withVisibleSignature(aVisibleSignature().withVisible(true))
                .build();

        // when
        Map<SignatureParameterGroup, List<String>> missing = missingFields(parameters);

        // then
        assertThat(missing)
                .containsExactly(entry(VISIBLE_SIGNATURE_PLACEMENT, List.of("visibleSignature.placement")),
                        entry(VISIBLE_SIGNATURE_CONTENT, List.of("visibleSignature.text or visibleSignature.image")));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static PadesVisibleSignaturePlacementDtoBuilder completeCoordinates() {
        return aPlacement().withPage(1).withOriginX(20f).withOriginY(30f).withWidth(180f).withHeight(60f);
    }

    /** Carries text, so only the placement can be incomplete. */
    private static PadesSignatureParametersDto visible(Boolean drawn,
            PadesVisibleSignaturePlacementDtoBuilder placement) {
        PadesVisibleSignatureDtoBuilder visibleSignature = aVisibleSignature()
                .withVisible(drawn)
                .withText("Signed by Operator")
                .withPlacement(placement);
        return aPadesParameters().withVisibleSignature(visibleSignature).build();
    }
}
