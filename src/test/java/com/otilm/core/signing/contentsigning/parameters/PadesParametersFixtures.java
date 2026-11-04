package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.model.common.signature.parameters.pades.CommitmentType;
import com.otilm.api.model.common.signature.parameters.pades.HorizontalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.ImageScaling;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureScope;
import com.otilm.api.model.common.signature.parameters.pades.TextHorizontalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.TextPosition;
import com.otilm.api.model.common.signature.parameters.pades.TextVerticalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.TextWrapping;
import com.otilm.api.model.common.signature.parameters.pades.VerticalAlignment;

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder.aVisibleSignature;
import static com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder.aPlacement;
import static com.otilm.core.util.builders.PadesVisibleSignatureStyleDtoBuilder.aStyle;

/**
 * PAdES parameters trees for tests; {@link #fullyPopulated()} sets every parameter field, so a walk over the tree can
 * prove it reaches each one.
 */
public final class PadesParametersFixtures {

    private PadesParametersFixtures() {
    }

    public static PadesSignatureParametersDto fullyPopulated() {
        return aPadesParameters()
                .withReason("Contract approval")
                .withLocation("Prague")
                .withContactInfo("jane.doe@example.com")
                .withSignerName("Jane Doe")
                .withSignatureScope(PadesSignatureScope.REVISION)
                .withCommitmentType(CommitmentType.PROOF_OF_APPROVAL)
                .withClaimedRoles("Head of Legal")
                .withVisibleSignature(aVisibleSignature()
                        .withVisible(true)
                        .withText("Signed by Jane Doe")
                        .withImage(new byte[]{1, 2, 3})
                        .withImageMimeType("image/png")
                        .withPlacement(aPlacement()
                                .withFieldId("Signature1")
                                .withPage(1)
                                .withOriginX(20f)
                                .withOriginY(30f)
                                .withWidth(180f)
                                .withHeight(60f)
                                .withAlignmentHorizontal(HorizontalAlignment.RIGHT)
                                .withAlignmentVertical(VerticalAlignment.BOTTOM)
                                .withZoom(100f))
                        .withStyle(aStyle()
                                .withTextColor("#171717")
                                .withTextBackgroundColor("#FFFFFF")
                                .withBackgroundColor("#F5F5F5")
                                .withPadding(5)
                                .withTextWrapping(TextWrapping.FONT_BASED)
                                .withTextPosition(TextPosition.LEFT)
                                .withTextHorizontalAlignment(TextHorizontalAlignment.LEFT)
                                .withTextVerticalAlignment(TextVerticalAlignment.MIDDLE)
                                .withImageScaling(ImageScaling.STRETCH)
                                .withDpi(300)))
                .build();
    }
}
