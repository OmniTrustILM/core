package com.otilm.core.serialization;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.CommitmentType;
import com.otilm.api.model.common.signature.parameters.pades.HorizontalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.ImageScaling;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureScope;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignaturePlacementDto;
import com.otilm.api.model.common.signature.parameters.pades.TextHorizontalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.TextPosition;
import com.otilm.api.model.common.signature.parameters.pades.TextVerticalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.TextWrapping;
import com.otilm.api.model.common.signature.parameters.pades.VerticalAlignment;
import java.util.Base64;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder.aVisibleSignature;
import static com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder.aPlacement;
import static com.otilm.core.util.builders.PadesVisibleSignatureStyleDtoBuilder.aStyle;
import static org.assertj.core.api.Assertions.assertThat;

class SignatureParametersJsonColumnRoundTripTest {

    private static final byte[] STAMP = {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};

    private final ObjectMapper mapper = ObjectMapperFactory.jsonColumn();

    @Test
    void survivesTheJsonColumnRecipe_forTheWholePadesTree() throws Exception {
        // given — every field of the PAdES tree populated, read back as the abstract base
        PadesSignatureParametersDto original = fullyPopulated();

        // when
        String json = mapper.writeValueAsString(original);
        SignatureParametersDto decoded = mapper.readValue(json, SignatureParametersDto.class);

        // then: the discriminator selected the subtype and every value is intact
        assertThat(decoded)
                .isInstanceOf(PadesSignatureParametersDto.class)
                .usingRecursiveComparison()
                .isEqualTo(original);
    }

    /** The discriminator has to be written into the document, or nothing can select the subtype on the way back. */
    @Test
    void writesTheFamilyDiscriminatorAsAPlainProperty() throws Exception {
        // given
        PadesSignatureParametersDto original = fullyPopulated();

        // when
        String json = mapper.writeValueAsString(original);

        // then
        assertThat(json).contains("\"family\":\"" + SignatureFamily.Codes.PADES + "\"");
    }

    /** The stamp image is what makes a stored default large; base64 is how it has to travel. */
    @Test
    void travelsTheStampImageAsBase64() throws Exception {
        // given
        PadesSignatureParametersDto original = aPadesParameters()
                .withVisibleSignature(aVisibleSignature().withImage(STAMP).withImageMimeType("image/png"))
                .build();

        // when
        String json = mapper.writeValueAsString(original);

        // then
        assertThat(json).contains(Base64.getEncoder().encodeToString(STAMP));
    }

    /** An anchored placement is the other mode a stored default can be in. */
    @Test
    void survivesTheJsonColumnRecipe_whenThePlacementIsAnchored() throws Exception {
        // given
        var zoomPercentage = 75;
        PadesSignatureParametersDto original = aPadesParameters()
                .withVisibleSignature(aVisibleSignature()
                        .withPlacement(aPlacement()
                                .withPage(2)
                                .withAlignmentHorizontal(HorizontalAlignment.RIGHT)
                                .withAlignmentVertical(VerticalAlignment.BOTTOM)
                                .withZoom(zoomPercentage)))
                .build();

        // when
        SignatureParametersDto decoded = mapper
                .readValue(mapper.writeValueAsString(original), SignatureParametersDto.class);

        // then
        PadesVisibleSignaturePlacementDto reloaded = ((PadesSignatureParametersDto) decoded)
                .getVisibleSignature()
                .getPlacement();
        assertThat(reloaded.getAlignmentHorizontal()).isEqualTo(HorizontalAlignment.RIGHT);
        assertThat(reloaded.getAlignmentVertical()).isEqualTo(VerticalAlignment.BOTTOM);
        assertThat(reloaded.getZoom()).isEqualTo(zoomPercentage);
        assertThat(reloaded.getOriginX()).isNull();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static PadesSignatureParametersDto fullyPopulated() {
        return aPadesParameters()
                .withReason("Contract approval")
                .withLocation("Prague")
                .withContactInfo("jane.doe@example.com")
                .withSignerName("Jane Doe")
                .withSignatureScope(PadesSignatureScope.CERTIFICATION)
                .withCommitmentType(CommitmentType.PROOF_OF_APPROVAL)
                .withClaimedRoles("Head of Legal")
                .withVisibleSignature(aVisibleSignature()
                        .withVisible(true)
                        .withText("Signed by Jane Doe")
                        .withImage(STAMP)
                        .withImageMimeType("image/png")
                        .withPlacement(aPlacement()
                                .withPage(1)
                                .withOriginX(20f)
                                .withOriginY(30f)
                                .withWidth(180f)
                                .withHeight(60f))
                        .withStyle(aStyle()
                                .withTextColor("#171717")
                                .withTextBackgroundColor("#ffffff")
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
