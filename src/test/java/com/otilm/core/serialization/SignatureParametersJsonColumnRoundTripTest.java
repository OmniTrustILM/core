package com.otilm.core.serialization;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.CommitmentType;
import com.otilm.api.model.common.signature.parameters.pades.HorizontalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.ImageScaling;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureScope;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignatureDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignaturePlacementDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignatureStyleDto;
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
        assertThat(decoded).isInstanceOf(PadesSignatureParametersDto.class);
        PadesSignatureParametersDto pades = (PadesSignatureParametersDto) decoded;
        assertThat(pades.getFamily()).isEqualTo(SignatureFamily.PADES);
        assertThat(pades.getReason()).isEqualTo("Contract approval");
        assertThat(pades.getLocation()).isEqualTo("Prague");
        assertThat(pades.getContactInfo()).isEqualTo("jane.doe@example.com");
        assertThat(pades.getSignerName()).isEqualTo("Jane Doe");
        assertThat(pades.getSignatureScope()).isEqualTo(PadesSignatureScope.CERTIFICATION);
        assertThat(pades.getCommitmentType()).isEqualTo(CommitmentType.PROOF_OF_APPROVAL);
        assertThat(pades.getClaimedRoles()).containsExactly("Head of Legal");

        PadesVisibleSignatureDto visible = pades.getVisibleSignature();
        assertThat(visible.getVisible()).isTrue();
        assertThat(visible.getText()).isEqualTo("Signed by Jane Doe");
        assertThat(visible.getImage()).isEqualTo(STAMP);
        assertThat(visible.getImageMimeType()).isEqualTo("image/png");

        PadesVisibleSignaturePlacementDto placement = visible.getPlacement();
        assertThat(placement.getPage()).isEqualTo(1);
        assertThat(placement.getOriginX()).isEqualTo(20f);
        assertThat(placement.getOriginY()).isEqualTo(30f);
        assertThat(placement.getWidth()).isEqualTo(180f);
        assertThat(placement.getHeight()).isEqualTo(60f);
        assertThat(placement.getRotation()).isEqualTo(90);

        PadesVisibleSignatureStyleDto style = visible.getStyle();
        assertThat(style.getTextColor()).isEqualTo("#171717");
        assertThat(style.getTextBackgroundColor()).isEqualTo("#ffffff");
        assertThat(style.getBackgroundColor()).isEqualTo("#F5F5F5");
        assertThat(style.getPadding()).isEqualTo(5);
        assertThat(style.getTextWrapping()).isEqualTo(TextWrapping.FONT_BASED);
        assertThat(style.getTextPosition()).isEqualTo(TextPosition.LEFT);
        assertThat(style.getTextHorizontalAlignment()).isEqualTo(TextHorizontalAlignment.LEFT);
        assertThat(style.getTextVerticalAlignment()).isEqualTo(TextVerticalAlignment.MIDDLE);
        assertThat(style.getImageScaling()).isEqualTo(ImageScaling.STRETCH);
        assertThat(style.getDpi()).isEqualTo(300);
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
                .withVisibleSignature(aVisibleSignature().withImage(STAMP, "image/png"))
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
        PadesSignatureParametersDto original = aPadesParameters()
                .withVisibleSignature(aVisibleSignature()
                        .withPlacement(aPlacement()
                                .withPage(2)
                                .withAlignmentHorizontal(HorizontalAlignment.RIGHT)
                                .withAlignmentVertical(VerticalAlignment.BOTTOM)
                                .withZoom(75f)))
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
        assertThat(reloaded.getZoom()).isEqualTo(75f);
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
                        .withImage(STAMP, "image/png")
                        .withPlacement(aPlacement()
                                .withPage(1)
                                .withOriginX(20f)
                                .withOriginY(30f)
                                .withWidth(180f)
                                .withHeight(60f)
                                .withRotation(90))
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
