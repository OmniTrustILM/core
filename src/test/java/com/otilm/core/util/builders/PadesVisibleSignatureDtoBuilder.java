package com.otilm.core.util.builders;

import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignatureDto;

/**
 * Test builder for {@link PadesVisibleSignatureDto}, building a bare object that carries only the fields the scenario
 * sets. An unset {@code visible} flag and an absent placement are themselves scenarios here, so the builder defaults
 * nothing.
 */
public final class PadesVisibleSignatureDtoBuilder {

    private Boolean visible;
    private String text;
    private byte[] image;
    private String imageMimeType;
    private PadesVisibleSignaturePlacementDtoBuilder placement;
    private PadesVisibleSignatureStyleDtoBuilder style;

    public static PadesVisibleSignatureDtoBuilder aVisibleSignature() {
        return new PadesVisibleSignatureDtoBuilder();
    }

    public PadesVisibleSignatureDtoBuilder withVisible(Boolean visible) {
        this.visible = visible;
        return this;
    }

    public PadesVisibleSignatureDtoBuilder withText(String text) {
        this.text = text;
        return this;
    }

    public PadesVisibleSignatureDtoBuilder withImage(byte[] image) {
        this.image = image;
        return this;
    }

    /** The image and the media type that decodes it travel together, and the merge rules keep them one unit. */
    public PadesVisibleSignatureDtoBuilder withImage(byte[] image, String imageMimeType) {
        this.image = image;
        this.imageMimeType = imageMimeType;
        return this;
    }

    public PadesVisibleSignatureDtoBuilder withImageMimeType(String imageMimeType) {
        this.imageMimeType = imageMimeType;
        return this;
    }

    public PadesVisibleSignatureDtoBuilder withPlacement(PadesVisibleSignaturePlacementDtoBuilder placement) {
        this.placement = placement;
        return this;
    }

    public PadesVisibleSignatureDtoBuilder withStyle(PadesVisibleSignatureStyleDtoBuilder style) {
        this.style = style;
        return this;
    }

    public PadesVisibleSignatureDto build() {
        PadesVisibleSignatureDto visibleSignature = new PadesVisibleSignatureDto();
        visibleSignature.setVisible(visible);
        visibleSignature.setText(text);
        visibleSignature.setImage(image);
        visibleSignature.setImageMimeType(imageMimeType);
        visibleSignature.setPlacement(placement == null ? null : placement.build());
        visibleSignature.setStyle(style == null ? null : style.build());
        return visibleSignature;
    }
}
