package com.otilm.core.util.builders;

import com.otilm.api.model.common.signature.parameters.pades.ImageScaling;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignatureStyleDto;
import com.otilm.api.model.common.signature.parameters.pades.TextHorizontalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.TextPosition;
import com.otilm.api.model.common.signature.parameters.pades.TextVerticalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.TextWrapping;

/**
 * Test builder for {@link PadesVisibleSignatureStyleDto}, building a bare object that carries only the fields the
 * scenario sets.
 */
public final class PadesVisibleSignatureStyleDtoBuilder {

    private String textColor;
    private String textBackgroundColor;
    private String backgroundColor;
    private Integer padding;
    private TextWrapping textWrapping;
    private TextPosition textPosition;
    private TextHorizontalAlignment textHorizontalAlignment;
    private TextVerticalAlignment textVerticalAlignment;
    private ImageScaling imageScaling;
    private Integer dpi;

    public static PadesVisibleSignatureStyleDtoBuilder aStyle() {
        return new PadesVisibleSignatureStyleDtoBuilder();
    }

    public PadesVisibleSignatureStyleDtoBuilder withTextColor(String textColor) {
        this.textColor = textColor;
        return this;
    }

    public PadesVisibleSignatureStyleDtoBuilder withTextBackgroundColor(String textBackgroundColor) {
        this.textBackgroundColor = textBackgroundColor;
        return this;
    }

    public PadesVisibleSignatureStyleDtoBuilder withBackgroundColor(String backgroundColor) {
        this.backgroundColor = backgroundColor;
        return this;
    }

    public PadesVisibleSignatureStyleDtoBuilder withPadding(Integer padding) {
        this.padding = padding;
        return this;
    }

    public PadesVisibleSignatureStyleDtoBuilder withTextWrapping(TextWrapping textWrapping) {
        this.textWrapping = textWrapping;
        return this;
    }

    public PadesVisibleSignatureStyleDtoBuilder withTextPosition(TextPosition textPosition) {
        this.textPosition = textPosition;
        return this;
    }

    public PadesVisibleSignatureStyleDtoBuilder withTextHorizontalAlignment(
            TextHorizontalAlignment textHorizontalAlignment) {
        this.textHorizontalAlignment = textHorizontalAlignment;
        return this;
    }

    public PadesVisibleSignatureStyleDtoBuilder withTextVerticalAlignment(TextVerticalAlignment textVerticalAlignment) {
        this.textVerticalAlignment = textVerticalAlignment;
        return this;
    }

    public PadesVisibleSignatureStyleDtoBuilder withImageScaling(ImageScaling imageScaling) {
        this.imageScaling = imageScaling;
        return this;
    }

    public PadesVisibleSignatureStyleDtoBuilder withDpi(Integer dpi) {
        this.dpi = dpi;
        return this;
    }

    public PadesVisibleSignatureStyleDto build() {
        PadesVisibleSignatureStyleDto style = new PadesVisibleSignatureStyleDto();
        style.setTextColor(textColor);
        style.setTextBackgroundColor(textBackgroundColor);
        style.setBackgroundColor(backgroundColor);
        style.setPadding(padding);
        style.setTextWrapping(textWrapping);
        style.setTextPosition(textPosition);
        style.setTextHorizontalAlignment(textHorizontalAlignment);
        style.setTextVerticalAlignment(textVerticalAlignment);
        style.setImageScaling(imageScaling);
        style.setDpi(dpi);
        return style;
    }
}
