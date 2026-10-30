package com.otilm.core.util.builders;

import com.otilm.api.model.common.signature.parameters.pades.HorizontalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignaturePlacementDto;
import com.otilm.api.model.common.signature.parameters.pades.VerticalAlignment;

/**
 * Test builder for {@link PadesVisibleSignaturePlacementDto}, building a bare object that carries only the fields the
 * scenario sets.
 */
public final class PadesVisibleSignaturePlacementDtoBuilder {

    private String fieldId;
    private Integer page;
    private Float originX;
    private Float originY;
    private Float width;
    private Float height;
    private Integer rotation;
    private HorizontalAlignment alignmentHorizontal;
    private VerticalAlignment alignmentVertical;
    private Float zoom;

    public static PadesVisibleSignaturePlacementDtoBuilder aPlacement() {
        return new PadesVisibleSignaturePlacementDtoBuilder();
    }

    public PadesVisibleSignaturePlacementDtoBuilder withFieldId(String fieldId) {
        this.fieldId = fieldId;
        return this;
    }

    public PadesVisibleSignaturePlacementDtoBuilder withPage(Integer page) {
        this.page = page;
        return this;
    }

    public PadesVisibleSignaturePlacementDtoBuilder withOriginX(Float originX) {
        this.originX = originX;
        return this;
    }

    public PadesVisibleSignaturePlacementDtoBuilder withOriginY(Float originY) {
        this.originY = originY;
        return this;
    }

    public PadesVisibleSignaturePlacementDtoBuilder withWidth(Float width) {
        this.width = width;
        return this;
    }

    public PadesVisibleSignaturePlacementDtoBuilder withHeight(Float height) {
        this.height = height;
        return this;
    }

    public PadesVisibleSignaturePlacementDtoBuilder withRotation(Integer rotation) {
        this.rotation = rotation;
        return this;
    }

    public PadesVisibleSignaturePlacementDtoBuilder withAlignmentHorizontal(HorizontalAlignment alignmentHorizontal) {
        this.alignmentHorizontal = alignmentHorizontal;
        return this;
    }

    public PadesVisibleSignaturePlacementDtoBuilder withAlignmentVertical(VerticalAlignment alignmentVertical) {
        this.alignmentVertical = alignmentVertical;
        return this;
    }

    public PadesVisibleSignaturePlacementDtoBuilder withZoom(Float zoom) {
        this.zoom = zoom;
        return this;
    }

    public PadesVisibleSignaturePlacementDto build() {
        PadesVisibleSignaturePlacementDto placement = new PadesVisibleSignaturePlacementDto();
        placement.setFieldId(fieldId);
        placement.setPage(page);
        placement.setOriginX(originX);
        placement.setOriginY(originY);
        placement.setWidth(width);
        placement.setHeight(height);
        placement.setRotation(rotation);
        placement.setAlignmentHorizontal(alignmentHorizontal);
        placement.setAlignmentVertical(alignmentVertical);
        placement.setZoom(zoom);
        return placement;
    }
}
