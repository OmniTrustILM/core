package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignatureDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignaturePlacementDto;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Checks that a merged PAdES visible signature is complete, so that signing and profile save share one rule.
 *
 * <p>
 * Completeness is a post-merge question only. A request may be legitimately partial because the profile completes it,
 * and a profile default may be legitimately partial because the request completes it; only the effective object has to
 * stand on its own.
 * </p>
 */
public final class PadesVisibleSignatureCompleteness {

    private static final String PLACEMENT = "visibleSignature.placement";
    private static final String CONTENT = "visibleSignature.text or visibleSignature.image";

    private PadesVisibleSignatureCompleteness() {
    }

    /**
     * @return the dotted path of every field the effective visible signature still needs, keyed by the group a request
     * supplies it through; empty when it is complete
     */
    public static Map<SignatureParameterGroup, List<String>> missingFields(PadesSignatureParametersDto effective) {
        Map<SignatureParameterGroup, List<String>> missing = new LinkedHashMap<>();
        if (effective == null || effective.getVisibleSignature() == null) {
            return missing;
        }
        PadesVisibleSignatureDto visible = effective.getVisibleSignature();
        List<String> placement = missingPlacementFields(visible);
        if (!placement.isEmpty()) {
            missing.put(SignatureParameterGroup.VISIBLE_SIGNATURE_PLACEMENT, placement);
        }
        if (isDrawn(visible) && visible.getText() == null && visible.getImage() == null) {
            missing.put(SignatureParameterGroup.VISIBLE_SIGNATURE_CONTENT, List.of(CONTENT));
        }
        return missing;
    }

    private static List<String> missingPlacementFields(PadesVisibleSignatureDto visible) {
        PadesVisibleSignaturePlacementDto placement = visible.getPlacement();
        if (placement == null) {
            // An absent visible leaves both the draw decision and the placement to the connector.
            return isDrawn(visible) ? List.of(PLACEMENT) : List.of();
        }
        if (placement.getFieldId() != null) {
            return List.of();
        }
        boolean anchored = placement.getAlignmentHorizontal() != null || placement.getAlignmentVertical() != null
                || placement.getZoom() != null;
        return anchored ? missingAnchorFields(placement) : missingCoordinateFields(placement);
    }

    private static boolean isDrawn(PadesVisibleSignatureDto visible) {
        return Boolean.TRUE.equals(visible.getVisible());
    }

    private static List<String> missingAnchorFields(PadesVisibleSignaturePlacementDto placement) {
        List<String> missing = new ArrayList<>();
        require(placement.getPage(), "page", missing);
        require(placement.getAlignmentHorizontal(), "alignmentHorizontal", missing);
        require(placement.getAlignmentVertical(), "alignmentVertical", missing);
        return missing;
    }

    private static List<String> missingCoordinateFields(PadesVisibleSignaturePlacementDto placement) {
        List<String> missing = new ArrayList<>();
        require(placement.getPage(), "page", missing);
        require(placement.getOriginX(), "originX", missing);
        require(placement.getOriginY(), "originY", missing);
        require(placement.getWidth(), "width", missing);
        require(placement.getHeight(), "height", missing);
        return missing;
    }

    private static void require(Object value, String field, List<String> missing) {
        if (value == null) {
            missing.add(PLACEMENT + "." + field);
        }
    }
}
