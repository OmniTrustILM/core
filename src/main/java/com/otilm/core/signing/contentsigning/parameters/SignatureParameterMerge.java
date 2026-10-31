package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.model.common.signature.parameters.SignatureParameterContainer;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignatureDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignaturePlacementDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignatureStyleDto;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Merges a request's signature parameters over the Signing Profile's defaults into a new effective object, leaving both
 * arguments untouched. PAdES is the only family that carries parameters, so both sides are PAdES.
 *
 * <p>
 * Per-field, request wins, absence yields to the profile. Two refinements the field rule cannot express on its own: a
 * list replaces wholesale, because an element-level union would make removal inexpressible; and a placement in a
 * different addressing mode replaces the profile's placement entirely, because merging coordinates into an anchor
 * produces nonsense. The stamp image and its media type need no special case: the contract's
 * {@code @ImageAndMimeTypeTogether} invariant refuses a validated object where they disagree.
 * </p>
 *
 * <p>
 * A container left carrying nothing is dropped, so an empty object in a request cannot hand the connector a decision
 * the group permission check never saw one field of. A visible signature that resolves to {@code visible=false} is
 * dropped too: an absent container is the only "no stamp" signal the connector reads.
 * </p>
 */
public final class SignatureParameterMerge {

    private SignatureParameterMerge() {
    }

    /**
     * @return the effective parameters, or {@code null} when nothing survives the merge -- which is how the connector
     * request carries "no parameters at all" rather than an empty envelope
     */
    public static SignatureParametersDto merge(SignatureParametersDto defaults, SignatureParametersDto requested) {
        PadesSignatureParametersDto effective = mergePades((PadesSignatureParametersDto) defaults,
                (PadesSignatureParametersDto) requested);
        return orNullWhenEmpty(effective);
    }

    private static PadesSignatureParametersDto mergePades(PadesSignatureParametersDto defaults,
            PadesSignatureParametersDto requested) {
        PadesSignatureParametersDto merged = new PadesSignatureParametersDto();
        merged.setReason(pick(defaults, requested, PadesSignatureParametersDto::getReason));
        merged.setLocation(pick(defaults, requested, PadesSignatureParametersDto::getLocation));
        merged.setContactInfo(pick(defaults, requested, PadesSignatureParametersDto::getContactInfo));
        merged.setSignerName(pick(defaults, requested, PadesSignatureParametersDto::getSignerName));
        merged.setSignatureScope(pick(defaults, requested, PadesSignatureParametersDto::getSignatureScope));
        merged.setCommitmentType(pick(defaults, requested, PadesSignatureParametersDto::getCommitmentType));
        merged.setClaimedRoles(pickList(defaults, requested, PadesSignatureParametersDto::getClaimedRoles));
        PadesVisibleSignatureDto visibleSignature = mergeVisibleSignature(
                read(defaults, PadesSignatureParametersDto::getVisibleSignature),
                read(requested, PadesSignatureParametersDto::getVisibleSignature));
        merged.setVisibleSignature(visibleSignature);
        return merged;
    }

    private static PadesVisibleSignatureDto mergeVisibleSignature(PadesVisibleSignatureDto defaults,
            PadesVisibleSignatureDto requested) {
        PadesVisibleSignatureDto merged = new PadesVisibleSignatureDto();
        merged.setVisible(pick(defaults, requested, PadesVisibleSignatureDto::getVisible));
        merged.setText(pick(defaults, requested, PadesVisibleSignatureDto::getText));
        byte[] image = pick(defaults, requested, PadesVisibleSignatureDto::getImage);
        merged.setImage(image == null ? null : image.clone());
        merged.setImageMimeType(pick(defaults, requested, PadesVisibleSignatureDto::getImageMimeType));
        PadesVisibleSignaturePlacementDto placement = mergePlacement(
                read(defaults, PadesVisibleSignatureDto::getPlacement),
                read(requested, PadesVisibleSignatureDto::getPlacement));
        merged.setPlacement(placement);
        PadesVisibleSignatureStyleDto style = mergeStyle(read(defaults, PadesVisibleSignatureDto::getStyle),
                read(requested, PadesVisibleSignatureDto::getStyle));
        merged.setStyle(style);
        return Boolean.FALSE.equals(merged.getVisible()) ? null : orNullWhenEmpty(merged);
    }

    private static PadesVisibleSignaturePlacementDto mergePlacement(PadesVisibleSignaturePlacementDto defaults,
            PadesVisibleSignaturePlacementDto requested) {
        PadesVisibleSignaturePlacementDto base = replacesWholesale(defaults, requested) ? null : defaults;
        PadesVisibleSignaturePlacementDto merged = new PadesVisibleSignaturePlacementDto();
        merged.setFieldId(pick(base, requested, PadesVisibleSignaturePlacementDto::getFieldId));
        merged.setPage(pick(base, requested, PadesVisibleSignaturePlacementDto::getPage));
        merged.setOriginX(pick(base, requested, PadesVisibleSignaturePlacementDto::getOriginX));
        merged.setOriginY(pick(base, requested, PadesVisibleSignaturePlacementDto::getOriginY));
        merged.setWidth(pick(base, requested, PadesVisibleSignaturePlacementDto::getWidth));
        merged.setHeight(pick(base, requested, PadesVisibleSignaturePlacementDto::getHeight));
        merged.setRotation(pick(base, requested, PadesVisibleSignaturePlacementDto::getRotation));
        merged.setAlignmentHorizontal(pick(base, requested, PadesVisibleSignaturePlacementDto::getAlignmentHorizontal));
        merged.setAlignmentVertical(pick(base, requested, PadesVisibleSignaturePlacementDto::getAlignmentVertical));
        merged.setZoom(pick(base, requested, PadesVisibleSignaturePlacementDto::getZoom));
        return orNullWhenEmpty(merged);
    }

    private static PadesVisibleSignatureStyleDto mergeStyle(PadesVisibleSignatureStyleDto defaults,
            PadesVisibleSignatureStyleDto requested) {
        PadesVisibleSignatureStyleDto merged = new PadesVisibleSignatureStyleDto();
        merged.setTextColor(pick(defaults, requested, PadesVisibleSignatureStyleDto::getTextColor));
        merged.setTextBackgroundColor(pick(defaults, requested, PadesVisibleSignatureStyleDto::getTextBackgroundColor));
        merged.setBackgroundColor(pick(defaults, requested, PadesVisibleSignatureStyleDto::getBackgroundColor));
        merged.setPadding(pick(defaults, requested, PadesVisibleSignatureStyleDto::getPadding));
        merged.setTextWrapping(pick(defaults, requested, PadesVisibleSignatureStyleDto::getTextWrapping));
        merged.setTextPosition(pick(defaults, requested, PadesVisibleSignatureStyleDto::getTextPosition));
        merged
                .setTextHorizontalAlignment(
                        pick(defaults, requested, PadesVisibleSignatureStyleDto::getTextHorizontalAlignment));
        merged
                .setTextVerticalAlignment(
                        pick(defaults, requested, PadesVisibleSignatureStyleDto::getTextVerticalAlignment));
        merged.setImageScaling(pick(defaults, requested, PadesVisibleSignatureStyleDto::getImageScaling));
        merged.setDpi(pick(defaults, requested, PadesVisibleSignatureStyleDto::getDpi));
        return orNullWhenEmpty(merged);
    }

    /**
     * @return whether the request's placement replaces the profile's rather than refining it. An empty requested
     * placement says nothing, so it never does.
     */
    private static boolean replacesWholesale(PadesVisibleSignaturePlacementDto defaults,
            PadesVisibleSignaturePlacementDto requested) {
        if (defaults == null || RequestParameterGroups.suppliesNothing(requested)) {
            return false;
        }
        return !refines(PlacementMode.of(requested), PlacementMode.of(defaults));
    }

    /**
     * @return whether the two placements combine into one legal addressing mode. A named field admits nothing beside
     * itself; a placement carrying only the page and rotation the other two modes share completes either of them.
     */
    private static boolean refines(PlacementMode requested, PlacementMode defaults) {
        if (requested == PlacementMode.NAMED_FIELD || defaults == PlacementMode.NAMED_FIELD) {
            return requested == defaults;
        }
        return requested == PlacementMode.NONE || defaults == PlacementMode.NONE || requested == defaults;
    }

    private static <N, V> V pick(N defaults, N requested, Function<N, V> field) {
        V requestedValue = read(requested, field);
        return requestedValue != null ? requestedValue : read(defaults, field);
    }

    /** An empty requested list counts as absent, as it does for the permission check. */
    private static <N> List<String> pickList(N defaults, N requested, Function<N, List<String>> field) {
        List<String> requestedValues = read(requested, field);
        List<String> values = requestedValues == null || requestedValues.isEmpty()
                ? read(defaults, field)
                : requestedValues;
        return values == null ? null : new ArrayList<>(values);
    }

    private static <N, V> V read(N node, Function<N, V> field) {
        return node == null ? null : field.apply(node);
    }

    private static <C extends SignatureParameterContainer> C orNullWhenEmpty(C container) {
        return RequestParameterGroups.suppliesNothing(container) ? null : container;
    }

    /** The placement addressing modes. {@code NONE} covers the page and rotation the other two modes share. */
    private enum PlacementMode {
        NAMED_FIELD,
        COORDINATES,
        ANCHOR,
        NONE;

        static PlacementMode of(PadesVisibleSignaturePlacementDto placement) {
            if (placement.getFieldId() != null) {
                return NAMED_FIELD;
            }
            if (placement.getOriginX() != null || placement.getOriginY() != null || placement.getWidth() != null
                    || placement.getHeight() != null) {
                return COORDINATES;
            }
            if (placement.getAlignmentHorizontal() != null || placement.getAlignmentVertical() != null
                    || placement.getZoom() != null) {
                return ANCHOR;
            }
            return NONE;
        }
    }
}
