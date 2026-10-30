package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static org.assertj.core.api.Assertions.assertThat;

class SignatureParameterOverlayCoverageTest {

    private static final String VISIBLE_SIGNATURE = "visibleSignature.";
    private static final String PLACEMENT = "visibleSignature.placement.";
    private static final String STYLE = "visibleSignature.style.";
    private static final List<String> INDISTINGUISHABLE = List.of("visibleSignature.visible");
    private static final String NAMED_FIELD = PLACEMENT + "fieldId";

    @Test
    void sweepsTheWholePadesTree() {
        // given — the leaf paths the sweeps below walk

        // when / then
        assertThat(paths()).isNotEmpty();
    }

    @Test
    void landsEveryRequestField_whenTheProfileSuppliesNothing() {
        // given / when / then
        sweep((defaults, requested, path) -> ParameterPaths.populate(requested, path, 1),
                "is not overlaid onto empty defaults");
    }

    @Test
    void overridesTheProfilesOwnValue_forEveryRequestField() {
        // given
        List<String> problems = new ArrayList<>();
        List<String> indistinguishable = new ArrayList<>();

        // when
        for (String path : paths()) {
            PadesSignatureParametersDto defaults = aPadesParameters().build();
            PadesSignatureParametersDto requested = aPadesParameters().build();
            Object configured = ParameterPaths.populate(defaults, path, 0);
            Object supplied = ParameterPaths.populate(requested, path, 1);
            if (Objects.deepEquals(configured, supplied)) {
                indistinguishable.add(path);
                continue;
            }
            Object effective = ParameterPaths.read(merge(defaults, requested), path);
            if (!Objects.deepEquals(supplied, effective)) {
                problems
                        .add(path + " does not override the profile's own value: expected " + render(supplied)
                                + " but the effective parameters hold " + render(effective));
            }
        }

        // then
        assertThat(problems).isEmpty();
        assertThat(indistinguishable).isEqualTo(INDISTINGUISHABLE);
    }

    @Test
    void keepsEveryProfileField_whenTheRequestIsAboutAnotherContainer() {
        // given / when / then
        sweep((defaults, requested, path) -> {
            ParameterPaths.populate(defaults, path, 0);
            ParameterPaths.populate(requested, outerNeutralFor(path), 1);
            return ParameterPaths.read(defaults, path);
        }, "does not survive a request about another container");
    }

    /**
     * A named field is an addressing mode on its own, so no placement field is neutral beside it: every one of them
     * replaces it wholesale, which {@code SignatureParameterMergeTest} holds.
     */
    @Test
    void keepsEveryProfileField_whenTheRequestIsAboutASiblingField() {
        // given / when / then
        sweep(paths().stream().filter(path -> !NAMED_FIELD.equals(path)).toList(), (defaults, requested, path) -> {
            ParameterPaths.populate(defaults, path, 0);
            ParameterPaths.populate(requested, siblingNeutralFor(path), 1);
            return ParameterPaths.read(defaults, path);
        }, "does not survive a request about a sibling field");
    }

    @Test
    void mutatesNeitherArgument() {
        // given
        List<String> problems = new ArrayList<>();

        // when
        for (String path : paths()) {
            PadesSignatureParametersDto defaults = aPadesParameters().build();
            PadesSignatureParametersDto requested = aPadesParameters().build();
            Object configured = ParameterPaths.populate(defaults, path, 0);
            Object supplied = ParameterPaths.populate(requested, path, 1);
            PadesSignatureParametersDto defaultsBefore = aPadesParameters().build();
            ParameterPaths.populate(defaultsBefore, path, 0);
            PadesSignatureParametersDto requestedBefore = aPadesParameters().build();
            ParameterPaths.populate(requestedBefore, path, 1);

            merge(defaults, requested);

            if (!defaults.equals(defaultsBefore) || !Objects.deepEquals(configured, read(defaults, path))) {
                problems.add("merging " + path + " mutated the profile defaults");
            }
            if (!requested.equals(requestedBefore) || !Objects.deepEquals(supplied, read(requested, path))) {
                problems.add("merging " + path + " mutated the request");
            }
        }

        // then
        assertThat(problems).isEmpty();
    }

    @Test
    void copiesTheImageArray_ratherThanSharingEitherArguments() {
        // given
        PadesSignatureParametersDto defaults = aPadesParameters().build();
        ParameterPaths.populate(defaults, "visibleSignature.image", 0);
        PadesSignatureParametersDto requested = aPadesParameters().build();
        ParameterPaths.populate(requested, "visibleSignature.image", 1);

        // when
        PadesSignatureParametersDto fromProfile = merge(defaults, requestOf("reason"));
        PadesSignatureParametersDto fromRequest = merge(defaults, requested);

        // then
        assertThat(fromProfile.getVisibleSignature().getImage())
                .as("the effective parameters share the profile's image array")
                .isNotSameAs(defaults.getVisibleSignature().getImage());
        assertThat(fromRequest.getVisibleSignature().getImage())
                .as("the effective parameters share the request's image array")
                .isNotSameAs(requested.getVisibleSignature().getImage());
    }

    @Test
    void overlaysEveryNeutralFieldItself() {
        // given — the neutral fields the sweeps above arrange the opposite side with

        // when / then
        for (String path : paths()) {
            for (String neutral : List.of(outerNeutralFor(path), siblingNeutralFor(path))) {
                PadesSignatureParametersDto requested = aPadesParameters().build();
                Object supplied = ParameterPaths.populate(requested, neutral, 1);

                Object effective = ParameterPaths.read(merge(aPadesParameters().build(), requested), neutral);

                assertThat(effective)
                        .as("%s is not overlaid, so a sweep using it proves nothing", neutral)
                        .isEqualTo(supplied);
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static void sweep(Arrangement arrange, String complaint) {
        sweep(paths(), arrange, complaint);
    }

    private static void sweep(List<String> paths, Arrangement arrange, String complaint) {
        List<String> problems = new ArrayList<>();
        for (String path : paths) {
            PadesSignatureParametersDto defaults = aPadesParameters().build();
            PadesSignatureParametersDto requested = aPadesParameters().build();

            Object expected = arrange.apply(defaults, requested, path);
            Object effective = ParameterPaths.read(merge(defaults, requested), path);

            if (!Objects.deepEquals(expected, effective)) {
                problems
                        .add(path + " " + complaint + ": expected " + render(expected)
                                + " but the effective parameters hold " + render(effective));
            }
        }
        assertThat(problems).isEmpty();
    }

    @FunctionalInterface
    private interface Arrangement {

        Object apply(PadesSignatureParametersDto defaults, PadesSignatureParametersDto requested, String path);
    }

    private static String outerNeutralFor(String path) {
        return "reason".equals(path) ? "location" : "reason";
    }

    private static String siblingNeutralFor(String path) {
        if (path.startsWith(PLACEMENT)) {
            return path.equals(PLACEMENT + "page") ? PLACEMENT + "rotation" : PLACEMENT + "page";
        }
        if (path.startsWith(STYLE)) {
            return path.equals(STYLE + "dpi") ? STYLE + "padding" : STYLE + "dpi";
        }
        if (path.startsWith(VISIBLE_SIGNATURE)) {
            return path.equals(VISIBLE_SIGNATURE + "text")
                    ? VISIBLE_SIGNATURE + "imageMimeType"
                    : VISIBLE_SIGNATURE + "text";
        }
        return outerNeutralFor(path);
    }

    private static PadesSignatureParametersDto requestOf(String path) {
        PadesSignatureParametersDto requested = aPadesParameters().build();
        ParameterPaths.populate(requested, path, 1);
        return requested;
    }

    private static List<String> paths() {
        return ParameterPaths.leafPaths(PadesSignatureParametersDto.class);
    }

    private static Object read(PadesSignatureParametersDto parameters, String path) {
        return ParameterPaths.read(parameters, path);
    }

    private static PadesSignatureParametersDto merge(PadesSignatureParametersDto defaults,
            PadesSignatureParametersDto requested) {
        return (PadesSignatureParametersDto) SignatureParameterMerge.merge(defaults, requested);
    }

    private static String render(Object value) {
        return value != null && value.getClass().isArray() ? Arrays.toString((byte[]) value) : String.valueOf(value);
    }
}
