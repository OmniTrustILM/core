package com.otilm.core.cbom.asset.identity;

import java.util.Arrays;
import java.util.List;

/**
 * The chain steps the identity chain can answer with, each with the label the row stores.
 *
 * <p>
 * Enumerated rather than spelled at each tier, so the set of steps is a value a test can read: the vector suite's
 * coverage check compared the steps the vectors exercise against a hand-written literal list, and a new tier with no
 * vector left both sides unchanged and the check green.
 */
public enum ChainStep {
    ALG_FAMILY("alg:family"),
    ALG_NAME("alg:name"),
    ALG_BACKSTOP("alg:backstop"),
    CRT_FINGERPRINT("crt:fingerprint"),
    CRT_COMPONENT_HASH("crt:component-hash"),
    CRT_SERIAL_ISSUER("crt:serial+issuer"),
    CRT_DN_COMPOSITE("crt:dn-composite", true),
    CRT_CN_ONLY("crt:cn-only"),
    CRT_SUBJECT_ONLY("crt:subject-only"),
    CRT_BACKSTOP("crt:backstop"),
    PRT_TYPE_VERSION_SUITES("prt:type+version+suites", true),
    PRT_TYPE_VERSION("prt:type+version"),
    PRT_TYPE_VERSION_NAME("prt:type+version+name"),
    PRT_TYPE_OCCURRENCE("prt:type+occurrence", true),
    PRT_TYPE_NAME("prt:type+name"),
    PRT_TYPE_ONLY("prt:type-only"),
    PRT_BACKSTOP("prt:backstop"),
    MAT_FINGERPRINT("mat:fingerprint"),
    MAT_VALUE_HASH("mat:value-hash"),
    MAT_ID("mat:id"),
    MAT_OCCURRENCE("mat:occurrence", true),
    MAT_BACKSTOP("mat:backstop"),
    UNKNOWN_TYPE("backstop:unknown-type");

    private final String label;

    private final boolean hashesInnerString;

    ChainStep(String label) {
        this(label, false);
    }

    ChainStep(String label, boolean hashesInnerString) {
        this.label = label;
        this.hashesInnerString = hashesInnerString;
    }

    /** The label stored with the row and published in the ratified vectors. */
    public String label() {
        return label;
    }

    /**
     * Whether this step's pre-image carries a digest of a string built here rather than the string itself.
     *
     * <p>
     * A ratified vector on such a step must publish that string as {@code innerPreImages}: without it a mismatched
     * digest names no slot, which is what cost one round 768 guesses. The property lives on the step because the vector
     * suite's check used a hand-written label list that could omit a tier silently.
     *
     * <p>
     * True only for the steps that hash unconditionally. {@code crt:cn-only} and {@code crt:subject-only} hash the
     * occurrence triples too, but only when the certificate states an occurrence -- without one the suffix is empty and
     * nothing is hashed -- so the vector suite asserts those two against the component instead.
     */
    public boolean hashesInnerString() {
        return hashesInnerString;
    }

    /** The labels of every step whose vectors must publish an inner pre-image. */
    public static List<String> hashingLabels() {
        return Arrays.stream(values()).filter(ChainStep::hashesInnerString).map(ChainStep::label).toList();
    }

    /** Every step's label, in chain order. */
    public static List<String> labels() {
        return Arrays.stream(values()).map(ChainStep::label).toList();
    }
}
