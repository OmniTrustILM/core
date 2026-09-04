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
    CRT_DN_COMPOSITE("crt:dn-composite"),
    CRT_CN_ONLY("crt:cn-only"),
    CRT_SUBJECT_ONLY("crt:subject-only"),
    CRT_BACKSTOP("crt:backstop"),
    PRT_TYPE_VERSION_SUITES("prt:type+version+suites"),
    PRT_TYPE_VERSION("prt:type+version"),
    PRT_TYPE_VERSION_NAME("prt:type+version+name"),
    PRT_TYPE_OCCURRENCE("prt:type+occurrence"),
    PRT_TYPE_NAME("prt:type+name"),
    PRT_TYPE_ONLY("prt:type-only"),
    PRT_BACKSTOP("prt:backstop"),
    MAT_FINGERPRINT("mat:fingerprint"),
    MAT_VALUE_HASH("mat:value-hash"),
    MAT_ID("mat:id"),
    MAT_OCCURRENCE("mat:occurrence"),
    MAT_BACKSTOP("mat:backstop"),
    UNKNOWN_TYPE("backstop:unknown-type");

    private final String label;

    ChainStep(String label) {
        this.label = label;
    }

    /** The label stored with the row and published in the ratified vectors. */
    public String label() {
        return label;
    }

    /** Every step's label, in chain order. */
    public static List<String> labels() {
        return Arrays.stream(values()).map(ChainStep::label).toList();
    }
}
