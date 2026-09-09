package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.Comparator;
import java.util.List;

/**
 * Why a family reaches its verdict. The rule id travels to the client, so "broken" stays distinct from "no standard".
 */
public enum FamilyClass {

    /** Factoring or discrete log: Shor breaks it outright. The class the inventory exists to find. */
    SHOR_BREAKABLE(PqcVerdict.NOT_READY, "CLASSICAL-SHOR",
            "Security rests on factorisation or a discrete logarithm, which a cryptographically relevant quantum computer breaks"),

    /**
     * Symmetric or hash-based and already broken classically. An adjudication this rule set makes rather than inherits:
     * IR 8547 framing would call DES post-quantum ready, which is true and useless. Separate from
     * {@link #SHOR_BREAKABLE} because the migration it needs is a different one.
     */
    CLASSICAL_LEGACY(PqcVerdict.NOT_READY, "CLASSICAL-LEGACY",
            "Already broken or deprecated on classical grounds, so it is not a migration target regardless of quantum threat"),

    /** Symmetric or hash-based and unbroken. Grover halves it; nothing breaks it. */
    QUANTUM_RESISTANT_SYMMETRIC(PqcVerdict.READY, "SYMMETRIC-READY",
            "Symmetric or hash-based, so no quantum algorithm breaks it outright"),

    /** FIPS 203/204/205 and SP 800-208. */
    PQC_STANDARDIZED(PqcVerdict.READY, "PQC-STANDARDIZED", "A standardised post-quantum scheme"),

    /**
     * A pre-standard candidate: a superseded draft of a scheme that was standardised under another name, or a candidate
     * still in an unfinished NIST round.
     */
    PQC_PRESTANDARD(PqcVerdict.NOT_READY, "PQC-PRESTANDARD",
            "A post-quantum scheme with no finished standard, so it is not a migration target yet"),

    /** Broken by cryptanalysis: SIKE and Rainbow (2022), GeMSS (CRYPTO 2021, dropped by NIST IR 8413). */
    PQC_BROKEN(PqcVerdict.NOT_READY, "PQC-BROKEN", "A post-quantum candidate broken by cryptanalysis"),

    /** A named hybrid, reached only when the name did not yield its components. */
    PQC_HYBRID(PqcVerdict.READY, "PQC-HYBRID-FAMILY",
            "A hybrid construction combining a classical and a standardised post-quantum scheme"),

    /**
     * The token spans several primitive kinds and the properties do not say which. {@code GOST} covers a hash, two
     * block ciphers and an EC signature; {@code RIPEMD} covers a broken 128-bit digest and RIPEMD-160. The reason names
     * the classical axis, because RIPEMD's split is classical: no RIPEMD member is quantum-vulnerable.
     */
    FAMILY_AMBIGUOUS(PqcVerdict.UNKNOWN, "FAMILY-AMBIGUOUS",
            "The family covers both a classically broken and an unbroken primitive, and the recorded properties do not say which");

    /**
     * Which post-quantum component decides a hybrid, most decisive first. A standardised component wins outright.
     * Between a broken candidate and a pre-standard one the broken one decides: it is the more severe finding, and a
     * pre-standard draft beside it must not mask it.
     */
    private static final List<FamilyClass> HYBRID_PRECEDENCE = List
            .of(PQC_STANDARDIZED, PQC_HYBRID, PQC_BROKEN, PQC_PRESTANDARD);

    private final PqcVerdict verdict;
    private final String ruleId;
    private final String reason;

    FamilyClass(PqcVerdict verdict, String ruleId, String reason) {
        this.verdict = verdict;
        this.ruleId = ruleId;
        this.reason = reason;
    }

    public PqcVerdict verdict() {
        return verdict;
    }

    public String ruleId() {
        return ruleId;
    }

    public String reason() {
        return reason;
    }

    public boolean isPostQuantum() {
        return HYBRID_PRECEDENCE.contains(this);
    }

    public static Comparator<FamilyClass> byHybridPrecedence() {
        return Comparator.comparingInt(HYBRID_PRECEDENCE::indexOf);
    }
}
