package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;

/**
 * Why a family reaches the verdict it does. The rule id travels to the client, so the distinction between "broken by
 * cryptanalysis" and "superseded by a standard" survives into an operator's filter rather than collapsing into one
 * undifferentiated {@code notReady}.
 */
public enum FamilyClass {

    /**
     * Its security rests on integer factorisation or a discrete logarithm, so Shor's algorithm breaks it outright. This
     * is the class the whole inventory exists to find.
     */
    SHOR_BREAKABLE(PqcVerdict.NOT_READY, "CLASSICAL-SHOR",
            "Security rests on factorisation or a discrete logarithm, which a cryptographically relevant quantum computer breaks"),

    /**
     * Symmetric or hash-based, and already broken or deprecated on classical grounds -- a 56-bit key, a 64-bit block, a
     * hash with practical collisions.
     *
     * <p>
     * <b>An adjudication this rule set makes rather than inherits.</b> NIST IR 8547 framing would put every symmetric
     * primitive in the ready column, and reporting DES as post-quantum ready is true and useless. The acceptance
     * criteria say "modern symmetric/hash", and this class is what "modern" excludes. It is recorded separately from
     * {@link #SHOR_BREAKABLE} because the reason is not quantum, and an operator reading the rule id can tell the two
     * migrations apart.
     */
    CLASSICAL_LEGACY(PqcVerdict.NOT_READY, "CLASSICAL-LEGACY",
            "Already broken or deprecated on classical grounds, so it is not a migration target regardless of quantum threat"),

    /** Symmetric or hash-based and unbroken. Grover's algorithm halves the effective strength; it does not break it. */
    QUANTUM_RESISTANT_SYMMETRIC(PqcVerdict.READY, "SYMMETRIC-READY",
            "Symmetric or hash-based, so no quantum algorithm breaks it outright"),

    /** Standardised post-quantum: the FIPS 203/204/205 schemes and the stateful hash-based signatures. */
    PQC_STANDARDIZED(PqcVerdict.READY, "PQC-STANDARDIZED", "A standardised post-quantum scheme"),

    /**
     * A pre-standard candidate: a superseded draft of a scheme that was standardised under another name, or a candidate
     * still in an unfinished NIST round.
     */
    PQC_PRESTANDARD(PqcVerdict.NOT_READY, "PQC-PRESTANDARD",
            "A pre-standard post-quantum candidate, not wire-compatible with the standardised scheme that superseded it"),

    /** A post-quantum candidate broken by cryptanalysis. Deployed, and worse than the classical scheme it replaced. */
    PQC_BROKEN(PqcVerdict.NOT_READY, "PQC-BROKEN", "A post-quantum candidate broken by cryptanalysis"),

    /** A named hybrid construction, reached only when the name did not yield its components. */
    PQC_HYBRID(PqcVerdict.READY, "PQC-HYBRID-FAMILY",
            "A hybrid construction combining a classical and a standardised post-quantum scheme"),

    /**
     * The family token names more than one primitive kind and the recorded properties do not say which. {@code GOST} is
     * the whole of this class today: it covers Streebog (a hash), Magma and Kuznyechik (block ciphers) and GOST R 34.10
     * (an elliptic-curve signature) -- one of which is Shor-breakable and the rest of which are not.
     */
    FAMILY_AMBIGUOUS(PqcVerdict.UNKNOWN, "FAMILY-AMBIGUOUS",
            "The family covers both quantum-vulnerable and quantum-resistant primitives, and the recorded properties do not say which");

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
}
