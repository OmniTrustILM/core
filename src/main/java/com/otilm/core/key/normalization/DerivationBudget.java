package com.otilm.core.key.normalization;

import java.math.BigInteger;

/** The key-derivation work one uploaded file may demand, shared by every derivation the file needs. */
public final class DerivationBudget {

    /** The iterations all key derivations of one file may take together. */
    public static final int FILE_ITERATIONS = 10_000_000;

    private static final String ITERATION_LIMIT = "key derivation iteration";

    private BigInteger remaining = BigInteger.valueOf(FILE_ITERATIONS);

    private DerivationBudget() {
    }

    /**
     * A budget for one file, none of it spent yet.
     *
     * @return the file's budget
     */
    public static DerivationBudget forFile() {
        return new DerivationBudget();
    }

    /**
     * Charges a derivation before it runs; refuses with the key derivation iteration limit once the file's share is
     * spent. A count below zero is refused the same way.
     *
     * @param iterations the iterations of the derivation, as the file states them
     */
    public void charge(BigInteger iterations) {
        if (iterations.signum() < 0 || iterations.compareTo(remaining) > 0) {
            throw KeyFileRefusal.limitExceeded(ITERATION_LIMIT, FILE_ITERATIONS);
        }
        remaining = remaining.subtract(iterations);
    }
}
