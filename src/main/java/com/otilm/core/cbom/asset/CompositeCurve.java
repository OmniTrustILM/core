package com.otilm.core.cbom.asset;

import java.util.List;

/**
 * Renders the stored curve members back into the composite spelling.
 *
 * <p>
 * A hybrid scheme names more than one curve, and the normalizer renders those as a single {@code +}-joined token in
 * sorted, deduplicated order. That token is what the ratified identity vectors hash, so its shape can never change; the
 * column holds the members split out of it, which is what lets a filter ask whether an asset touches a curve rather
 * than whether its whole composite equals one. The split preserves the normalizer's order, so joining the members back
 * reproduces the preimage spelling byte for byte -- which is what the API contract keeps carrying.
 */
public final class CompositeCurve {

    private static final String SEPARATOR = "+";

    private CompositeCurve() {
    }

    /** The stored members in the spelling the identity preimage and the API contract both use, or {@code null}. */
    public static String join(List<String> members) {
        if (members == null || members.isEmpty()) {
            return null;
        }
        return String.join(SEPARATOR, members);
    }
}
