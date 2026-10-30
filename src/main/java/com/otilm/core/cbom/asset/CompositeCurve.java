package com.otilm.core.cbom.asset;

import java.util.List;
import java.util.regex.Pattern;

/**
 * The composite curve spelling and the stored members, and the conversion between them in both directions.
 *
 * <p>
 * A hybrid scheme names more than one curve, and the normalizer renders those as a single {@code +}-joined token in
 * sorted, deduplicated order. That token is what the ratified identity vectors hash, so its shape can never change; the
 * column holds the members split out of it, which is what lets a filter ask whether an asset touches a curve rather
 * than whether its whole composite equals one. The split preserves the normalizer's order, so joining the members back
 * reproduces the preimage spelling byte for byte -- which is what the API contract keeps carrying.
 *
 * <p>
 * Both directions live here so the separator has one definition rather than one per caller: {@code join(split(x)) == x}
 * is what the untouched identity preimage rests on, and a separator spelled separately in the writer, the reader and
 * the normalizer can break that in one of them without breaking it in the others.
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

    /**
     * The members the column holds for a composite spelling, in the order the normalizer put them in, or {@code null}.
     * A blank composite is absent rather than a one-element array of the empty string, which {@link #join} would report
     * as {@code null} while anything reading the column joined reported {@code ""}.
     */
    public static List<String> split(String composite) {
        if (composite == null || composite.isBlank()) {
            return null;
        }
        return List.of(composite.split(Pattern.quote(SEPARATOR), -1));
    }
}
