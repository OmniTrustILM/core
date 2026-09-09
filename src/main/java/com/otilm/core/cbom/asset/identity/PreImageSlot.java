package com.otilm.core.cbom.asset.identity;

/**
 * Renders a value into one slot of an identity pre-image, percent-escaping the delimiter set.
 *
 * <p>
 * The hazard is concrete, not theoretical. A producer-controlled {@code relatedCryptoMaterialProperties.id} of
 * {@code abc|F|x} produces the pre-image {@code MAT|secret-key|I|abc|F|x} -- which is exactly the shape a
 * fingerprint-tier asset emits, so a sloppy or hostile producer could forge a collision with a different tier of the
 * chain. Escaping is lossless, so no two distinct values are ever conflated.
 *
 * <p>
 * <b>Outer slots only.</b> A value that lands in a slot of the pre-image is escaped; a value that goes into a string
 * which is then <em>hashed</em>, with only the digest reaching a slot, is left literal. The distinguished-name
 * composite is the worked example: {@code CRT|S|v1|...} carries {@code 2.5.4.3=example%20ca} because that DN sits in an
 * outer slot, while the composite's inner pre-image carries {@code 2.5.4.3=vector ca} with the space intact, because
 * only its SHA-256 enters a slot. Getting this backwards re-keys every certificate.
 *
 * <p>
 * <b>{@code #} is deliberately not in the set.</b> It is the separator of the occurrence triple, owned by
 * {@link Occurrences#slot} rather than by this class, and a triple can be forged through it by a <em>textual</em> line
 * or offset: {@code {"line": "1#2", "offset": "3"}} and {@code {"line": "1", "offset": "2#3"}} render one slot. What
 * keeps that out is the CycloneDX schema typing both as integers, not this escape set and not any check in core --
 * {@code Occurrences.slot} renders a textual position without complaint if one arrives. Adding {@code #} here would
 * re-key every occurrence-bearing row, so the exposure is documented rather than escaped, and it is an argument about
 * cost, not a claim that the case is impossible. A reader asking "why is {@code #} missing?" should find the answer
 * here; if a textual position ever becomes reachable, this is the paragraph that has to change with it.
 */
public final class PreImageSlot {

    private PreImageSlot() {
    }

    /** An absent value renders as the empty slot, which is distinct from every present value. */
    public static String of(String value) {
        return value == null ? "" : escape(value, PreImageSlot::escapeFor);
    }

    public static String of(Integer value) {
        return value == null ? "" : value.toString();
    }

    /**
     * The escape set a caller applies to its own delimiter.
     *
     * <p>
     * A nested pre-image has a delimiter of its own that this class does not escape -- the {@code alg:content} digest
     * claim is the worked example -- so the escape set is the caller's, while the walk stays here.
     */
    interface EscapeSet {

        /** The replacement for {@code character}, or {@code null} when it passes through unchanged. */
        String replacementFor(char character);
    }

    /**
     * Applies an escape set, allocating only once something actually escapes.
     *
     * <p>
     * <b>Escapes compose, and the outer layer wins twice.</b> A value escaped by an inner set and then passed to
     * {@link #of} carries its {@code %} escaped again: an {@code alg} of {@code sha-256:x} becomes {@code sha-256%3Ax}
     * from the digest set and then {@code sha-256%253Ax} in the outer slot. Composing injective escapers stays
     * injective, so nothing collides -- but a conformance vector must pin the doubly-escaped spelling, because that is
     * what reaches the pre-image.
     */
    static String escape(String value, EscapeSet escapes) {
        StringBuilder escaped = null;
        for (int index = 0; index < value.length(); index++) {
            String replacement = escapes.replacementFor(value.charAt(index));
            if (replacement == null) {
                if (escaped != null) {
                    escaped.append(value.charAt(index));
                }
                continue;
            }
            if (escaped == null) {
                escaped = new StringBuilder(value.length() + 8).append(value, 0, index);
            }
            escaped.append(replacement);
        }
        return escaped == null ? value : escaped.toString();
    }

    private static String escapeFor(char character) {
        return switch (character) {
            case '%' -> "%25";
            case '|' -> "%7C";
            case ' ' -> "%20";
            case '\t' -> "%09";
            case '\r' -> "%0D";
            case '\n' -> "%0A";
            default -> null;
        };
    }
}
