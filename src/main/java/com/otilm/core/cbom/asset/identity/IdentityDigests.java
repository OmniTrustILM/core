package com.otilm.core.cbom.asset.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** SHA-256 over UTF-8, rendered lowercase hex -- the one digest form every tier of the identity chain uses. */
public final class IdentityDigests {

    private IdentityDigests() {
    }

    /**
     * The digest of a pre-image, over its UTF-8 bytes.
     *
     * <p>
     * An unpaired surrogate is rejected rather than encoded. {@code String.getBytes(UTF_8)} substitutes {@code ?} for
     * one silently, which merges distinct producer strings onto a single pre-image: a lone high surrogate, a lone low
     * surrogate and a literal {@code ?} all hash identically. That is an identity collision reachable from a document
     * carrying a bare {@code \uD800} escape, which Jackson admits. The reference implementation raises here, so
     * refusing is also what keeps the two byte-identical. The component becomes a reported skip, not a failed walk.
     *
     * <p>
     * <b>RFC 8259 section 8.2 does not exclude one, and this guard is load-bearing because of that.</b> The section
     * permits an unpaired surrogate in the grammar and withholds only interoperability -- it is a SHOULD about
     * exchange, not a prohibition -- so a schema-valid document really can carry one and the parser really will hand it
     * over. An earlier reading of that section had this method documented as unreachable, which is the shape of claim
     * that gets a guard deleted as dead code.
     */
    public static String sha256Hex(String text) {
        requireWellFormedUnicode(text);
        return HexFormat.of().formatHex(digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    public static String sha256HexOfBytes(byte[] bytes) {
        return HexFormat.of().formatHex(digest(bytes));
    }

    /**
     * Refuses a string with no UTF-8 encoding -- the check {@link #sha256Hex} applies to every pre-image, exposed so
     * the extractor can apply the same rule to the strings it hands toward a {@code jsonb} column without hashing them.
     */
    static void requireWellFormedUnicode(String text) {
        int index = 0;
        while (index < text.length()) {
            char character = text.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 == text.length() || !Character.isLowSurrogate(text.charAt(index + 1))) {
                    throw new IllegalArgumentException("An identity input carries an unpaired surrogate");
                }
                index += 2;
            } else if (Character.isLowSurrogate(character)) {
                throw new IllegalArgumentException("An identity input carries an unpaired surrogate");
            } else {
                index++;
            }
        }
    }

    private static byte[] digest(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JCA specification; its absence is a broken JRE, not a runtime condition.
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
