package com.otilm.core.cbom.asset.identity;

import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * The digest of a public-key {@code value}, specified without reference to any decoder.
 *
 * <p>
 * Two branches, and the second fires for the commonest real spelling:
 *
 * <ul>
 * <li><b>Decodable base64</b> -- ASCII whitespace removed, every remaining character in the standard alphabet with at
 * most two trailing {@code =}, and a length that is a multiple of four: SHA-256 over the <b>lowercase hex rendering of
 * the decoded bytes</b>. Not over the bytes; not over the base64 text.</li>
 * <li><b>Anything else</b> -- SHA-256 over the value <b>verbatim</b>, whitespace and PEM armour included.
 * {@code -----BEGIN PUBLIC KEY-----...} takes this branch, and so does any value a producer wrote as hex, as a
 * fingerprint, or as prose.</li>
 * </ul>
 *
 * <p>
 * <b>Both halves are arbitrary, so both are written down here rather than left to a decoder.</b> Recovering the first
 * cost one proof-of-concept round roughly 16 000 excluded candidate transforms, and 295 of its 296 remaining
 * certificate divergences sat in this function. Do <b>not</b> simplify the first branch to {@code sha256(decoded)} --
 * that reads like the natural definition and would silently re-key every certificate whose public-key target carries a
 * value.
 *
 * <p>
 * The alphabet and length tests are stated explicitly because the reference originally delegated them to a lenient
 * decoder that discards non-alphabet characters and then rejects on the leftover length. Java's MIME decoder is lenient
 * exactly where that one is strict, so the old behaviour was "whatever this interpreter does" -- which is precisely
 * what a byte-level contract cannot be.
 */
public final class MaterialValueDigest {

    private static final Pattern ASCII_WHITESPACE = Pattern.compile("[ \\t\\r\\n]");

    private static final Pattern BASE64_ALPHABET = Pattern.compile("[A-Za-z0-9+/]*={0,2}");

    private MaterialValueDigest() {
    }

    public static String of(String value) {
        String cleaned = ASCII_WHITESPACE.matcher(value).replaceAll("");
        if (!cleaned.isEmpty() && cleaned.length() % 4 == 0 && BASE64_ALPHABET.matcher(cleaned).matches()) {
            try {
                byte[] decoded = Base64.getDecoder().decode(cleaned);
                return IdentityDigests.sha256Hex(HexFormat.of().formatHex(decoded));
            } catch (IllegalArgumentException e) {
                // Defensive only: the alphabet and length tests above already exclude what the decoder would reject.
                return IdentityDigests.sha256Hex(value);
            }
        }
        return IdentityDigests.sha256Hex(value);
    }
}
