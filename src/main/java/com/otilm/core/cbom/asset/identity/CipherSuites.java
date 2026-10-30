package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Cipher-suite identifiers, reduced to IANA codes -- never bom-refs, never raw suite names.
 *
 * <p>
 * A suite's {@code algorithms[]} holds document-internal bom-refs, and the same AES-128-GCM asset is
 * {@code ...@sha256:eba74aba...} in one document and {@code ...@b0c6374d-...} in another, so hashing them forks one
 * estate into two rows. The suite {@code name} is not producer-stable either: one producer emits the OpenSSL alias
 * {@code TLS_AKE_WITH_AES_128_GCM_SHA256} where IANA calls code {@code 0x1301} {@code TLS_AES_128_GCM_SHA256}. The
 * identifiers are the code bytes, so they are stable.
 */
public final class CipherSuites {

    private static final Pattern HEX_DIGITS = Pattern.compile("[0-9a-f]+");

    private static final int MAX_CODE_UNIT = 0xFFFF;

    private CipherSuites() {
    }

    /**
     * Normalizes an identifier list to its IANA code as lowercase hex, or {@code null}.
     *
     * <p>
     * Four encodings occur in real documents and all four must land on the same code: one element per byte unpadded
     * ({@code ["0x13", "0x1"]}), one element per byte padded ({@code ["0xC0", "0x30"]}), both bytes comma-packed into a
     * single element ({@code "0x13,0x02"}), and the whole two-byte code in one token ({@code ["0x1301"]}, which
     * CycloneDX's own {@code valid-cryptography-full-1.7} conformance fixture emits). Rendering each token to an even
     * hex width is what merges them; a one-octet parser splits that fixture's TLS 1.3 suite from every per-byte
     * spelling of it.
     *
     * <p>
     * The width is the <b>producer's</b>, rounded up to a whole octet -- never the width of the parsed value.
     * {@code Integer.toHexString} drops leading zeros, so padding its output restored a nibble instead of an octet and
     * the merge held only for a non-zero high byte: {@code ["0x002F"]} rendered {@code 2f} where
     * {@code ["0x00", "0x2F"]} rendered {@code 002f}. That forked every suite in {@code 0x0000}-{@code 0x00FF} between
     * its two spellings -- the classic TLS block, {@code 0x002F} {@code TLS_RSA_WITH_AES_128_CBC_SHA} among them -- and
     * also let a packed {@code 0x002F} collide with a malformed one-byte {@code ["0x2F"]}.
     *
     * <p>
     * Bytes are joined in <b>array order, before any sorting</b>, because flattening across suites collides:
     * {@code {0xC02B, 0x1301}} and {@code {0xC001, 0x132B}} share a byte multiset and would otherwise hash alike.
     *
     * <p>
     * <b>Grouping is not identity.</b> Because every token renders to a whole number of octets, the result is the
     * declaration's <em>byte stream</em> and nothing else: {@code ["0x131", "0x1"]} and {@code ["0x01", "0x3101"]} both
     * render {@code 013101} because both state the bytes {@code 01 31 01}. That is the same equivalence that merges the
     * four spellings above, not a collision beside it -- two lists keying alike means they said the same bytes. What
     * would be a defect is a token rendering to half an octet, which is what the unpadded {@code %02x} did to
     * {@code 0x131}: {@code 131} is not a byte stream at all, so the concatenation stopped meaning anything.
     */
    public static String code(JsonNode identifiers) {
        if (identifiers == null || !identifiers.isArray()) {
            return null;
        }
        StringBuilder octets = new StringBuilder();
        for (JsonNode element : identifiers) {
            if (!element.isTextual()) {
                // Skipping it instead let ["0x13", {}, "0x01"] produce the code of the well-formed ["0x13", "0x01"],
                // so a malformed list impersonated a real suite. All-or-nothing means the malformed element decides.
                return null;
            }
            if (!appendOctets(element.textValue(), octets)) {
                return null;
            }
        }
        return octets.isEmpty() ? null : octets.toString();
    }

    /** Appends every token of one element, or returns {@code false} for a list this implementation cannot read. */
    private static boolean appendOctets(String element, StringBuilder octets) {
        // Limit -1 keeps trailing empty tokens, which the default drops: "," split with the default yields no tokens
        // at all, so the blank check below never saw it and the element contributed nothing silently.
        for (String token : element.split(",", -1)) {
            String trimmed = AsciiText.strip(token);
            if (trimmed.isEmpty()) {
                // Skipped, a blank token made ["0x13","","0x01"] render byte-identically to the well-formed
                // ["0x13","0x01"], which is the impersonation the non-textual branch above refuses. The two rules
                // now agree: anything in the list this implementation cannot read costs the whole code.
                //
                // That doctrine is deliberate and it has a cost worth stating: a merely sloppy list pays the same
                // price as an unreadable one, so ["0x13,"] -- one unambiguous octet with a trailing comma -- yields no
                // code, and tokens() falls back from c:13 to n:<NAME>, re-keying the protocol tier. Exempting a
                // leading or trailing empty token would rescue it, at the price of a rule with two halves: an empty
                // token is either readable or it is not, and deciding by position is a guess about producer intent.
                // One rule, uniformly fail-closed, is the arm chosen here.
                return false;
            }
            String hex = octetsOf(AsciiText.fold(trimmed));
            if (hex == null) {
                return false;
            }
            octets.append(hex);
        }
        return true;
    }

    /**
     * One folded token as an even number of lowercase hex digits, or {@code null} when it is not a readable code unit.
     *
     * <p>
     * A token this implementation cannot read yields no code for the whole list rather than a partial one. The caller
     * falls back to the suite name, which is what keeps "we know it has suites and cannot read them" apart from
     * "nothing was said".
     *
     * @param folded a non-empty token, already ASCII-folded by the caller -- the case fold stays there because that is
     * where the token is known to be present, and this method is about hex rather than about case
     */
    private static String octetsOf(String folded) {
        if (folded.startsWith("+") || folded.startsWith("-")) {
            return null;
        }
        String digits = folded.startsWith("0x") ? folded.substring(2) : folded;
        if (!HEX_DIGITS.matcher(digits).matches()) {
            return null;
        }
        try {
            int value = Integer.parseInt(digits, 16);
            if (value > MAX_CODE_UNIT) {
                return null;
            }
            // The producer's own width, rounded up to a whole octet -- not the width of the parsed value.
            // Integer.toHexString drops leading zeros, so padding its result restored a nibble rather than an
            // octet: ["0x002F"] rendered 2f where ["0x00","0x2F"] rendered 002f, forking every suite in
            // 0x0000-0x00FF -- the classic TLS block -- between its packed and per-byte spellings.
            int width = digits.length() + (digits.length() & 1);
            String hex = Integer.toHexString(value);
            return "0".repeat(width - hex.length()) + hex;
        } catch (NumberFormatException e) {
            // More hex digits than an int holds. HEX_DIGITS already passed, so this is length alone.
            return null;
        }
    }

    /**
     * The exact newline-joined string the cipher-suite slot hashes, or {@code null} when no suite yields a token.
     *
     * <p>
     * Exposed for the same reason as the occurrence triples: a hashed slot that does not publish its input is not
     * testable, because a vector shows only the digest.
     *
     * <p>
     * A suite whose code was refuted by the document falls back to its uppercased name rather than vanishing. That
     * fallback is also what makes a name-emitting producer split visibly from a code-emitting one.
     */
    public static String tokens(JsonNode properties, Set<String> refuted) {
        JsonNode protocol = properties == null ? null : properties.get("protocolProperties");
        JsonNode suites = protocol == null ? null : protocol.get("cipherSuites");
        if (suites == null || !suites.isArray()) {
            return null;
        }
        // Code-point order, not Java's UTF-16 order: this set is hashed into the protocol tier, and a bare TreeSet
        // sorted two suite names with astral characters opposite to the way the occurrence triples sort them.
        TreeSet<String> tokens = new TreeSet<>(AsciiText.BY_CODE_POINT);
        for (JsonNode suite : suites) {
            if (!suite.isObject()) {
                continue;
            }
            String code = code(suite.get("identifiers"));
            JsonNode name = suite.get("name");
            if (code != null && !refuted.contains(code)) {
                tokens.add("c:" + code);
            } else if (name != null && name.isTextual() && !AsciiText.isBlank(name.textValue())) {
                tokens.add("n:" + PreImageSlot.of(AsciiText.upper(AsciiText.strip(name.textValue()))));
            }
        }
        return tokens.isEmpty() ? null : String.join("\n", tokens);
    }

    /** True when the properties declare a {@code cipherSuites} array with at least one entry. */
    public static boolean declared(JsonNode properties) {
        JsonNode protocol = properties == null ? null : properties.get("protocolProperties");
        JsonNode suites = protocol == null ? null : protocol.get("cipherSuites");
        return suites != null && suites.isArray() && suites.size() > 0;
    }
}
