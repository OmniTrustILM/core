package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * RFC 8785 (JCS) canonicalization, restricted to what CBOM documents actually contain, plus the reference-stripping
 * projection every hashed payload passes through first.
 *
 * <p>
 * Load-bearing for three separate things, which is why it lives in exactly one place: the hash-backstop pre-image, the
 * deterministic merge tie-break, and the redaction substitute.
 *
 * <p>
 * <b>Byte-exactness is the contract.</b> Two implementations that group assets identically can still write different
 * identity keys, and a partition-based conformance suite cannot see the difference -- that is why the specification
 * pins the bytes and ships vectors carrying each pre-image, not only each digest. Every choice below is made to match
 * the reference rather than to match what a JSON library does by default:
 *
 * <ul>
 * <li><b>Keys sort by Unicode code point</b>, not by UTF-16 code unit. The two orders disagree for any key containing a
 * character above the basic multilingual plane, because a surrogate pair compares below {@code U+E000..U+FFFF} as code
 * units and above it as code points.</li>
 * <li><b>Control characters escape as lowercase {@code \\u00XX}</b>, with the {@code \\b \\f \\n \\r \\t} shortcuts.
 * Jackson emits uppercase hex, which is a different byte for the same document.</li>
 * <li><b>Non-ASCII passes through raw.</b> No {@code \\u} escaping of anything above {@code U+001F}.</li>
 * <li><b>An integral number renders as an integer.</b> One producer really does ship {@code specVersion: 999} as a
 * number while everyone else ships a string, and two payloads differing only in that spelling must not produce
 * different digests.</li>
 * </ul>
 */
public final class CanonicalJson {

    /**
     * Document-internal bom-refs. CycloneDX 1.7 renamed every one of them, so excluding them from any hashed projection
     * is what makes the hash backstop 1.6/1.7 parity-safe: keeping them was measured to produce 13 material rows where
     * 8 are correct, purely because the same asset carries {@code algorithmRef} under 1.6 and
     * {@code relatedCryptographicAssets} under 1.7.
     */
    private static final Set<String> REFERENCE_FIELDS = Set
            .of("algorithmRef", "signatureAlgorithmRef", "subjectPublicKeyRef", "cryptoRefArray",
                    "relatedCryptographicAssets", "relatedCryptographicAsset");

    private CanonicalJson() {
    }

    /** The canonical serialization of a node, as the reference writes it. */
    public static String canonicalize(JsonNode node) {
        StringBuilder out = new StringBuilder(256);
        write(node, out);
        return out.toString();
    }

    /** SHA-256 over {@link #canonicalize}. */
    public static String canonicalDigest(JsonNode node) {
        return IdentityDigests.sha256Hex(canonicalize(node));
    }

    /** SHA-256 over the canonical form of the reference-stripped projection -- the backstop tiers' payload digest. */
    public static String projectionDigest(JsonNode node) {
        return canonicalDigest(strippedProjection(node));
    }

    /** Strips document-internal references, recursively, before anything hashes the payload. */
    public static JsonNode strippedProjection(JsonNode node) {
        if (node == null) {
            return null;
        }
        if (node.isObject()) {
            ObjectNode stripped = JsonNodeFactory.instance.objectNode();
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                if (!REFERENCE_FIELDS.contains(field.getKey())) {
                    stripped.set(field.getKey(), strippedProjection(field.getValue()));
                }
            }
            return stripped;
        }
        if (node.isArray()) {
            ArrayNode stripped = JsonNodeFactory.instance.arrayNode();
            for (JsonNode element : node) {
                stripped.add(strippedProjection(element));
            }
            return stripped;
        }
        return node;
    }

    private static void write(JsonNode node, StringBuilder out) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            out.append("null");
            return;
        }
        if (node.isBoolean()) {
            out.append(node.booleanValue() ? "true" : "false");
            return;
        }
        if (node.isNumber()) {
            writeNumber(node, out);
            return;
        }
        if (node.isTextual()) {
            writeString(node.textValue(), out);
            return;
        }
        if (node.isArray()) {
            out.append('[');
            for (int index = 0; index < node.size(); index++) {
                if (index > 0) {
                    out.append(',');
                }
                write(node.get(index), out);
            }
            out.append(']');
            return;
        }
        if (node.isObject()) {
            List<String> names = new ArrayList<>(node.properties().size());
            node.properties().forEach(field -> names.add(field.getKey()));
            names.sort(AsciiText.BY_CODE_POINT);
            out.append('{');
            for (int index = 0; index < names.size(); index++) {
                if (index > 0) {
                    out.append(',');
                }
                writeString(names.get(index), out);
                out.append(':');
                write(node.get(names.get(index)), out);
            }
            out.append('}');
            return;
        }
        // Binary and POJO nodes cannot appear in a parsed CBOM document; refusing is better than inventing bytes.
        throw new IllegalArgumentException("Unsupported node kind in canonical JSON: " + node.getNodeType());
    }

    private static void writeNumber(JsonNode node, StringBuilder out) {
        // An integer token keeps arbitrary precision, as the reference's own integers do.
        if (node.isIntegralNumber()) {
            out.append(node.bigIntegerValue().toString());
            return;
        }
        // A fractional token is narrowed to a double FIRST, deliberately. The reference parses JSON floats into
        // machine doubles, so `0.1000000000000000000001` and `0.1` are one value there; keeping the literal's full
        // precision here would write a different payload for a document the reference considers identical.
        double value = node.doubleValue();
        if (!Double.isFinite(value)) {
            // The reference refuses to serialize a non-finite number rather than inventing a spelling for it. The
            // walker turns this into a per-component skip, which is what a document carrying `1e400` deserves.
            throw new IllegalArgumentException("A non-finite number cannot enter a canonical payload");
        }
        // An integral float is emitted as an integer, so `999` and `999.0` cannot produce different digests. The
        // exact binary value is taken, not the shortest decimal: `1e30` is 1000000000000000019884624838656.
        if (value == Math.rint(value)) {
            out.append(exactBinaryValue(value).toBigIntegerExact().toString());
            return;
        }
        out.append(shortestDecimal(value));
    }

    /**
     * The double's exact binary value, which is the value the digest is defined over.
     *
     * <p>
     * {@code BigDecimal.valueOf} is deliberately not used, and this is the single place that choice is made:
     * {@code valueOf} routes through {@code Double.toString}, so {@code 1e30} would enter the payload as
     * {@code 1000000000000000000000000000000} where the value actually held is {@code 1000000000000000019884624838656}.
     * The two spellings hash differently, so the shortest-decimal one cannot be substituted here.
     */
    private static BigDecimal exactBinaryValue(double value) {
        return new BigDecimal(value); // NOSONAR - the exact binary value is the point; see above
    }

    /**
     * The shortest round-tripping decimal, rendered the way the reference renders it.
     *
     * <p>
     * Not a Java default. {@code BigDecimal.toPlainString} writes {@code 1e-7} as {@code 0.0000001} and the reference
     * writes {@code 1e-07}, so a payload carrying a small fractional number would hash differently in the two
     * implementations while every other byte agreed. The threshold is the reference's: scientific notation when the
     * decimal point falls at or below position -4, fixed notation otherwise, with a signed two-digit exponent.
     *
     * <p>
     * <b>This is a specification gap, recorded rather than papered over.</b> The specification calls the canonical
     * payload "RFC 8785 / JCS", but RFC 8785 mandates ECMAScript number formatting, which would render this same value
     * {@code 1e-7} -- a third spelling, agreeing with neither. No corpus document reaches this branch (measured: zero
     * fractional numbers in 2355 real payloads, because every numeric field CycloneDX defines is an integer), so
     * nothing observable turns on it today. It is written down here, and pinned by a test, because the alternative is
     * what happened to this project's base64 boundary once already: a hashed path whose behaviour was whatever one
     * language's primitive happened to do, discovered years later as two rows for one key.
     */
    private static String shortestDecimal(double value) {
        double magnitude = Math.abs(value);
        BigDecimal exact = exactBinaryValue(magnitude);
        BigDecimal shortest = null;
        // Fewest significant digits that still round-trip, rounded half-even off the EXACT binary value. Deliberately
        // not derived from Double.toString: the JDK renders Double.MIN_VALUE as 4.9E-324 where the shortest
        // round-tripping form -- and the reference's -- is 5e-324. Both parse back to the same double, so a
        // round-trip check alone would have accepted the longer one and written a different byte.
        for (int precision = 1; precision <= 17; precision++) {
            BigDecimal candidate = exact.round(new MathContext(precision, RoundingMode.HALF_EVEN));
            if (candidate.doubleValue() == magnitude) {
                shortest = candidate.stripTrailingZeros();
                break;
            }
        }
        if (shortest == null) {
            shortest = exact.stripTrailingZeros();
        }
        String digits = shortest.unscaledValue().toString();
        int pointPosition = digits.length() - shortest.scale();
        String sign = value < 0 ? "-" : "";
        if (pointPosition > -4 && pointPosition <= 17) {
            StringBuilder fixed = new StringBuilder(sign);
            if (pointPosition <= 0) {
                fixed.append("0.").append("0".repeat(-pointPosition)).append(digits);
            } else if (pointPosition >= digits.length()) {
                fixed.append(digits).append("0".repeat(pointPosition - digits.length())).append(".0");
            } else {
                fixed.append(digits, 0, pointPosition).append('.').append(digits.substring(pointPosition));
            }
            return fixed.toString();
        }
        StringBuilder scientific = new StringBuilder(sign).append(digits.charAt(0));
        if (digits.length() > 1) {
            scientific.append('.').append(digits.substring(1));
        }
        int renderedExponent = pointPosition - 1;
        scientific.append('e').append(renderedExponent < 0 ? '-' : '+');
        String exponentDigits = Integer.toString(Math.abs(renderedExponent));
        return scientific.append(exponentDigits.length() < 2 ? "0" + exponentDigits : exponentDigits).toString();
    }

    private static void writeString(String text, StringBuilder out) {
        out.append('"');
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            switch (character) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    // Lowercase hex, and only below U+0020. Jackson escapes with uppercase hex and would escape more,
                    // either of which is a different byte for the same document.
                    if (character < 0x20) {
                        out.append(String.format("\\u%04x", (int) character));
                    } else {
                        out.append(character);
                    }
                }
            }
        }
        out.append('"');
    }
}
