package com.otilm.core.cbom.asset.identity;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * Canonical, unambiguous, hashable form of a distinguished name.
 *
 * <p>
 * Core already persists a normalized DN via {@code PlatformX500NameStyle.NORMALIZED}, and it is already OID-typed and
 * sorted. Three gaps make it unsafe to hash as-is: no case folding, no Unicode or whitespace normalization, and no
 * escaping -- a raw comma inside a value ({@code 2.5.4.10=Org, s.r.o.}) makes the serialization ambiguous, so two
 * different DNs can produce one pre-image. This closes all three.
 *
 * <p>
 * The rules, each of which is load-bearing rather than tidy:
 *
 * <ul>
 * <li><b>Attribute types become dotted OIDs</b>, never short names. Core's short names are runtime-mutable
 * ({@code OidHandler.cacheOid}, and {@code updateCertificateSubjectDN} exists precisely to rewrite DNs on an OID
 * rename), so a short-name key would orphan every stored row on a rename. The mapping is read from the ratified tables,
 * which carry the long spellings too.</li>
 * <li><b>RDNs sort on the full rendered {@code oid=value} string</b>, plain lexicographic by code point -- so
 * {@code 2.5.4.10} precedes {@code 2.5.4.3}, and it is not OID-numeric order either. Not on the normalized value, which
 * the specification claimed for months and which was caught by diffing vectors against it. Sorting is not a preference:
 * the producer's own renderer has already rebuilt the RDNs in a hardcoded field order and discarded true DER order, so
 * preserving source order would make one certificate reported by two producers never agree. Code point rather than
 * UTF-16 unit, which is what {@code sort(null)} compared: the reference sorts by code point, as does every other
 * ordered sequence in this package, and the two orders disagree on an astral character against one above U+E000.</li>
 * <li><b>{@code OID=#hexDER} is decoded</b> before comparison, because that is what one producer emits for every
 * attribute type it does not know.</li>
 * <li><b>RFC 4514 escapes are decoded, RFC 2253 legacy forms are read.</b> A {@code \hh} pair is the octet it names, so
 * {@code CN=a\2Cb} is the same name as {@code CN=a\,b} and not as {@code CN=a2Cb}, which dropping the backslash made
 * it. A quoted value ({@code O="Entrust, Inc."}, the OpenSSL {@code -nameopt} rendering that 84 of the 1 595 corpus DN
 * values carry) is one value: split on its inner comma, {@code O="Entrust, Inc."} and {@code O="Entrust, Ltd."}
 * rendered one AVA, {@code 2.5.4.10=\"entrust}, with the rest silently dropped. A quote opens a quoted value only as
 * the first character of one; anywhere else it is a character, or a stray one would swallow every later RDN and
 * {@code CN=a"b, O=c} would render exactly as the single-valued {@code CN=a\"b\, O\=c}. And {@code ;} separates RDNs as
 * RFC 2253 §4 requires, where RFC 4514 gives an unescaped {@code ;} no reading at all.</li>
 * <li><b>A segment carrying no {@code =} is kept as text, never dropped.</b> Dropping it keyed {@code CN=a;b},
 * {@code CN=a,b} and {@code CN=a+b} all as {@code CN=a}: a producer-controlled spelling that merges two subjects. It
 * renders without a type, which no attribute can, so it cannot alias one -- and it is not read as a common name, or
 * {@code CN=a;b} would merge with {@code CN=a,CN=b}.</li>
 * <li><b>A quoted value that is not one well-formed quoted string renders in a reserved namespace.</b> An unterminated
 * quote, or a closing quote followed by more text, is malformed under RFC 2253; its unescaped quotes render bare, which
 * {@link #escape} never lets a well-formed value do, so {@code O="Entrust, Inc., C=US} cannot key as the one-RDN
 * {@code O=\"Entrust\, Inc.\, C\=US} nor as the two-RDN {@code O=\"Entrust, Inc., C=US}.</li>
 * <li><b>A DN carrying no {@code =} at all is a bare common name</b>, not a malformed DN. Refusing it made the
 * composite unconstructible and dropped two <em>different</em> root CAs onto one identity.</li>
 * </ul>
 */
public final class DistinguishedNames {

    /**
     * Attribute types whose values are case-insensitive by their syntax. Default-deny: anything not listed is compared
     * verbatim. {@code serialNumber}, {@code emailAddress} (RFC 5321 local-parts are case-sensitive),
     * {@code dnQualifier} and binary attributes are excluded deliberately.
     */
    private static final String COMMON_NAME_OID = "2.5.4.3";

    private static final Set<String> FOLDABLE_ATTRIBUTE_OIDS = Set
            .of(COMMON_NAME_OID, "2.5.4.4", "2.5.4.6", "2.5.4.7", "2.5.4.8", "2.5.4.9", "2.5.4.10", "2.5.4.11",
                    "2.5.4.12", "2.5.4.15", "2.5.4.17", "2.5.4.41", "2.5.4.65", "2.5.4.97",
                    "0.9.2342.19200300.100.1.25", "0.9.2342.19200300.100.1.1");

    private DistinguishedNames() {
    }

    /** The canonical form, or {@code null} when the input carries no distinguished name at all. */
    public static String normalize(String dn, IdentityTables tables) {
        if (dn == null || AsciiText.isBlank(dn)) {
            return null;
        }
        String trimmed = AsciiText.strip(dn);
        if (trimmed.indexOf('=') < 0) {
            String collapsed = AsciiText.collapseWhitespace(Normalizer.normalize(trimmed, Normalizer.Form.NFKC));
            return COMMON_NAME_OID + "=" + escape(escapePercent(AsciiText.fold(collapsed)));
        }

        List<String> rdns = new ArrayList<>();
        for (String rdn : splitUnescaped(trimmed, ",;")) {
            if (AsciiText.isBlank(rdn)) {
                continue;
            }
            List<String> avas = new ArrayList<>();
            for (String ava : splitUnescaped(rdn, "+")) {
                if (!AsciiText.isBlank(ava)) {
                    avas.add(renderAttribute(ava, tables));
                }
            }
            if (!avas.isEmpty()) {
                avas.sort(AsciiText.BY_CODE_POINT);
                rdns.add(String.join("+", avas));
            }
        }
        if (rdns.isEmpty()) {
            return null;
        }
        rdns.sort(AsciiText.BY_CODE_POINT);
        return String.join(",", rdns);
    }

    /**
     * True when the DN carries nothing but a common name.
     *
     * <p>
     * A CN-only observation is deliberately not merged into a full-DN row. Merging them would fuse two certificates
     * that share a CN -- {@code CN=localhost} is issued endlessly by internal CAs -- into one row that inherits one
     * certificate's key size and expiry and both certificates' occurrences. In an inventory whose job is "where is weak
     * crypto deployed", that makes the operator's query return CLEAN for a vulnerable host. The asymmetry decides it: a
     * missed merge is one visible, repairable duplicate row; a wrong merge is silent corruption.
     */
    public static boolean isCommonNameOnly(String normalizedDn) {
        if (normalizedDn == null || normalizedDn.isEmpty()) {
            return false;
        }
        // Every RDN must be a single common-name AVA. Checking only the start of each one classified the multi-valued
        // `CN=x+SN=y` as CN-only whenever CN happened to sort first, so the reported step depended on attribute order.
        // `CN=a,CN=b` stays CN-only: it carries nothing but common names, which is what the name claims.
        return splitUnescaped(normalizedDn, ",")
                .stream()
                .allMatch(part -> part.startsWith(COMMON_NAME_OID + "=") && splitUnescaped(part, "+").size() == 1);
    }

    /**
     * One {@code type=value} pair rendered as {@code oid=value}, or a segment with no {@code =} rendered as escaped
     * text on its own.
     *
     * <p>
     * The typeless segment is compared verbatim -- default-deny, like any attribute whose syntax is unknown -- and is
     * deliberately not promoted to a common name, which is what the whole-DN bare-name rule does: that rule reads a
     * producer's {@code issuerName: "EJBCA-Root-CA"}, while a typeless segment inside a DN is a spelling nobody
     * defined, and reading it as {@code CN=} would merge {@code CN=a;b} with {@code CN=a,CN=b}.
     */
    private static String renderAttribute(String ava, IdentityTables tables) {
        int separator = ava.indexOf('=');
        if (separator < 0) {
            return escape(normalizeText(AsciiText.strip(ava)));
        }
        String rawType = AsciiText.fold(AsciiText.strip(ava.substring(0, separator)));
        String oid = tables.dnAttributeOids().getOrDefault(rawType, rawType);
        return oid + "=" + renderValue(AsciiText.stripPresent(ava.substring(separator + 1)),
                FOLDABLE_ATTRIBUTE_OIDS.contains(oid));
    }

    /**
     * The value normalized and escaped.
     *
     * <p>
     * Escaping happens here rather than in the caller because one rendering must escape <em>selectively</em>: a value
     * that opens a quote it never closes, or closes it and carries on, is malformed, and its unescaped quotes render
     * bare so that no well-formed value -- every one of whose quotes {@link #escape} escapes -- can render alike.
     * Rendering the malformed spelling as text instead reproduced the composite that a single-valued RDN with the
     * separators escaped produces, which is the boundary-shift collision the escape exists to prevent.
     *
     * @param rawValue the value as written, stripped and still escaped: whether it is quoted or opens with the ASCII
     * {@code #} marker is decided on this spelling, before RFC 4514 unescaping and before NFKC, because both can
     * manufacture a {@code #}
     * @param fold whether the attribute's syntax is case-insensitive, so ASCII letters fold
     */
    private static String renderValue(String rawValue, boolean fold) {
        if (rawValue.startsWith("\"") && closingQuote(rawValue) != rawValue.length() - 1) {
            return renderMalformedQuote(rawValue, fold);
        }
        return escape(normalizeValue(rawValue, fold));
    }

    /**
     * Every unescaped quote bare, the text between them normalized and escaped as any value is.
     *
     * <p>
     * The pieces render separately so that the quotes' positions survive: {@code O="a"b} and {@code O="a\"b} are two
     * malformed spellings, and rendering their text as one piece made them one value.
     */
    private static String renderMalformedQuote(String rawValue, boolean fold) {
        StringBuilder out = new StringBuilder(rawValue.length() + 8);
        int start = 0;
        for (int index = 0; index <= rawValue.length(); index++) {
            if (index == rawValue.length() || isUnescapedQuote(rawValue, index)) {
                out.append(escape(foldIf(fold, normalizeText(rawValue.substring(start, index)))));
                if (index < rawValue.length()) {
                    out.append('"');
                }
                start = index + 1;
            }
        }
        return out.toString();
    }

    private static boolean isUnescapedQuote(String text, int index) {
        if (text.charAt(index) != '"') {
            return false;
        }
        int backslashes = 0;
        for (int back = index - 1; back >= 0 && text.charAt(back) == '\\'; back--) {
            backslashes++;
        }
        return backslashes % 2 == 0;
    }

    /**
     * The index of the unescaped quote that closes the one the value opens with, or {@code -1} when nothing does. The
     * value is one well-formed RFC 2253 quoted string exactly when that index is its last.
     */
    private static int closingQuote(String rawValue) {
        for (int index = 1; index < rawValue.length(); index++) {
            if (isUnescapedQuote(rawValue, index)) {
                return index;
            }
        }
        return -1;
    }

    private static String foldIf(boolean fold, String value) {
        return fold ? AsciiText.fold(value) : value;
    }

    /** Ordinary text: RFC 4514 escapes decoded, NFKC applied, whitespace collapsed and stripped. Never folded. */
    private static String normalizeText(String raw) {
        return AsciiText.strip(AsciiText.collapseWhitespace(decodeEscapes(raw)));
    }

    private static String normalizeValue(String rawValue, boolean fold) {
        // One escape rule, three paths, and they must not overlap. A bare `%XX` in the output means "a byte no
        // decoder could read"; every other percent is escaped to `%25` -- inside decodeEscapes for an ordinary textual
        // value, and inside decodeHexDer for a hex value that decodes. Escaping only inside the hex paths left `CN=#FF`
        // and `CN=%FF` rendering one AVA, because a literal value never enters that method.
        //
        // NFKC runs FIRST, on every path, because the escape is injective only over normalized text. U+FF05 FULLWIDTH
        // PERCENT SIGN is not a `%` when the escape looks at it and is one afterwards, so `CN=\uFF05FF` normalized to
        // a bare `%FF` -- byte-identical to what the malformed-bytes fallback renders for `CN=#FF`, and two issuers
        // merged onto one row. Ordering it this way is what makes the class's own rule -- that any `%` in a
        // normalized value came from an escape here -- true rather than nearly true.
        //
        // The `#` test does NOT move with it. RFC 4514 defines the hex-DER marker over ASCII `#` alone, and NFKC maps
        // U+FF03 FULLWIDTH NUMBER SIGN and U+FE5F SMALL NUMBER SIGN onto `#`: tested after normalization, a textual
        // common name spelled with a compatibility number sign was decoded as DER, failed UTF-8, and rendered the
        // bare `%FF` reserved for a byte no decoder could read -- so `CN=#FF`, `CN=\uFF03FF` and `CN=\uFF05FF` were
        // one issuer. The spelling as written decides whether the payload is hex; NFKC still normalizes the payload.
        // A quoted value is text whatever it opens with: RFC 2253 quotes make the content literal. The caller has
        // already ruled that a value opening with a quote is one well-formed quoted string.
        String value;
        if (rawValue.startsWith("\"")) {
            value = normalizeText(rawValue.substring(1, rawValue.length() - 1));
        } else if (rawValue.startsWith("#")) {
            String decoded = decodeHexDer(Normalizer.normalize(unescapePairs(rawValue), Normalizer.Form.NFKC));
            value = AsciiText.strip(AsciiText.collapseWhitespace(decoded));
        } else {
            value = normalizeText(rawValue);
        }
        // ASCII-only (R12). A value differing only in non-ASCII case keys separately; the case-fold twin detector
        // reports the pair rather than merging it, which is what makes the under-merge visible instead of silent.
        return foldIf(fold, value);
    }

    /**
     * Decodes the {@code #hexDER} form one producer emits for every attribute type it does not know, refusing to
     * collapse bytes that are not UTF-8.
     *
     * <p>
     * <b>{@code new String(bytes, UTF_8)} was lossy in the identity-bearing direction.</b> It maps every malformed
     * sequence to U+FFFD, so {@code #1401E9}, {@code #1401EA} and {@code #1401FF} produced one byte-identical AVA and
     * two different issuers merged onto one row -- and {@code DocumentScope.certificateDigestClaims} normalizes the
     * same values, so the refutation index could not see the contradiction either. This is the decoding-side twin of
     * the unpaired-surrogate hole closed on the encoding side.
     *
     * <p>
     * A sequence that is not UTF-8 renders as its bytes, percent-escaped -- {@code %14%01%E9} -- which is ASCII and
     * reproducible in the reference kernel, whose {@code decode("utf-8", "replace")} carries the same defect and moves
     * with this. Escaping the whole value rather than the offending run keeps the two implementations from having to
     * agree on where a malformed run begins.
     *
     * <p>
     * <b>The escape namespace is reserved across every path, or the escape is not injective.</b> Two attempts got this
     * wrong before it was right. Escaping only the fallback moved the merge rather than closing it: {@code #FF} is not
     * UTF-8 and renders {@code %FF}, while {@code #254646} decodes cleanly to the three ASCII characters {@code %FF}.
     * Escaping both hex paths closed that pair and left a third: an ordinary textual AVA of {@code %FF} never enters
     * this method at all, so {@code CN=#FF} and {@code CN=%FF} still rendered one value. The rule that holds is that
     * <em>any</em> {@code %} in a normalized attribute value came from an escape here -- so {@link #normalizeValue}
     * escapes the literal path instead of this method escaping it twice, and a bare {@code %XX} can only mean a byte no
     * decoder could read. 0 of 1 595 corpus DN values carry a {@code %} or a {@code #} at all, so nothing moves today;
     * what changes is that a forged value no longer merges.
     */
    private static String decodeHexDer(String value) {
        try {
            byte[] decoded = HexFormat.of().parseHex(value.substring(1));
            String text = strictUtf8(decoded);
            StringBuilder printable = new StringBuilder(text.length());
            text.codePoints().filter(DistinguishedNames::isPrintable).forEach(printable::appendCodePoint);
            return AsciiText.strip(printable.toString());
        } catch (IllegalArgumentException e) {
            // Not hex after all. The leading marker is dropped and the rest compared verbatim, which is what the
            // reference does -- refusing the value outright would lose a real attribute. Escaped like any other
            // readable text: returning it raw let `CN=#%FF` render the bare `%FF` the malformed-bytes fallback
            // reserves for `CN=#FF`.
            return escapePercent(value.substring(1));
        }
    }

    private static String strictUtf8(byte[] bytes) {
        try {
            // Normalized before it is escaped, and escaped here rather than by the caller: the caller normalized the
            // hex spelling, not the bytes it decodes to, so a value whose bytes spell U+FF05 would otherwise fold to
            // a bare `%` after this method had already decided there was none. The fallback below must keep its
            // escapes bare, or a malformed byte and a decoded value spelling that byte's escape render alike --
            // which is item 17's own merge, moved rather than closed.
            return escapePercent(Normalizer.normalize(decodeUtf8Strictly(bytes), Normalizer.Form.NFKC));
        } catch (CharacterCodingException e) {
            // Bare, and the only bare escapes in the result: the caller escapes the decode path's percents first, so
            // `%FF` from here and a decoded literal `%FF` cannot render alike.
            return bareBytes(bytes);
        }
    }

    private static String decodeUtf8Strictly(byte[] bytes) throws CharacterCodingException {
        return StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
    }

    /** Each byte as a bare {@code %XX}: the one rendering reserved for a byte no decoder could read. */
    private static String bareBytes(byte[] bytes) {
        StringBuilder escaped = new StringBuilder(bytes.length * 3);
        for (byte value : bytes) {
            escaped.append('%').append(HexFormat.of().withUpperCase().toHexDigits(value));
        }
        return escaped.toString();
    }

    /**
     * Mirrors the reference's printability test, which is Unicode's rather than ASCII's: a character is printable
     * unless it is a separator or an "other" category, with space itself the one exception.
     */
    private static boolean isPrintable(int codePoint) {
        if (codePoint == ' ') {
            return true;
        }
        return switch (Character.getType(codePoint)) {
            case Character.SPACE_SEPARATOR, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR, Character.CONTROL,
                    Character.FORMAT, Character.SURROGATE, Character.PRIVATE_USE, Character.UNASSIGNED ->
                false;
            default -> true;
        };
    }

    /**
     * Splits on separators, honouring RFC 4514 backslash escapes and RFC 2253 quoted values.
     *
     * <p>
     * A plain split would break {@code O=Qualys\, Inc.} -- a real value in the corpus -- into two RDNs, and a split
     * blind to quotes broke {@code O="Entrust, Inc."} -- 84 corpus values -- the same way.
     *
     * <p>
     * A quote opens a quoted value only where a value starts: directly after an unescaped {@code =}, with nothing but
     * whitespace between. A quote anywhere else is a character. Toggling on every unescaped quote let one stray
     * {@code "} -- an inch mark, a truncated rendering -- swallow every RDN after it into the value, which then
     * rendered exactly as a single-valued RDN spelling the same text with its separators escaped. An opening quote that
     * is never closed still runs to the end: the value renders in the reserved namespace {@link #renderMalformedQuote}
     * owns, so the swallowed text cannot alias anything.
     */
    static List<String> splitUnescaped(String text, String separators) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean escaped = false;
        boolean quoted = false;
        boolean valueStart = false;
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            current.append(character);
            if (escaped) {
                escaped = false;
            } else if (character == '\\') {
                escaped = true;
                valueStart = false;
            } else if (quoted) {
                quoted = character != '"';
            } else if (character == '"' && valueStart) {
                quoted = true;
                valueStart = false;
            } else if (separators.indexOf(character) >= 0) {
                current.setLength(current.length() - 1);
                parts.add(current.toString());
                current.setLength(0);
                valueStart = false;
            } else {
                valueStart = character == '=' || (valueStart && AsciiText.isWhitespace(character));
            }
        }
        parts.add(current.toString());
        return parts;
    }

    /**
     * Decodes RFC 4514 escapes into normalized, percent-escaped text.
     *
     * <p>
     * A backslash before two hex digits is the octet they name, and consecutive pairs are one byte run: {@code \C3\BA}
     * is {@code ú}, which then joins the surrounding text so NFKC sees a whole word. Dropping the backslash and keeping
     * the digits, which this did before, made {@code CN=a\2Cb} the same name as {@code CN=a2Cb} and rendered the
     * NetLock and E-Tugra roots in the corpus as {@code TanC3BAs...}. A run that is not UTF-8 renders as bare
     * {@code %XX} bytes, the same reservation {@link #strictUtf8} makes: every other percent in the result was escaped
     * here, after NFKC, so an undecodable byte and a literal spelling of its escape cannot render alike. A backslash
     * before any other character yields that character; a trailing lone backslash escapes nothing and is dropped.
     */
    private static String decodeEscapes(String text) {
        StringBuilder out = new StringBuilder(text.length());
        StringBuilder pending = new StringBuilder();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int index = 0;
        while (index < text.length()) {
            char character = text.charAt(index);
            if (character == '\\' && index + 2 < text.length() && HexFormat.isHexDigit(text.charAt(index + 1))
                    && HexFormat.isHexDigit(text.charAt(index + 2))) {
                bytes.write(HexFormat.fromHexDigits(text, index + 1, index + 3));
                index += 3;
                continue;
            }
            flushBytes(bytes, pending, out);
            if (character != '\\') {
                pending.append(character);
                index++;
            } else if (index + 1 < text.length()) {
                pending.append(text.charAt(index + 1));
                index += 2;
            } else {
                index++;
            }
        }
        flushBytes(bytes, pending, out);
        flushText(pending, out);
        return out.toString();
    }

    /** A completed byte run joins the pending text when it decodes, and renders bare when it does not. */
    private static void flushBytes(ByteArrayOutputStream bytes, StringBuilder pending, StringBuilder out) {
        if (bytes.size() == 0) {
            return;
        }
        byte[] run = bytes.toByteArray();
        bytes.reset();
        try {
            pending.append(decodeUtf8Strictly(run));
        } catch (CharacterCodingException e) {
            flushText(pending, out);
            out.append(bareBytes(run));
        }
    }

    private static void flushText(StringBuilder pending, StringBuilder out) {
        if (!pending.isEmpty()) {
            out.append(escapePercent(Normalizer.normalize(pending, Normalizer.Form.NFKC)));
            pending.setLength(0);
        }
    }

    /**
     * Drops the backslash of every escape pair and nothing more. The hex-DER path only: its payload is hex digits, so a
     * {@code \hh} pair inside it is not an octet but a spelling {@link #decodeHexDer} will refuse as not hex.
     */
    private static String unescapePairs(String text) {
        StringBuilder out = new StringBuilder(text.length());
        boolean escaped = false;
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (escaped) {
                out.append(character);
                escaped = false;
            } else if (character == '\\') {
                escaped = true;
            } else {
                out.append(character);
            }
        }
        return out.toString();
    }

    /**
     * Reserves the escape namespace, and is applied only after NFKC on whichever path produced the text -- the
     * normalizer maps four code points onto `%` and `#`, so escaping first leaves an unescaped percent behind.
     */
    private static String escapePercent(String value) {
        return value.replace("%", "%25");
    }

    /**
     * Escapes the characters that would otherwise make a serialized DN ambiguous.
     *
     * <p>
     * The pipe is in the set on purpose: the identity pre-image is pipe-delimited, so an unescaped {@code |} inside a
     * crafted common name could shift every later field boundary and forge a collision.
     */
    private static String escape(String text) {
        StringBuilder out = new StringBuilder(text.length() + 8);
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            switch (character) {
                case '\\', ',', '+', '=', '<', '>', ';', '"', '#', '|' -> out.append('\\').append(character);
                default -> out.append(character);
            }
        }
        return out.toString();
    }
}
