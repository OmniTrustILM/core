package com.otilm.core.cbom.asset.identity;

import java.util.Comparator;
import java.util.regex.Pattern;

/**
 * ASCII-only case folding, and the separator-dropping fold used for table lookup.
 *
 * <p>
 * The governing rule (specification R12): an operation applied to a keyed value must not be able to change across a
 * runtime or library version. Locale is only one such dependency -- an unpinned {@code toUpperCase()} turns
 * {@code Camellia} into {@code CAMELL<dotless I>A} under Turkish and loses the family -- but Unicode case-folding
 * tables are another, and they have changed between Unicode versions. A stored unique arbiter that shifts on a JDK
 * upgrade re-keys the estate silently.
 *
 * <p>
 * Two concrete hazards a Unicode fold carries that this one does not:
 *
 * <ul>
 * <li>{@code U+212A KELVIN SIGN} case-folds to ASCII {@code k}, so a non-ASCII character could <em>alias</em> onto a
 * registry token and claim a family it does not have.</li>
 * <li>{@code <sharp s>.toUpperCase()} is {@code SS} -- length-changing -- so an uppercase fold is strictly worse than a
 * lowercase one on non-ASCII input.</li>
 * </ul>
 *
 * <p>
 * Non-ASCII characters therefore pass through unchanged. They can never fold onto an ASCII token, and a value differing
 * only in non-ASCII case under-merges -- the safe direction, and stable forever. The resulting duplicate is not
 * accepted silently: it is reported by the case-fold twin detector, which may use the runtime's Unicode tables
 * precisely because its answer never enters a key.
 */
public final class AsciiText {

    /**
     * The whitespace the reference strips and collapses, which is not the whitespace Java strips.
     *
     * <p>
     * Measured over the whole BMP, the two definitions disagree on exactly four code points, all in one direction:
     * {@code U+0085 NEXT LINE}, {@code U+00A0 NO-BREAK SPACE}, {@code U+2007 FIGURE SPACE} and
     * {@code U+202F NARROW NO-BREAK SPACE} are whitespace to the reference and are not whitespace to
     * {@link Character#isWhitespace}, which is what {@link String#strip()} consults. Nothing runs the other way --
     * every character the JDK calls whitespace is in this set -- so substituting {@link #strip} for the JDK's is always
     * safe. {@code U+200B ZERO WIDTH SPACE} is correctly whitespace to neither.
     *
     * <p>
     * The no-break spaces are exactly the ones that occur in producer text pasted out of documents. A trailing one
     * survives {@code String.strip()}, and NFKC then turns it into an ordinary trailing space, keying {@code "RSA "}
     * apart from {@code "RSA"}: a silent inventory split on a formatting accident.
     */
    private static final String PYTHON_WHITESPACE = " \t\n\u000B\f\r\u001C\u001D\u001E\u001F\u0085\u00A0"
            + "\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u2028\u2029"
            + "\u202F\u205F\u3000";

    private static final Pattern LOOKUP_SEPARATORS = Pattern.compile("[" + PYTHON_WHITESPACE + "_\\-/]+");

    private static final Pattern WHITESPACE_RUN = Pattern.compile("[" + PYTHON_WHITESPACE + "]+");

    /**
     * Orders by code point, so an astral character sorts above every basic-plane one, as the reference does.
     *
     * <p>
     * Java's natural {@code String} order compares UTF-16 units, which sorts a supplementary character <em>below</em>
     * {@code U+E000}-{@code U+FFFF}, because its high surrogate is {@code U+D800}-{@code U+DBFF}. Every sorted sequence
     * that reaches a pre-image or a canonical rendering has to use this instead of {@code compareTo} or a bare
     * {@code TreeSet}.
     *
     * <p>
     * It lives here rather than in any one of its callers because all of them are load-bearing for byte-exactness, so a
     * correction has to land in one place. Three sequences depend on it today: canonical object member order, the
     * occurrence triples, and the cipher-suite tokens.
     */
    public static final Comparator<String> BY_CODE_POINT = (left, right) -> {
        int leftIndex = 0;
        int rightIndex = 0;
        while (leftIndex < left.length() && rightIndex < right.length()) {
            int leftPoint = left.codePointAt(leftIndex);
            int rightPoint = right.codePointAt(rightIndex);
            if (leftPoint != rightPoint) {
                return Integer.compare(leftPoint, rightPoint);
            }
            leftIndex += Character.charCount(leftPoint);
            rightIndex += Character.charCount(rightPoint);
        }
        return Integer.compare(left.length() - leftIndex, right.length() - rightIndex);
    };

    private AsciiText() {
    }

    /** Lower-cases ASCII letters only, leaving every other code point untouched. */
    public static String fold(String text) {
        return text == null ? null : foldPresent(text);
    }

    /**
     * {@link #fold} for a value whose presence is already established, so the return is not nullable.
     *
     * <p>
     * Identical folding. The split exists because {@code fold}'s null tolerance is right at the producer boundary,
     * where a missing member and an empty one both arrive as {@code null}, and wrong below it: the nullable return
     * propagates into the dataflow of every caller that hands it a value it constructed one line earlier, and a
     * dereference of the result is then unprovable rather than unreachable. Callers that built the string pass it here;
     * callers reading a producer's member keep {@code fold}.
     */
    public static String foldPresent(String text) {
        StringBuilder folded = null;
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (character >= 'A' && character <= 'Z') {
                if (folded == null) {
                    folded = new StringBuilder(text);
                }
                folded.setCharAt(index, (char) (character + 32));
            }
        }
        return folded == null ? text : folded.toString();
    }

    /**
     * Upper-cases ASCII letters only -- the same restriction as {@link #fold}, upward.
     *
     * <p>
     * Enum-shaped slots (mode, padding, cipher-suite names) are upper-cased before they enter a key, and some of them
     * carry producer-controlled text. {@code String.toUpperCase()} would apply the runtime's tables to that text.
     */
    public static String upper(String text) {
        if (text == null) {
            return null;
        }
        return upperPresent(text);
    }

    /**
     * {@link #upper} for a string the caller knows is present -- the same split, and for the same reason, as
     * {@link #foldPresent} against {@link #fold}: a nullable return propagates into the dataflow of every caller that
     * dereferences it one line later, where the null is unreachable but unprovable.
     */
    public static String upperPresent(String text) {
        StringBuilder uppered = null;
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (character >= 'a' && character <= 'z') {
                if (uppered == null) {
                    uppered = new StringBuilder(text);
                }
                uppered.setCharAt(index, (char) (character - 32));
            }
        }
        return uppered == null ? text : uppered.toString();
    }

    /**
     * Normalizes for table <em>lookup</em>: drops separators, then ASCII-folds case.
     *
     * <p>
     * Lookup-only. A value folded this way is matched against a table; it is the table's own spelling that enters a
     * key, never this. That is what lets {@code aes}, {@code AES} and {@code A-E-S} all resolve to the registry's
     * {@code AES} without any of those spellings being keyed.
     */
    public static String lookupKey(String text) {
        return text == null ? null : fold(LOOKUP_SEPARATORS.matcher(text).replaceAll(""));
    }

    public static boolean isAsciiPrintable(String text) {
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (character < 32 || character > 126) {
                return false;
            }
        }
        return true;
    }

    /** Strips leading and trailing whitespace as the reference defines it, not as the JDK defines it. */
    public static String strip(String text) {
        if (text == null) {
            return null;
        }
        return stripPresent(text);
    }

    /**
     * {@link #strip} for a string the caller knows is present -- the same split, and for the same reason, as
     * {@link #foldPresent} against {@link #fold}: a nullable return propagates into the dataflow of every caller that
     * dereferences it one line later, where the null is unreachable but unprovable.
     */
    public static String stripPresent(String text) {
        int start = 0;
        int end = text.length();
        while (start < end && isWhitespace(text.charAt(start))) {
            start++;
        }
        while (end > start && isWhitespace(text.charAt(end - 1))) {
            end--;
        }
        return text.substring(start, end);
    }

    /** Collapses every run of whitespace to a single space, by the same definition. */
    public static String collapseWhitespace(String text) {
        return text == null ? null : WHITESPACE_RUN.matcher(text).replaceAll(" ");
    }

    public static boolean isWhitespace(char character) {
        return PYTHON_WHITESPACE.indexOf(character) >= 0;
    }

    /** True when the value is absent or contains nothing but whitespace, by the same definition. */
    public static boolean isBlank(String text) {
        return text == null || strip(text).isEmpty();
    }

    /**
     * True when the value is a dot-separated run of ASCII digit groups carrying at least {@code minimumDots} dots --
     * the shape of an OID arc, and of a dotted protocol version.
     *
     * <p>
     * Scanned by hand rather than matched against {@code \d+(\.\d+)*}, which is the same grammar: a nested unbounded
     * repetition recurses inside Java's matcher, so a long enough input overflows the stack where this returns false.
     * Digits are ASCII-only here exactly as {@code \d} is ASCII-only by default, so no keyed value changes.
     */
    public static boolean isDottedDigits(String text, int minimumDots) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        int dots = 0;
        boolean digitRequired = true;
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (character >= '0' && character <= '9') {
                digitRequired = false;
            } else if (character == '.' && !digitRequired) {
                dots++;
                digitRequired = true;
            } else {
                return false;
            }
        }
        return !digitRequired && dots >= minimumDots;
    }
}
