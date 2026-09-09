package com.otilm.core.cbom.client;

import java.util.List;
import java.util.Optional;

/**
 * Reads the {@code rel="next"} target out of RFC 8288 {@code Link} headers.
 *
 * <p>
 * Only what the cbom-repository feed needs: the target of the first link related as {@code next}. The header is walked
 * once by hand rather than matched by a regular expression -- both the quoted-string and the parameter-list grammar
 * repeat an alternation, and a backtracking engine implements group repetition by recursing once per repetition, so a
 * long header can exhaust the stack. A quoted value stays intact, so a {@code title="a, b"} on the same link does not
 * split it. Anything that is not a well-formed link is ignored rather than rejected; the caller decides what a missing
 * {@code next} means.
 */
final class LinkHeader {

    private LinkHeader() {
    }

    static Optional<String> nextTarget(List<String> headerValues) {
        if (headerValues == null) {
            return Optional.empty();
        }
        for (String headerValue : headerValues) {
            if (headerValue == null) {
                continue;
            }
            final Optional<String> target = nextTargetIn(headerValue);
            if (target.isPresent()) {
                return target;
            }
        }
        return Optional.empty();
    }

    private static Optional<String> nextTargetIn(String headerValue) {
        final LinkScanner scanner = new LinkScanner(headerValue);
        while (scanner.advanceToLink()) {
            final String target = scanner.readTarget();
            if (target == null) {
                // An unterminated '<': nothing well-formed can follow it.
                return Optional.empty();
            }
            if (scanner.parametersRelateAsNext()) {
                return Optional.of(target.trim());
            }
        }
        return Optional.empty();
    }

    /**
     * A position in one header line. Every method reads forward from it, so a header line is walked exactly once
     * however many links and parameters it carries, and no input can nest the reader.
     */
    private static final class LinkScanner {

        private static final String NEXT = "next";

        /** The token characters of RFC 7230, less the alphanumerics. */
        private static final String TOKEN_SYMBOLS = "!#$%&'*+.^_`|~-";

        private final String header;
        private int at;

        private LinkScanner(String header) {
            this.header = header;
        }

        /** Moves onto the next {@code '<'}, or reports that the rest of the header holds no link. */
        private boolean advanceToLink() {
            final int start = header.indexOf('<', at);
            if (start < 0) {
                at = header.length();
                return false;
            }
            at = start;
            return true;
        }

        /** The target of the link the scanner stands on, or null when its {@code '>'} is missing. */
        private String readTarget() {
            final int end = header.indexOf('>', at + 1);
            if (end < 0) {
                at = header.length();
                return null;
            }
            final String target = header.substring(at + 1, end);
            at = end + 1;
            return target;
        }

        /**
         * Reads this link's parameters and reports whether its first {@code rel} names {@code next}. The parameters are
         * read to the end of the link even once the answer is known: a quoted value may hold a {@code '<'} that would
         * otherwise be read as the start of a link.
         */
        private boolean parametersRelateAsNext() {
            boolean relSeen = false;
            boolean next = false;
            while (advanceToParameter()) {
                final String name = readName();
                final String value = readValue();
                if (!relSeen && "rel".equalsIgnoreCase(name)) {
                    relSeen = true;
                    next = namesNext(value);
                }
            }
            return next;
        }

        /**
         * Moves onto the name of the next parameter of the current link, or reports that the link ended: at the end of
         * the header, at the comma that opens the next link, or at text that is not a parameter list at all. The comma
         * is left where it is -- {@link #advanceToLink()} reads over it looking for the next target.
         */
        private boolean advanceToParameter() {
            skipWhitespace();
            if (at >= header.length() || header.charAt(at) != ';') {
                return false;
            }
            at++;
            skipWhitespace();
            return true;
        }

        /** A parameter name, empty when the position holds no token character. */
        private String readName() {
            final int start = at;
            while (at < header.length() && isTokenCharacter(header.charAt(at))) {
                at++;
            }
            return header.substring(start, at);
        }

        /** The value of the parameter just named, unquoted, or null when the parameter carries none. */
        private String readValue() {
            skipWhitespace();
            if (at >= header.length() || header.charAt(at) != '=') {
                return null;
            }
            at++;
            skipWhitespace();
            if (at < header.length() && header.charAt(at) == '"') {
                return readQuotedValue();
            }
            return readTokenValue();
        }

        /** A quoted value with its escapes resolved; an unterminated quote runs to the end of the header. */
        private String readQuotedValue() {
            at++;
            final StringBuilder value = new StringBuilder();
            while (at < header.length()) {
                final char character = header.charAt(at++);
                if (character == '"') {
                    break;
                }
                if (character == '\\' && at < header.length()) {
                    value.append(header.charAt(at++));
                } else {
                    value.append(character);
                }
            }
            return value.toString();
        }

        /** An unquoted value: everything up to the next parameter, link or space. */
        private String readTokenValue() {
            final int start = at;
            while (at < header.length() && !isValueBoundary(header.charAt(at))) {
                at++;
            }
            return header.substring(start, at);
        }

        private void skipWhitespace() {
            while (at < header.length() && Character.isWhitespace(header.charAt(at))) {
                at++;
            }
        }

        /**
         * Whether a {@code rel} value names {@code next}. The value is a space-separated list of relation types,
         * compared token by token so a {@code nextish} never matches.
         */
        private static boolean namesNext(String relValue) {
            if (relValue == null) {
                return false;
            }
            int at = 0;
            while (at < relValue.length()) {
                while (at < relValue.length() && Character.isWhitespace(relValue.charAt(at))) {
                    at++;
                }
                final int start = at;
                while (at < relValue.length() && !Character.isWhitespace(relValue.charAt(at))) {
                    at++;
                }
                if (at - start == NEXT.length() && relValue.regionMatches(true, start, NEXT, 0, NEXT.length())) {
                    return true;
                }
            }
            return false;
        }

        private static boolean isTokenCharacter(char character) {
            return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
                    || character >= '0' && character <= '9' || TOKEN_SYMBOLS.indexOf(character) >= 0;
        }

        private static boolean isValueBoundary(char character) {
            return character == ';' || character == ',' || Character.isWhitespace(character);
        }
    }
}
