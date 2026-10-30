package com.otilm.core.util;

/** Escapes line separators in text used to identify objects in diagnostic messages. */
public final class IdentifierStringUtils {

    private IdentifierStringUtils() {
    }

    /**
     * Replaces carriage return, line feed, vertical tab, form feed, next line, and Unicode line and paragraph
     * separators with visible backslash escapes. Other characters are preserved; this is not a general-purpose encoder
     * for JSON, HTML, or terminal control sequences.
     *
     * @param value non-null text to escape
     * @return text with no literal line separators
     * @throws NullPointerException if {@code value} is null
     */
    public static String escapeLineBreaks(String value) {
        return value
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\u000B", "\\u000B")
                .replace("\f", "\\f")
                .replace("\u0085", "\\u0085")
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029");
    }
}
