package com.otilm.core.cbom.asset.identity;

import java.util.regex.Pattern;

/**
 * The part of a component name that survives a rescan, and the address-shaped runs that must never be read as sizes.
 *
 * <p>
 * Producer-generated identifiers must not enter identity: one producer names every secret-key asset
 * {@code key@<random UUIDv4>}, so keying on the raw name would rewrite every row on every scan. Stripping UUID-shaped
 * and long-hex tokens leaves {@code key@}, which is identical across scans and therefore contributes nothing -- exactly
 * the desired behaviour.
 *
 * <p>
 * What it does buy is distinctness where the name is the only real information left. A CRL and a CSR both arrive as
 * {@code type: "other"} with no id, no fingerprint and no value, and they merged on a shared occurrence location until
 * this token separated them.
 */
public final class ComponentNames {

    private static final Pattern UUID = Pattern
            .compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", Pattern.CASE_INSENSITIVE);

    /**
     * Thirty-two, not sixteen: a 16-hex-digit run is a plausible <em>meaningful</em> key identifier, and stripping it
     * collapsed {@code key-0123456789abcdef} and {@code key-fedcba9876543210} onto one token. Thirty-two keeps
     * UUID-without-dashes and digest-shaped runs in scope.
     */
    private static final Pattern LONG_HEX = Pattern.compile("(?<![0-9a-zA-Z])[0-9a-fA-F]{32,}(?![0-9a-zA-Z])");

    private static final Pattern OPAQUE_PORT = Pattern.compile(":\\d{2,5}(?!\\d)");

    /**
     * An IPv4 literal is an address, not four numbers: a certificate named {@code 192.168.56.10:636} keyed
     * {@code parameterSet: 192} with the rest spilling into the residue. Stripped before the port rule, so
     * {@code host:port} loses both halves.
     */
    private static final Pattern OPAQUE_IPV4 = Pattern.compile("(?<![0-9.])\\d{1,3}(?:\\.\\d{1,3}){3}(?![0-9.])");

    /** The one place a separator carries meaning: between two digits. */
    private static final Pattern DIGIT_JOINED_SEPARATOR = Pattern.compile("(?<=\\d)[^0-9a-zA-Z]+(?=\\d)");

    /** The placeholder that survives the punctuation sweep, standing in for a kept separator. */
    private static final String KEPT_SEPARATOR = "\0";

    private static final Pattern NON_ALPHANUMERIC = Pattern.compile("[^0-9a-zA-Z" + KEPT_SEPARATOR + "]+");

    private ComponentNames() {
    }

    /**
     * The stable name token: identifiers stripped, punctuation dropped except where it sits between two digits.
     *
     * <p>
     * Deleting all punctuation collapsed {@code key-12} and {@code key1-2}; replacing all of it churned
     * {@code PrivateKey} against {@code Private-Key}. An underscore is punctuation like any other, so
     * {@code Private_Key} and {@code Private-Key} must agree.
     */
    public static String stableToken(String name) {
        if (name == null || AsciiText.isBlank(name)) {
            return "";
        }
        String text = LONG_HEX.matcher(UUID.matcher(name).replaceAll("")).replaceAll("");
        text = DIGIT_JOINED_SEPARATOR.matcher(text).replaceAll(KEPT_SEPARATOR);
        text = NON_ALPHANUMERIC.matcher(text).replaceAll("");
        return AsciiText.fold(trimUnderscores(text.replace(KEPT_SEPARATOR, "_")));
    }

    /** Removes address-shaped runs before any digit in a name is read as a size. */
    public static String stripOpaqueTokens(String name) {
        String withoutUuids = UUID.matcher(name).replaceAll(" ");
        String withoutAddresses = OPAQUE_IPV4.matcher(withoutUuids).replaceAll(" ");
        return OPAQUE_PORT.matcher(withoutAddresses).replaceAll(" ");
    }

    private static String trimUnderscores(String text) {
        int start = 0;
        int end = text.length();
        while (start < end && text.charAt(start) == '_') {
            start++;
        }
        while (end > start && text.charAt(end - 1) == '_') {
            end--;
        }
        return text.substring(start, end);
    }
}
