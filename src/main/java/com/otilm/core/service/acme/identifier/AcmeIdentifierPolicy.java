package com.otilm.core.service.acme.identifier;

import com.otilm.api.model.core.acme.AcmeIdentifierMatchType;
import com.otilm.api.model.core.acme.AcmePreauthorizedIdentifierDto;
import com.otilm.api.model.core.acme.Identifier;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Whether an ACME profile's pre-authorization policy covers an ordered identifier, so the authorization for it can be
 * created valid and carry no challenge.
 *
 * <p>
 * Pure by construction. Addresses are parsed here rather than handed to {@code InetAddress}, because any API that can
 * fall back to name resolution would let whoever controls DNS decide what a policy covers; nothing in this class
 * performs I/O of any kind.
 *
 * <p>
 * Everything fails closed. A value that cannot be parsed with certainty — a malformed name, an address that is not a
 * literal, a non-ASCII character, an identifier type it does not know — is not covered, because the alternative is
 * issuing a certificate for a name nobody proved control of.
 */
public final class AcmeIdentifierPolicy {

    private static final String DNS = "dns";
    private static final String IP = "ip";
    private static final String WILDCARD_PREFIX = "*.";

    /** A DNS label: letters, digits and inner hyphens, per the preferred name syntax of RFC 1035 section 2.3.1. */
    private static final Pattern LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");

    private static final Pattern IPV4 = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");

    private static final Pattern HEXTET = Pattern.compile("[0-9A-Fa-f]{1,4}");

    private static final int MAX_NAME_LENGTH = 253;
    private static final int IPV6_BYTES = 16;

    private AcmeIdentifierPolicy() {
    }

    /** Whether any entry of the policy covers this identifier. */
    public static boolean covers(List<AcmePreauthorizedIdentifierDto> policy, Identifier identifier) {
        if (policy == null || policy.isEmpty() || !isSupportedType(identifier) || identifier.getValue() == null) {
            return false;
        }
        return policy.stream().anyMatch(entry -> coveredBy(entry, identifier));
    }

    private static boolean coveredBy(AcmePreauthorizedIdentifierDto entry, Identifier identifier) {
        if (entry == null || entry.getValue() == null || entry.getMatchType() == null) {
            return false;
        }
        return isIp(identifier)
                ? coversAddress(entry, identifier.getValue())
                : coversName(entry, identifier.getValue());
    }

    /**
     * RFC 8738 addresses have no hierarchy to descend, so only an exact entry can cover one, and both sides must parse
     * as literals.
     */
    private static boolean coversAddress(AcmePreauthorizedIdentifierDto entry, String orderedValue) {
        if (entry.getMatchType() != AcmeIdentifierMatchType.EXACT) {
            return false;
        }
        Optional<byte[]> ordered = addressBytes(orderedValue);
        Optional<byte[]> pattern = addressBytes(entry.getValue());
        return ordered.isPresent() && pattern.isPresent() && Arrays.equals(ordered.get(), pattern.get());
    }

    private static boolean coversName(AcmePreauthorizedIdentifierDto entry, String orderedValue) {
        String pattern = normalizeName(entry.getValue());
        if (pattern == null || pattern.startsWith(WILDCARD_PREFIX)) {
            // An entry is a name, never a pattern: the match type is what widens it.
            return false;
        }
        String ordered = normalizeName(orderedValue);
        if (ordered == null) {
            return false;
        }
        if (ordered.startsWith(WILDCARD_PREFIX)) {
            return coversWildcard(entry, ordered.substring(WILDCARD_PREFIX.length()), pattern);
        }
        return entry.getMatchType() == AcmeIdentifierMatchType.EXACT
                ? ordered.equals(pattern)
                : isDescendantOf(ordered, pattern);
    }

    /**
     * A wildcard identifier stands for every name one label under {@code parent}, so an entry covers it only when the
     * entry already covers all of them. An exact entry never does: it covers a single name. A subdomain entry does when
     * the parent is the entry's own name or sits below it, since everything a label under such a parent is a descendant
     * of the entry.
     */
    private static boolean coversWildcard(AcmePreauthorizedIdentifierDto entry, String parent, String pattern) {
        return entry.isAllowWildcard() && entry.getMatchType() == AcmeIdentifierMatchType.SUBDOMAIN
                && (parent.equals(pattern) || isDescendantOf(parent, pattern));
    }

    /** Below the name at any depth, and not the name itself: covering both takes two entries. */
    private static boolean isDescendantOf(String candidate, String ancestor) {
        return candidate.length() > ancestor.length() + 1 && candidate.endsWith("." + ancestor);
    }

    private static boolean isIp(Identifier identifier) {
        return IP.equalsIgnoreCase(identifier.getType());
    }

    /**
     * The comparable form of a DNS name, or null when the value is not one. Case and a single trailing root dot name
     * the same host and are folded away; anything else is refused rather than quietly repaired, so what is compared is
     * always what was submitted. Non-ASCII is refused before case folding, because U+212A KELVIN SIGN lowercases to an
     * ASCII {@code k} and would otherwise pass as a name the policy never listed.
     */
    private static String normalizeName(String value) {
        if (!isAscii(value)) {
            return null;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        String withoutRoot = lower.endsWith(".") ? lower.substring(0, lower.length() - 1) : lower;
        if (withoutRoot.isEmpty() || withoutRoot.length() > MAX_NAME_LENGTH) {
            return null;
        }
        String bare = withoutRoot.startsWith(WILDCARD_PREFIX)
                ? withoutRoot.substring(WILDCARD_PREFIX.length())
                : withoutRoot;
        if (bare.isEmpty()) {
            return null;
        }
        for (String label : bare.split("\\.", -1)) {
            if (!LABEL.matcher(label).matches()) {
                return null;
            }
        }
        return withoutRoot;
    }

    private static boolean isAscii(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) > 0x7F) {
                return false;
            }
        }
        return true;
    }

    /** The bytes of an IP literal, or empty when the value is not one. */
    private static Optional<byte[]> addressBytes(String value) {
        return value.indexOf(':') >= 0 ? ipv6Bytes(value) : ipv4Bytes(value);
    }

    private static Optional<byte[]> ipv4Bytes(String value) {
        var matcher = IPV4.matcher(value);
        if (!matcher.matches()) {
            return Optional.empty();
        }
        byte[] address = new byte[4];
        for (int group = 1; group <= 4; group++) {
            String octet = matcher.group(group);
            // Refused rather than interpreted: a leading zero reads as octal to some parsers and decimal to others.
            if (octet.length() > 1 && octet.charAt(0) == '0') {
                return Optional.empty();
            }
            int parsed = Integer.parseInt(octet);
            if (parsed > 255) {
                return Optional.empty();
            }
            address[group - 1] = (byte) parsed;
        }
        return Optional.of(address);
    }

    /**
     * RFC 4291 section 2.2, with the dotted-quad tail of form 3 and at most one {@code ::}. A zone identifier is
     * refused: it names a local interface rather than a distinguishable address, and resolving what it means would take
     * a look at the host's own interfaces.
     */
    private static Optional<byte[]> ipv6Bytes(String value) {
        if (value.indexOf('%') >= 0 || value.indexOf("::") != value.lastIndexOf("::")) {
            return Optional.empty();
        }
        int compression = value.indexOf("::");
        Optional<byte[]> head = hextets(compression < 0 ? value : value.substring(0, compression));
        Optional<byte[]> tail = hextets(compression < 0 ? "" : value.substring(compression + 2));
        if (head.isEmpty() || tail.isEmpty()) {
            return Optional.empty();
        }
        byte[] left = head.get();
        byte[] right = tail.get();
        if (compression < 0) {
            return left.length == IPV6_BYTES ? Optional.of(left) : Optional.empty();
        }
        // The elision must stand for at least one group, or the address would be writable without it.
        if (left.length + right.length >= IPV6_BYTES) {
            return Optional.empty();
        }
        byte[] address = new byte[IPV6_BYTES];
        System.arraycopy(left, 0, address, 0, left.length);
        System.arraycopy(right, 0, address, IPV6_BYTES - right.length, right.length);
        return Optional.of(address);
    }

    /** One colon-separated run of hextets, optionally ending in a dotted quad. Empty text is an empty run. */
    private static Optional<byte[]> hextets(String text) {
        if (text.isEmpty()) {
            return Optional.of(new byte[0]);
        }
        String[] parts = text.split(":", -1);
        byte[] bytes = new byte[0];
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (part.indexOf('.') >= 0) {
                if (i != parts.length - 1) {
                    return Optional.empty();
                }
                Optional<byte[]> quad = ipv4Bytes(part);
                if (quad.isEmpty()) {
                    return Optional.empty();
                }
                bytes = concat(bytes, quad.get());
                continue;
            }
            if (!HEXTET.matcher(part).matches()) {
                return Optional.empty();
            }
            int parsed = Integer.parseInt(part, 16);
            bytes = concat(bytes, new byte[]{(byte) (parsed >> 8), (byte) parsed});
        }
        return bytes.length > IPV6_BYTES ? Optional.empty() : Optional.of(bytes);
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] joined = Arrays.copyOf(left, left.length + right.length);
        System.arraycopy(right, 0, joined, left.length, right.length);
        return joined;
    }

    /** Whether the type is one the platform pre-authorizes at all. Anything else is not covered. */
    public static boolean isSupportedType(Identifier identifier) {
        return identifier != null
                && (DNS.equalsIgnoreCase(identifier.getType()) || IP.equalsIgnoreCase(identifier.getType()));
    }
}
