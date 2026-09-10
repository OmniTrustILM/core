package com.otilm.core.service.acme.identifier;

import com.otilm.api.model.core.acme.AcmeIdentifierMatchType;
import com.otilm.api.model.core.acme.AcmePreauthorizedIdentifierDto;
import com.otilm.api.model.core.acme.Identifier;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Whether an ACME profile's pre-authorization policy covers an ordered identifier, so the authorization for it can be
 * created valid and carry no challenge. Pure: the policy and the identifier in, a decision out, no I/O of any kind.
 *
 * <p>
 * Everything here fails closed. A value this class cannot parse with certainty — a malformed name, an address that is
 * not a literal, an identifier type it does not know — is not covered, because the alternative is issuing a certificate
 * for a name nobody proved control of.
 */
public final class AcmeIdentifierPolicy {

    private static final String DNS = "dns";
    private static final String IP = "ip";
    private static final String WILDCARD_PREFIX = "*.";

    /** A DNS label: letters, digits and inner hyphens, per the preferred name syntax of RFC 1035 section 2.3.1. */
    private static final Pattern LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");

    private static final Pattern IPV4 = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");

    /** The character set of an IPv6 literal, including a zone identifier. No hostname can match it. */
    private static final Pattern IPV6_SHAPED = Pattern
            .compile("[0-9A-Fa-f:.%\\p{Alnum}_-]*:[0-9A-Fa-f:.%\\p{Alnum}_-]*");

    private static final int MAX_NAME_LENGTH = 253;

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
     * RFC 8738 addresses have no hierarchy to descend, so only an exact entry can cover one. Both sides must parse as
     * literals: a name is never resolved, since that would let whoever controls DNS decide what a policy covers.
     */
    private static boolean coversAddress(AcmePreauthorizedIdentifierDto entry, String orderedValue) {
        if (entry.getMatchType() != AcmeIdentifierMatchType.EXACT) {
            return false;
        }
        byte[] ordered = addressBytes(orderedValue);
        byte[] pattern = addressBytes(entry.getValue());
        return ordered != null && pattern != null && Arrays.equals(ordered, pattern);
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
     * the same host and are folded away; anything else — whitespace, control characters, an empty or over-long label, a
     * stray asterisk — makes the value unusable rather than being quietly repaired, so that what is compared is always
     * what was submitted.
     */
    private static String normalizeName(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        String withoutRoot = lower.endsWith(".") ? lower.substring(0, lower.length() - 1) : lower;
        String bare = withoutRoot.startsWith(WILDCARD_PREFIX)
                ? withoutRoot.substring(WILDCARD_PREFIX.length())
                : withoutRoot;
        if (bare.isEmpty() || bare.length() > MAX_NAME_LENGTH) {
            return null;
        }
        for (String label : bare.split("\\.", -1)) {
            if (!LABEL.matcher(label).matches()) {
                return null;
            }
        }
        return withoutRoot;
    }

    /**
     * The bytes of an IP literal, or null when the value is not one. Nothing here consults the resolver: an IPv6
     * literal is recognised by a character set no hostname can have, and IPv4 is parsed digit by digit.
     */
    private static byte[] addressBytes(String value) {
        if (value.indexOf(':') >= 0) {
            return IPV6_SHAPED.matcher(value).matches() ? parseWithoutLookup(value) : null;
        }
        var matcher = IPV4.matcher(value);
        if (!matcher.matches()) {
            return null;
        }
        byte[] address = new byte[4];
        for (int group = 1; group <= 4; group++) {
            String octet = matcher.group(group);
            // Rejected rather than interpreted: a leading zero reads as octal to some parsers and decimal to others.
            if (octet.length() > 1 && octet.charAt(0) == '0') {
                return null;
            }
            int parsed = Integer.parseInt(octet);
            if (parsed > 255) {
                return null;
            }
            address[group - 1] = (byte) parsed;
        }
        return address;
    }

    /** Safe only for a value already known to be IPv6-shaped, which the resolver never treats as a hostname. */
    private static byte[] parseWithoutLookup(String literal) {
        try {
            return InetAddress.getByName(literal).getAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /** Whether the type is one the platform pre-authorizes at all. Anything else is not covered. */
    public static boolean isSupportedType(Identifier identifier) {
        return identifier != null
                && (DNS.equalsIgnoreCase(identifier.getType()) || IP.equalsIgnoreCase(identifier.getType()));
    }
}
