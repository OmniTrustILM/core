package com.otilm.core.service.acme.identifier;

import com.otilm.api.model.core.acme.AcmeIdentifierMatchType;
import com.otilm.api.model.core.acme.AcmePreauthorizedIdentifierDto;
import com.otilm.api.model.core.acme.Identifier;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Whether an ACME profile's pre-authorization policy covers an ordered identifier, so the authorization for it can be
 * created valid and carry no challenge. Pure: the policy and the identifier in, a decision out.
 */
public final class AcmeIdentifierPolicy {

    private static final String DNS = "dns";
    private static final String IP = "ip";
    private static final String WILDCARD_PREFIX = "*.";

    private AcmeIdentifierPolicy() {
    }

    /** Whether any entry of the policy covers this identifier. */
    public static boolean covers(List<AcmePreauthorizedIdentifierDto> policy, Identifier identifier) {
        if (policy == null || policy.isEmpty() || identifier == null || identifier.getValue() == null) {
            return false;
        }
        return policy.stream().anyMatch(entry -> coveredBy(entry, identifier));
    }

    private static boolean coveredBy(AcmePreauthorizedIdentifierDto entry, Identifier identifier) {
        if (entry == null || entry.getValue() == null || entry.getMatchType() == null) {
            return false;
        }
        if (isIp(identifier)) {
            // RFC 8738 addresses have no hierarchy to descend, so only an exact entry can cover one, and the
            // comparison is on the address rather than on how it was written.
            return entry.getMatchType() == AcmeIdentifierMatchType.EXACT
                    && sameAddress(entry.getValue(), identifier.getValue());
        }
        String ordered = normalize(identifier.getValue());
        String pattern = normalize(entry.getValue());
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

    /** DNS names are compared case-insensitively, and a trailing root dot names the same host. */
    private static String normalize(String value) {
        String trimmed = value.trim().toLowerCase(Locale.ROOT);
        return trimmed.endsWith(".") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    private static boolean sameAddress(String pattern, String ordered) {
        byte[] left = addressBytes(pattern);
        return left != null && Arrays.equals(left, addressBytes(ordered));
    }

    /**
     * Parsed rather than compared as text, so the same address written two ways matches. Only literals are accepted: a
     * name would otherwise be resolved, letting DNS decide what a policy covers.
     */
    private static byte[] addressBytes(String value) {
        String literal = value.trim();
        if (!InetAddresses.isLiteral(literal)) {
            return null;
        }
        try {
            return InetAddress.getByName(literal).getAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /** Whether a string is an IP literal, without asking the resolver. */
    private static final class InetAddresses {

        private InetAddresses() {
        }

        static boolean isLiteral(String value) {
            if (value.isEmpty()) {
                return false;
            }
            char first = value.charAt(0);
            return Character.digit(first, 16) != -1 || first == ':';
        }
    }

    /** Whether the type is one the platform pre-authorizes at all. */
    public static boolean isSupportedType(Identifier identifier) {
        return identifier != null
                && (DNS.equalsIgnoreCase(identifier.getType()) || IP.equalsIgnoreCase(identifier.getType()));
    }
}
