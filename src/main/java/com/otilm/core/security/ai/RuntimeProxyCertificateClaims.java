package com.otilm.core.security.ai;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.UUID;

/** Certificate URI claims; the caller must separately verify TLS, workload state and authority. */
public record RuntimeProxyCertificateClaims(String cluster, String namespace, String serviceAccount, String podName,
        UUID podUid) {
    private static final String SCHEME = "ilm-runtime-proxy";
    private static final String INVALID = "Invalid runtime proxy certificate claims";

    public RuntimeProxyCertificateClaims {
        if (!label(cluster) || !label(namespace) || !subdomain(serviceAccount) || !subdomain(podName) || podUid == null
                || (podUid.getMostSignificantBits() == 0 && podUid.getLeastSignificantBits() == 0)) {
            throw new IllegalArgumentException(INVALID);
        }
    }

    public static Optional<RuntimeProxyCertificateClaims> parse(String encoded) {
        if (!visibleAscii(encoded)) {
            return Optional.empty();
        }
        try {
            URI parsed = new URI(encoded);
            if (!SCHEME.equals(parsed.getScheme()) || !label(parsed.getRawAuthority()) || parsed.getRawQuery() != null
                    || parsed.getRawFragment() != null) {
                return Optional.empty();
            }
            String[] path = parsed.getRawPath().split("/", -1);
            if (path.length != 9 || !path[0].isEmpty() || !"ns".equals(path[1]) || !"sa".equals(path[3])
                    || !"pod".equals(path[5]) || !"uid".equals(path[7])) {
                return Optional.empty();
            }
            UUID uid = UUID.fromString(path[8]);
            RuntimeProxyCertificateClaims claims = new RuntimeProxyCertificateClaims(parsed.getRawAuthority(), path[2],
                    path[4], path[6], uid);
            return claims.uri().equals(encoded) ? Optional.of(claims) : Optional.empty();
        } catch (URISyntaxException | IllegalArgumentException invalid) {
            return Optional.empty();
        }
    }

    public String uri() {
        return SCHEME + "://" + cluster + "/ns/" + namespace + "/sa/" + serviceAccount + "/pod/" + podName + "/uid/"
                + podUid;
    }

    private static boolean visibleAscii(String value) {
        if (value == null || value.isEmpty() || value.length() > 1024) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) < 0x21 || value.charAt(i) > 0x7e) {
                return false;
            }
        }
        return true;
    }

    private static boolean subdomain(String value) {
        if (value == null || value.isEmpty() || value.length() > 253) {
            return false;
        }
        for (String part : value.split("\\.", -1)) {
            if (!label(part)) {
                return false;
            }
        }
        return true;
    }

    private static boolean label(String value) {
        if (value == null || value.isEmpty() || value.length() > 63 || !alphanumeric(value.charAt(0))
                || !alphanumeric(value.charAt(value.length() - 1))) {
            return false;
        }
        for (int i = 1; i < value.length() - 1; i++) {
            char c = value.charAt(i);
            if (!alphanumeric(c) && c != '-') {
                return false;
            }
        }
        return true;
    }

    private static boolean alphanumeric(char value) {
        return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9');
    }
}
