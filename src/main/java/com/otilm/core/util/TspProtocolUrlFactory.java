package com.otilm.core.util;

/**
 * Composes the externally-reachable TSP protocol URLs that are surfaced to operators in profile DTOs.
 * <p>
 * The request-derived base (scheme, host, context path) is supplied by the web layer — these methods perform pure
 * string composition and hold no dependency on the current request, so they are safe to call from anywhere and
 * straightforward to unit-test.
 */
public final class TspProtocolUrlFactory {

    private static final String TSP_PROTOCOL_BASE_PATH = "/v1/protocols/tsp";

    private TspProtocolUrlFactory() {
    }

    /**
     * Endpoint a client posts timestamp requests to for a given TSP profile.
     */
    public static String forTspProfile(String baseUrl, String tspProfileName) {
        return baseUrl + TSP_PROTOCOL_BASE_PATH + "/" + tspProfileName;
    }

    /**
     * Endpoint a client posts timestamp requests to for a TSP-activated signing profile.
     */
    public static String forSigningProfile(String baseUrl, String signingProfileName) {
        return baseUrl + TSP_PROTOCOL_BASE_PATH + "/signingProfiles/" + signingProfileName;
    }
}
