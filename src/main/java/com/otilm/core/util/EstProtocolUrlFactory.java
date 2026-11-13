package com.otilm.core.util;

import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Composes the externally-reachable EST URLs that are surfaced to operators in profile DTOs.
 * <p>
 * {@link #currentOrigin()} reads the request being served and is the only method that depends on it; {@link #forLabel}
 * is pure string composition on the origin it is given, so it is safe to call from anywhere and straightforward to
 * unit-test. EST clients find the service under {@code /.well-known/est} of the origin, so the URLs carry no context
 * path.
 */
public final class EstProtocolUrlFactory {

    private static final String EST_WELL_KNOWN_PATH = "/.well-known/est";

    private EstProtocolUrlFactory() {
    }

    /**
     * Scheme, host and port of the request being served, without its context path.
     */
    public static String currentOrigin() {
        return ServletUriComponentsBuilder.fromCurrentContextPath().replacePath(null).build().toUriString();
    }

    /**
     * URL EST clients use for a label; they append the operation, such as {@code cacerts} or {@code simpleenroll}.
     */
    public static String forLabel(String origin, String label) {
        return origin + EST_WELL_KNOWN_PATH + "/" + label;
    }
}
