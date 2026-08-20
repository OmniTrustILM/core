package com.otilm.core.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;

/**
 * Pins how far the branding entry in the permit-all list reaches. The list is matched against every incoming request,
 * so a pattern that is one character too broad opens an authenticated surface anonymously, and nothing else in the
 * build would notice.
 */
class AuthHelperBrandingEndpointTest {

    private static final String NO_CONTEXT_PATH = "";

    private static final String GET = HttpMethod.GET.name();

    @ParameterizedTest
    @ValueSource(strings = {"/v1/branding", "/v2/branding"})
    void theBrandingReadIsPermittedAnonymously(String uri) {
        Assertions.assertTrue(AuthHelper.permitAllEndpointInRequest(uri, GET, NO_CONTEXT_PATH));
    }

    /**
     * The settings surface branding is stored in stays authenticated, and the pattern must not spill onto a
     * neighbouring path that merely starts the same way.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "/v1/settings/platform",
            "/v1/settings/platform/branding",
            "/v1/branding/logo",
            "/v1/brandings",
            "/v1/certificates"})
    void nothingBeyondTheBrandingReadIsOpenedUp(String uri) {
        Assertions.assertFalse(AuthHelper.permitAllEndpointInRequest(uri, GET, NO_CONTEXT_PATH), uri);
    }

    /**
     * Only the read is anonymous. A write against the same path has to reach the authenticated branch, so that the
     * refusal comes from the security chain and does not depend on the handler mapping registering no such method.
     */
    @ParameterizedTest
    @ValueSource(strings = {"POST", "PUT", "PATCH", "DELETE"})
    void aWriteAgainstTheBrandingPathIsNotPermittedAnonymously(String method) {
        Assertions.assertFalse(AuthHelper.permitAllEndpointInRequest("/v1/branding", method, NO_CONTEXT_PATH), method);
    }

    /** The endpoints that were open before branding stay open for every method, branding's entry aside. */
    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST", "PUT", "DELETE"})
    void theMethodAgnosticEntriesAreUnaffected(String method) {
        Assertions.assertTrue(AuthHelper.permitAllEndpointInRequest("/v1/health/ready", method, NO_CONTEXT_PATH));
        Assertions.assertTrue(AuthHelper.permitAllEndpointInRequest("/v1/connector/register", method, NO_CONTEXT_PATH));
    }
}
