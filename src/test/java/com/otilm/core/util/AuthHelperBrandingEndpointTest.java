package com.otilm.core.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Pins how far the branding entry in the permit-all list reaches. The list is matched against every incoming request,
 * so a pattern that is one character too broad opens an authenticated surface anonymously, and nothing else in the
 * build would notice.
 */
class AuthHelperBrandingEndpointTest {

    private static final String NO_CONTEXT_PATH = "";

    @ParameterizedTest
    @ValueSource(strings = {"/v1/branding", "/v2/branding"})
    void theBrandingReadIsPermittedAnonymously(String uri) {
        Assertions.assertTrue(AuthHelper.permitAllEndpointInRequest(uri, NO_CONTEXT_PATH));
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
        Assertions.assertFalse(AuthHelper.permitAllEndpointInRequest(uri, NO_CONTEXT_PATH), uri);
    }
}
