package com.otilm.core.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

public final class OAuth2LoginFlowHelper {

    private OAuth2LoginFlowHelper() {
        // Utility class.
    }

    public static String getSessionAccessToken(HttpServletRequest request) {
        try {
            OAuth2AccessToken oauth2AccessToken = (OAuth2AccessToken) request.getSession(false).getAttribute(OAuth2Constants.ACCESS_TOKEN_SESSION_ATTRIBUTE);
            return oauth2AccessToken.getTokenValue();
        } catch (NullPointerException e) {
            return null;
        }
    }
}
