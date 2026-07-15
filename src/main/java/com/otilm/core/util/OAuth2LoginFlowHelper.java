package com.otilm.core.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

public final class OAuth2LoginFlowHelper {

    private OAuth2LoginFlowHelper() {
        // Utility class.
    }

    public static String getSessionAccessToken(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        if (session.getAttribute(OAuth2Constants.ACCESS_TOKEN_SESSION_ATTRIBUTE)
                instanceof OAuth2AccessToken oauth2AccessToken) {
            return oauth2AccessToken.getTokenValue();
        }
        return null;
    }
}
