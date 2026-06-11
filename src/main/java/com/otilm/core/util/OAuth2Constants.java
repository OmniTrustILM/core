package com.otilm.core.util;

public final class OAuth2Constants {

    private OAuth2Constants() {
    }

    public static final String TOKEN_USERNAME_CLAIM_NAME = "username";
    public static final String TOKEN_AUTHENTICATION_HEADER = "Token-Authentication";
    public static final String REDIRECT_URL_SESSION_ATTRIBUTE = "REDIRECT_URL";
    public static final String SERVLET_CONTEXT_SESSION_ATTRIBUTE = "SERVLET_CONTEXT";
    public static final String ACCESS_TOKEN_SESSION_ATTRIBUTE = "ACCESS_TOKEN";
    public static final String REFRESH_TOKEN_SESSION_ATTRIBUTE = "REFRESH_TOKEN";

    public static final String INTERNAL_OAUTH2_PROVIDER_RESERVED_NAME = "internal";
}
