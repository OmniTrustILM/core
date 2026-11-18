package com.otilm.core.security.authn;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * The {@code WWW-Authenticate} challenge of the main security chain. It points a client that was refused to the
 * metadata of the API (RFC 9728), where it finds the authorization servers that issue tokens for it.
 */
public final class ProtectedResourceChallenge {

    public static final String RESOURCE_PATH = "/api";

    public static final String METADATA_PATH = "/.well-known/oauth-protected-resource" + RESOURCE_PATH;

    /** {@code GET} of the metadata, which is public and answers whatever credentials the request carries. */
    public static final RequestMatcher METADATA_REQUEST = PathPatternRequestMatcher
            .withDefaults()
            .matcher(HttpMethod.GET, METADATA_PATH);

    private static final String BEARER = "Bearer";

    private static final String INVALID_TOKEN_DESCRIPTION = "The access token is invalid.";

    private static final BearerTokenAuthenticationEntryPoint BEARER_ENTRY_POINT = bearerEntryPoint();

    private ProtectedResourceChallenge() {
    }

    /** Scheme, host and port of the request, without the context path. */
    public static String origin(ServletUriComponentsBuilder contextPathBuilder) {
        return contextPathBuilder.replacePath(null).build().toUriString();
    }

    /**
     * Adds the metadata parameter to a challenge, keeping the parameters an existing Bearer challenge already carries.
     *
     * @param existingChallenge the challenge already produced for the response, or {@code null}
     */
    public static String headerValue(String metadataUrl, String existingChallenge) {
        String parameter = "resource_metadata=\"" + metadataUrl + "\"";
        if (existingChallenge == null || existingChallenge.isBlank() || BEARER.equals(existingChallenge)) {
            return BEARER + " " + parameter;
        }
        return existingChallenge + ", " + parameter;
    }

    public static void rejectWithChallenge(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        setChallenge(request, response);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    public static void rejectWithChallenge(HttpServletRequest request, HttpServletResponse response, String message)
            throws IOException {
        setChallenge(request, response);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
    }

    /**
     * Entry point for a bearer token that was refused. Spring's entry point writes the RFC 6750 error parameters only
     * for an OAuth2 refusal, so the platform's own refusals are reported as an invalid token with a fixed description
     * that reveals nothing about why. It also adds a {@code resource_metadata} parameter of its own, so it is told the
     * platform's metadata URL rather than appended to.
     */
    public static void commenceBearer(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) {
        AuthenticationException refusal = exception instanceof OAuth2AuthenticationException
                ? exception
                : new InvalidBearerTokenException(INVALID_TOKEN_DESCRIPTION, exception);
        BEARER_ENTRY_POINT.commence(request, response, refusal);
    }

    private static BearerTokenAuthenticationEntryPoint bearerEntryPoint() {
        BearerTokenAuthenticationEntryPoint entryPoint = new BearerTokenAuthenticationEntryPoint();
        entryPoint.setResourceMetadataParameterResolver(ProtectedResourceChallenge::metadataUrl);
        return entryPoint;
    }

    private static String metadataUrl(HttpServletRequest request) {
        return origin(ServletUriComponentsBuilder.fromContextPath(request)) + METADATA_PATH;
    }

    private static void setChallenge(HttpServletRequest request, HttpServletResponse response) {
        String metadataUrl = metadataUrl(request);
        String existing = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, headerValue(metadataUrl, existing));
    }
}
