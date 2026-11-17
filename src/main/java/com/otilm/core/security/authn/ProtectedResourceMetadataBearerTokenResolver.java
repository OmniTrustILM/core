package com.otilm.core.security.authn;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Resolves bearer tokens like Spring's default resolver, except for {@code GET} of the protected resource metadata,
 * which is public and must answer even when the client sends a token that would be refused.
 */
public class ProtectedResourceMetadataBearerTokenResolver implements BearerTokenResolver {

    private final RequestMatcher metadataRequest = PathPatternRequestMatcher
            .withDefaults()
            .matcher(HttpMethod.GET, ProtectedResourceChallenge.METADATA_PATH);

    private final BearerTokenResolver delegate = new DefaultBearerTokenResolver();

    @Override
    public String resolve(HttpServletRequest request) {
        if (metadataRequest.matches(request)) {
            return null;
        }
        return delegate.resolve(request);
    }
}
