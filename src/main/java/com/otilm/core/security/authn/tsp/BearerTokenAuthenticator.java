package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.auth.oauth2.PlatformJwtDecoder;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;

/** Authenticates a TSP request presenting an OAuth2 bearer token in the {@code Authorization} header. */
public class BearerTokenAuthenticator implements TspAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(BearerTokenAuthenticator.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final PlatformJwtDecoder jwtDecoder;
    private final PlatformAuthenticationClient authClient;
    private final TspSecurityContextWriter contextWriter;

    public BearerTokenAuthenticator(PlatformJwtDecoder jwtDecoder, PlatformAuthenticationClient authClient,
                                    TspSecurityContextWriter contextWriter) {
        this.jwtDecoder = jwtDecoder;
        this.authClient = authClient;
        this.contextWriter = contextWriter;
    }

    @Override
    public TspAuthenticationMethod method() {
        return TspAuthenticationMethod.BEARER_TOKEN;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        return authorization != null && authorization.startsWith(BEARER_PREFIX);
    }

    @Override
    public boolean authenticate(HttpServletRequest request, TspProfileModel profile) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION).substring(BEARER_PREFIX.length()).trim();
        try {
            Jwt jwt = jwtDecoder.decode(token);
            if (jwt == null) {
                return false;
            }
            AuthenticationInfo authInfo = authClient.authenticateByToken(jwt.getClaims());
            return contextWriter.setFromAuthInfo(authInfo);
        } catch (RuntimeException e) {
            log.warn("TSP authentication: bearer-token authentication failed: {}", e.getMessage());
            return false;
        }
    }
}
