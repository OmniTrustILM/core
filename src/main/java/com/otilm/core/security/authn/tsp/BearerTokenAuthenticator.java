package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.logging.records.DelegateRecord;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.auth.oauth2.AuthenticationSnapshotRequestHolder;
import com.otilm.core.auth.oauth2.PlatformJwtDecoder;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.settings.AuthenticationSettingsSnapshot;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.OAuth2Constants;
import com.otilm.core.util.OAuth2Util;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
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
        LoggingHelper.putDelegateInfo(null);
        String token = request.getHeader(HttpHeaders.AUTHORIZATION).substring(BEARER_PREFIX.length()).trim();
        try {
            Jwt jwt = jwtDecoder.decode(token);
            if (jwt == null) {
                return false;
            }
            AuthenticationSettingsSnapshot snapshot = validatedSnapshot();
            OAuth2ProviderSettingsDto provider = OAuth2Util
                    .findProviderByIssuer(snapshot.settings(),
                            jwt.getIssuer() == null ? null : jwt.getIssuer().toString());
            DelegateRecord delegate = OAuth2Util.resolveDelegate(provider, jwt.getClaims());
            LoggingHelper.putDelegateInfo(delegate);
            Map<String, Object> claims = new HashMap<>(jwt.getClaims());
            claims.put(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME, OAuth2Util.resolveUsername(provider, claims));
            AuthenticationInfo authInfo = authClient.authenticateByToken(claims, snapshot.generation());
            boolean authenticated = contextWriter.setFromAuthInfo(authInfo);
            if (authenticated) {
                LoggingHelper.putDelegateInfo(delegate);
            }
            return authenticated;
        } catch (RuntimeException e) {
            LoggingHelper.putDelegateInfo(null);
            log.warn("TSP authentication: bearer-token authentication failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Returns the snapshot the decoder validated the token against, so the username claim and the cache generation come
     * from the very provider configuration that accepted the token. Falls back to the current settings only when the
     * decoder published nothing.
     */
    private static AuthenticationSettingsSnapshot validatedSnapshot() {
        AuthenticationSettingsSnapshot published = AuthenticationSnapshotRequestHolder.get();
        return published != null ? published : SettingsCache.getAuthenticationSnapshot();
    }
}
