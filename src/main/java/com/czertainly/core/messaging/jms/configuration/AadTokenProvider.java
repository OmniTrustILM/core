package com.czertainly.core.messaging.jms.configuration;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import jakarta.jms.Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.function.BiFunction;

/**
 * Token provider for Azure Active Directory (AAD) authentication with Azure ServiceBus.
 * <p>
 * This class implements the Qpid JMS PASSWORD_OVERRIDE extension mechanism to provide
 * OAuth2 tokens for AMQP connection authentication. It automatically handles token
 * caching and refresh before expiration.
 * <p>
 * The provider is called by Qpid JMS client on each connection attempt, including
 * reconnects after connection loss, ensuring fresh tokens are always used.
 */
public class AadTokenProvider implements BiFunction<Connection, URI, Object> {

    private static final Logger logger = LoggerFactory.getLogger(AadTokenProvider.class);

    private static final String SERVICEBUS_SCOPE = "https://servicebus.azure.net/.default";

    private final TokenCredential credential;
    private final int tokenRefreshBufferSeconds;
    private final int tokenGettingTimeout;
    private volatile String cachedToken;
    private volatile OffsetDateTime tokenExpiry;

    public AadTokenProvider(TokenCredential credential, int tokenRefreshBufferSeconds, int tokenGettingTimeoutSeconds) {
        this.credential = credential;
        this.tokenRefreshBufferSeconds = tokenRefreshBufferSeconds;
        this.tokenGettingTimeout = tokenGettingTimeoutSeconds;
    }

    @Override
    public Object apply(Connection connection, URI uri) {
        logger.debug("AAD PASSWORD_OVERRIDE called for URI: {}", uri);
        String token = getToken();
        logger.debug("Returning AAD token (length: {})", token.length());
        return token;
    }

    /**
     * Gets a valid OAuth2 token, refreshing it if necessary.
     * <p>
     * Token is refreshed if:
     * <ul>
     *   <li>No token has been obtained yet</li>
     *   <li>Token will expire within the configured refresh buffer period</li>
     * </ul>
     *
     * @return valid OAuth2 access token
     * @throws RuntimeException if token acquisition fails
     */
    public synchronized String getToken() {
        if (shouldRefreshToken()) {
            refreshToken();
        }
        return cachedToken;
    }

    private boolean shouldRefreshToken() {
        if (cachedToken == null || tokenExpiry == null) {
            return true;
        }
        return OffsetDateTime.now().plusSeconds(tokenRefreshBufferSeconds).isAfter(tokenExpiry);
    }

    private void refreshToken() {
        logger.debug("Refreshing AAD token for ServiceBus authentication");
        try {
            TokenRequestContext context = new TokenRequestContext().addScopes(SERVICEBUS_SCOPE);
            AccessToken accessToken = credential.getToken(context).block(Duration.ofSeconds(tokenGettingTimeout));
            if (accessToken == null) {
                throw new RuntimeException("Failed to acquire AAD token: null response");
            }

            this.cachedToken = accessToken.getToken();
            this.tokenExpiry = accessToken.getExpiresAt();

            logger.debug("AAD token refreshed successfully, expires at: {}", tokenExpiry);
        } catch (Exception e) {
            logger.error("Failed to refresh AAD token for ServiceBus (timeout: {}s)", tokenGettingTimeout, e);
            throw new RuntimeException("Failed to acquire AAD token for ServiceBus authentication", e);
        }
    }
}