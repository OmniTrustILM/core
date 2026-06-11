package com.otilm.core.config;

import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.util.OAuth2Constants;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;

@Configuration
public class OAuth2Config {
    @Bean
    public OAuth2AuthorizedClientProvider oAuth2AuthorizedClientProvider() {
        RestClientRefreshTokenTokenResponseClient refreshTokenTokenResponseClient = new RestClientRefreshTokenTokenResponseClient();
        refreshTokenTokenResponseClient.addHeadersConverter(
                this::convertProxyHeaders
        );

        return OAuth2AuthorizedClientProviderBuilder.builder()
                .refreshToken(configure -> configure.accessTokenResponseClient(refreshTokenTokenResponseClient))
                .build();
    }

    private HttpHeaders convertProxyHeaders(AbstractOAuth2AuthorizationGrantRequest grantRequest) {
        HttpHeaders headers = new HttpHeaders();
        ClientRegistration clientRegistration = grantRequest.getClientRegistration();
        if (clientRegistration.getRegistrationId().equals(OAuth2Constants.INTERNAL_OAUTH2_PROVIDER_RESERVED_NAME)) {
            URI issuerUrl;
            try {
                String issuerUrlString = SignedJWT.parse(((OAuth2RefreshTokenGrantRequest) grantRequest).getAccessToken().getTokenValue()).getJWTClaimsSet().getIssuer();
                issuerUrl = new URI(issuerUrlString);
            } catch (URISyntaxException | ParseException e) {
                throw new PlatformAuthenticationException("Could not parse issuer URL in token: " + e.getMessage());
            }
            headers.set("X-Forwarded-Host", issuerUrl.getHost());
            if (issuerUrl.getPort() > 0) headers.set("X-Forwarded-Port", String.valueOf(issuerUrl.getPort()));
            headers.set("X-Forwarded-Proto", issuerUrl.getScheme());
        }
        return headers;
    }

}
