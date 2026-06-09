package com.czertainly.core.auth.oauth2;

import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.SecretEncodingVersion;
import com.czertainly.core.util.SecretsUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class CzertainlyClientRegistrationRepository implements ClientRegistrationRepository {

    @Value("${server.port}")
    private String port;

    @Value("${server.servlet.context-path}")
    private String context;

    @Value("${server.ssl.enabled}")
    private boolean sslEnabled;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        OAuth2ProviderSettingsDto clientSettings = authenticationSettings.getOAuth2Providers().get(registrationId);
        return convertSettingsToClientRegistration(clientSettings, registrationId);
    }

    private ClientRegistration convertSettingsToClientRegistration(OAuth2ProviderSettingsDto clientSettings, String registrationId) {
        if (clientSettings == null) {
            return null;
        }
        Map<String, Object> configMetadata = new HashMap<>();
        configMetadata.put("end_session_endpoint", clientSettings.getLogoutUrl());
        configMetadata.put("post_logout_uri", clientSettings.getPostLogoutUrl());

        String protocol = sslEnabled ? "https" : "http";
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId(clientSettings.getClientId())
                .clientSecret(SecretsUtil.decodeAndDecryptSecretString(clientSettings.getClientSecret(), SecretEncodingVersion.V1))
                .authorizationGrantType(new AuthorizationGrantType("authorization_code"))
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(clientSettings.getScope())
                .authorizationUri(clientSettings.getAuthorizationUrl())
                .tokenUri(clientSettings.getTokenUrl())
                .jwkSetUri(clientSettings.getJwkSetUrl() != null ? clientSettings.getJwkSetUrl() : protocol + "://localhost:" + port + context + "/oauth2/" + registrationId + "/jwkSet")
                .providerConfigurationMetadata(configMetadata)
                .build();
    }

}
