package com.otilm.core.service.impl;

import com.otilm.api.model.core.auth.ProtectedResourceMetadataDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.security.authn.ProtectedResourceChallenge;
import com.otilm.core.security.authz.UnauthenticatedEndpoint;
import com.otilm.core.service.ProtectedResourceMetadataExternalService;
import com.otilm.core.settings.SettingsCache;
import java.util.Collection;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Serves the protected resource metadata to anonymous callers. It reads the settings cache, so a request costs no
 * database query, and an unpopulated cache yields a document that lists no authorization server.
 */
@Service
public class ProtectedResourceMetadataServiceImpl implements ProtectedResourceMetadataExternalService {

    @Override
    @UnauthenticatedEndpoint
    public ProtectedResourceMetadataDto getProtectedResourceMetadata() {
        String origin = ProtectedResourceChallenge.origin(ServletUriComponentsBuilder.fromCurrentContextPath());
        return ProtectedResourceMetadataBuilder
                .build(origin + ProtectedResourceChallenge.RESOURCE_PATH, configuredProviders());
    }

    private static Collection<OAuth2ProviderSettingsDto> configuredProviders() {
        AuthenticationSettingsDto settings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);
        if (settings == null || settings.getOAuth2Providers() == null) {
            return List.of();
        }
        return settings.getOAuth2Providers().values();
    }
}
