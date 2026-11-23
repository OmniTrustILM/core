package com.otilm.core.service.impl;

import com.otilm.api.model.core.auth.ProtectedResourceAuthorizationServerDto;
import com.otilm.api.model.core.auth.ProtectedResourceMetadataDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ApplicationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

/**
 * Assembles the protected resource metadata field by field, so that nothing else held by the provider settings, such as
 * the client secret, can reach an anonymous caller.
 */
final class ProtectedResourceMetadataBuilder {

    static final String RESOURCE_NAME = "OmniTrust ILM";

    private static final String BEARER_METHOD_HEADER = "header";

    private ProtectedResourceMetadataBuilder() {
    }

    /**
     * @param resource the identifier of the API, as the client addresses it
     * @param providers all configured providers; only those enabled for applications are listed, sorted by name
     */
    static ProtectedResourceMetadataDto build(String resource, Collection<OAuth2ProviderSettingsDto> providers) {
        List<OAuth2ProviderSettingsDto> enabledProviders = providers
                .stream()
                .filter(provider -> provider.getApplications() != null && provider.getApplications().isEnabled())
                .sorted(Comparator
                        .comparing(OAuth2ProviderSettingsDto::getName, Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();

        ProtectedResourceMetadataDto metadata = new ProtectedResourceMetadataDto();
        metadata.setResource(resource);
        metadata.setResourceName(RESOURCE_NAME);
        metadata.setBearerMethodsSupported(List.of(BEARER_METHOD_HEADER));
        metadata
                .setAuthorizationServers(
                        enabledProviders.stream().map(OAuth2ProviderSettingsDto::getIssuerUrl).toList());
        metadata
                .setOtilmAuthorizationServers(enabledProviders
                        .stream()
                        .map(ProtectedResourceMetadataBuilder::toAuthorizationServer)
                        .toList());
        return metadata;
    }

    private static ProtectedResourceAuthorizationServerDto toAuthorizationServer(OAuth2ProviderSettingsDto provider) {
        OAuth2ApplicationSettingsDto applications = provider.getApplications();
        ProtectedResourceAuthorizationServerDto server = new ProtectedResourceAuthorizationServerDto();
        server.setIssuer(provider.getIssuerUrl());
        server.setName(applications.getName() != null ? applications.getName() : provider.getName());
        server.setClientId(applications.getClientId());
        server.setResource(applications.getResource());
        List<String> scopes = applications.getScopes() == null ? List.of() : applications.getScopes();
        server.setScopes(new ArrayList<>(scopes));
        return server;
    }
}
