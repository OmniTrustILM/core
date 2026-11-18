package com.otilm.core.service.impl;

import com.otilm.api.model.core.auth.ProtectedResourceAuthorizationServerDto;
import com.otilm.api.model.core.auth.ProtectedResourceMetadataDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ApplicationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProtectedResourceMetadataBuilderTest {

    private static final String RESOURCE = "https://ilm.example.com/api";

    @Test
    void listsNoAuthorizationServer_whenNoProviderIsEnabledForApplications() {
        // given
        var disabled = createProvider("a", "https://a.example.com", null);
        var explicitlyDisabled = createProvider("b", "https://b.example.com", createApplications(false));

        // when
        ProtectedResourceMetadataDto metadata = ProtectedResourceMetadataBuilder
                .build(RESOURCE, List.of(disabled, explicitlyDisabled));

        // then
        assertThat(metadata.getAuthorizationServers()).isEmpty();
        assertThat(metadata.getOtilmAuthorizationServers()).isEmpty();
        assertThat(metadata.getResource()).isEqualTo(RESOURCE);
        assertThat(metadata.getResourceName()).isEqualTo("OmniTrust ILM");
        assertThat(metadata.getBearerMethodsSupported()).containsExactly("header");
    }

    @Test
    void listsEnabledProvidersSortedByName_whenSeveralAreConfigured() {
        // given
        var second = createProvider("zeta", "https://zeta.example.com", createApplications(true));
        var skipped = createProvider("middle", "https://middle.example.com", createApplications(false));
        var first = createProvider("alpha", "https://alpha.example.com", createApplications(true));

        // when
        ProtectedResourceMetadataDto metadata = ProtectedResourceMetadataBuilder
                .build(RESOURCE, List.of(second, skipped, first));

        // then
        assertThat(metadata.getAuthorizationServers())
                .containsExactly("https://alpha.example.com", "https://zeta.example.com");
        assertThat(metadata.getOtilmAuthorizationServers())
                .extracting(server -> server.getIssuer())
                .containsExactly("https://alpha.example.com", "https://zeta.example.com");
    }

    @Test
    void fallsBackToProviderNameAndOmitsUnsetFields_whenApplicationsSetNothingElse() {
        // given
        var provider = createProvider("keycloak", "https://kc.example.com", createApplications(true));

        // when
        ProtectedResourceMetadataDto metadata = ProtectedResourceMetadataBuilder.build(RESOURCE, List.of(provider));

        // then
        ProtectedResourceAuthorizationServerDto server = metadata.getOtilmAuthorizationServers().getFirst();
        assertThat(server.getName()).isEqualTo("keycloak");
        assertThat(server.getClientId()).isNull();
        assertThat(server.getResource()).isNull();
        assertThat(server.getScopes()).isEmpty();
    }

    @Test
    void carriesApplicationSettingsOnly_whenTheyAreSet() {
        // given
        var applications = createApplications(true);
        applications.setName("Sign in with Keycloak");
        applications.setClientId("public-client");
        applications.setResource("https://ilm.example.com/api");
        applications.setScopes(List.of("openid", "profile"));
        var provider = createProvider("keycloak", "https://kc.example.com", applications);
        provider.setClientId("confidential-client");
        provider.setClientSecret("secret");

        // when
        ProtectedResourceMetadataDto metadata = ProtectedResourceMetadataBuilder.build(RESOURCE, List.of(provider));

        // then
        ProtectedResourceAuthorizationServerDto server = metadata.getOtilmAuthorizationServers().getFirst();
        assertThat(server.getName()).isEqualTo("Sign in with Keycloak");
        assertThat(server.getClientId()).isEqualTo("public-client");
        assertThat(server.getResource()).isEqualTo("https://ilm.example.com/api");
        assertThat(server.getScopes()).containsExactly("openid", "profile");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static OAuth2ProviderSettingsDto createProvider(String name, String issuerUrl,
            OAuth2ApplicationSettingsDto applications) {
        var provider = new OAuth2ProviderSettingsDto();
        provider.setName(name);
        provider.setIssuerUrl(issuerUrl);
        provider.setApplications(applications);
        return provider;
    }

    private static OAuth2ApplicationSettingsDto createApplications(boolean enabled) {
        var applications = new OAuth2ApplicationSettingsDto();
        applications.setEnabled(enabled);
        return applications;
    }
}
