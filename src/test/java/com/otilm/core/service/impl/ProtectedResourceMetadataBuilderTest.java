package com.otilm.core.service.impl;

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
        var disabled = provider("a", "https://a.example.com", null);
        var explicitlyDisabled = provider("b", "https://b.example.com", applications(false));

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
        var second = provider("zeta", "https://zeta.example.com", applications(true));
        var skipped = provider("middle", "https://middle.example.com", applications(false));
        var first = provider("alpha", "https://alpha.example.com", applications(true));

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
        var provider = provider("keycloak", "https://kc.example.com", applications(true));

        // when
        ProtectedResourceMetadataDto metadata = ProtectedResourceMetadataBuilder.build(RESOURCE, List.of(provider));

        // then
        var server = metadata.getOtilmAuthorizationServers().getFirst();
        assertThat(server.getName()).isEqualTo("keycloak");
        assertThat(server.getClientId()).isNull();
        assertThat(server.getResource()).isNull();
        assertThat(server.getScopes()).isEmpty();
    }

    @Test
    void carriesApplicationSettingsOnly_whenTheyAreSet() {
        // given
        var applications = applications(true);
        applications.setName("Sign in with Keycloak");
        applications.setClientId("public-client");
        applications.setResource("https://ilm.example.com/api");
        applications.setScopes(List.of("openid", "profile"));
        var provider = provider("keycloak", "https://kc.example.com", applications);
        provider.setClientId("confidential-client");
        provider.setClientSecret("secret");

        // when
        ProtectedResourceMetadataDto metadata = ProtectedResourceMetadataBuilder.build(RESOURCE, List.of(provider));

        // then
        var server = metadata.getOtilmAuthorizationServers().getFirst();
        assertThat(server.getName()).isEqualTo("Sign in with Keycloak");
        assertThat(server.getClientId()).isEqualTo("public-client");
        assertThat(server.getResource()).isEqualTo("https://ilm.example.com/api");
        assertThat(server.getScopes()).containsExactly("openid", "profile");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static OAuth2ProviderSettingsDto provider(String name, String issuerUrl,
            OAuth2ApplicationSettingsDto applications) {
        var provider = new OAuth2ProviderSettingsDto();
        provider.setName(name);
        provider.setIssuerUrl(issuerUrl);
        provider.setApplications(applications);
        return provider;
    }

    private static OAuth2ApplicationSettingsDto applications(boolean enabled) {
        var applications = new OAuth2ApplicationSettingsDto();
        applications.setEnabled(enabled);
        return applications;
    }
}
