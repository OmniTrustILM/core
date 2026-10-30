package com.otilm.core.settings;

import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SettingsCacheTest {

    private final SettingsCache settingsCache = new SettingsCache();

    // Static cache state survives across tests: every test seeds settings under a unique provider
    // name so its first cacheSettings call is always a change, regardless of execution order.
    private static AuthenticationSettingsDto settingsWithProvider(String name, String usernameClaim) {
        OAuth2ProviderSettingsDto provider = new OAuth2ProviderSettingsDto();
        provider.setName(name);
        provider.setUsernameClaim(usernameClaim);
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        settings.setOAuth2Providers(Map.of(name, provider));
        return settings;
    }

    private static String uniqueName() {
        return "provider-" + UUID.randomUUID();
    }

    @Test
    void changedAuthenticationSettings_bumpGeneration() {
        String name = uniqueName();
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settingsWithProvider(name, "username"));
        long afterFirst = SettingsCache.getAuthenticationSnapshot().generation();

        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settingsWithProvider(name, "preferred_username"));
        assertEquals(afterFirst + 1, SettingsCache.getAuthenticationSnapshot().generation());
    }

    @Test
    void equalAuthenticationSettings_keepGeneration() {
        String name = uniqueName();
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settingsWithProvider(name, "username"));
        long generation = SettingsCache.getAuthenticationSnapshot().generation();

        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settingsWithProvider(name, "username"));
        assertEquals(generation, SettingsCache.getAuthenticationSnapshot().generation());
    }

    @Test
    void snapshotIsTheAuthoritativeStoreForAuthenticationSection() {
        AuthenticationSettingsDto settings = settingsWithProvider(uniqueName(), "username");
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settings);
        assertEquals(settings, SettingsCache.getAuthenticationSnapshot().settings());
        assertEquals(settings, SettingsCache.getSettings(SettingsSection.AUTHENTICATION));
    }
}
