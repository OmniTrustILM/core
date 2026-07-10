package com.otilm.core.integration.service;

import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.service.impl.OAuth2LoginServiceImpl;
import com.otilm.core.settings.SettingsCache;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@SpringBootTest
class OAuth2LoginServiceImplITest {

    @Autowired
    private OAuth2LoginServiceImpl service;

    @Autowired
    private SettingsCache settingsCache;

    @BeforeEach
    void setUp() {
        // Reset cache before each test
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());
    }

    @Test
    void testIsOAuth2ProviderValid_Success() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        Assertions.assertTrue(service.isOAuth2ProviderValid(settings));
    }

    @Test
    void testIsOAuth2ProviderValid_MissingClientId() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setClientId(null);
        Assertions.assertFalse(service.isOAuth2ProviderValid(settings));
    }

    @Test
    void testIsOAuth2ProviderValid_MissingClientSecret() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setClientSecret(null);
        Assertions.assertFalse(service.isOAuth2ProviderValid(settings));
    }

    @Test
    void testIsOAuth2ProviderValid_MissingAuthUrl() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setAuthorizationUrl(null);
        Assertions.assertFalse(service.isOAuth2ProviderValid(settings));
    }

    @Test
    void testIsOAuth2ProviderValid_MissingTokenUrl() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setTokenUrl(null);
        Assertions.assertFalse(service.isOAuth2ProviderValid(settings));
    }

    @Test
    void testIsOAuth2ProviderValid_MissingJwkSet() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setJwkSetUrl(null);
        settings.setJwkSet(null);
        Assertions.assertFalse(service.isOAuth2ProviderValid(settings));
    }

    @Test
    void testIsOAuth2ProviderValid_HasJwkSetContent() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setJwkSetUrl(null);
        settings.setJwkSet("{\"keys\":[]}");
        Assertions.assertTrue(service.isOAuth2ProviderValid(settings));
    }

    @Test
    void testIsOAuth2ProviderValid_MissingLogoutUrl() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setLogoutUrl(null);
        Assertions.assertFalse(service.isOAuth2ProviderValid(settings));
    }

    @Test
    void testIsOAuth2ProviderValid_MissingPostLogoutUrl() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setPostLogoutUrl(null);
        Assertions.assertFalse(service.isOAuth2ProviderValid(settings));
    }

    @Test
    void testGetValidOAuth2Providers() {
        AuthenticationSettingsDto authSettings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();

        providers.put("valid1", createValidProvider("valid1"));
        providers.put("valid2", createValidProvider("valid2"));

        OAuth2ProviderSettingsDto invalid = createValidProvider("invalid");
        invalid.setClientId(null);
        providers.put("invalid", invalid);

        authSettings.setOAuth2Providers(providers);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, authSettings);

        List<OAuth2ProviderSettingsDto> validProviders = service.getValidOAuth2Providers();
        Assertions.assertEquals(2, validProviders.size());
        Assertions.assertTrue(validProviders.stream().anyMatch(p -> p.getName().equals("valid1")));
        Assertions.assertTrue(validProviders.stream().anyMatch(p -> p.getName().equals("valid2")));
        Assertions.assertTrue(validProviders.stream().noneMatch(p -> p.getName().equals("invalid")));
    }

    @Test
    void testGetValidOAuth2Providers_Empty() {
        List<OAuth2ProviderSettingsDto> validProviders = service.getValidOAuth2Providers();
        Assertions.assertEquals(0, validProviders.size());
    }

    @Test
    void testGetOAuth2ProviderSettings_Success() {
        AuthenticationSettingsDto authSettings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        OAuth2ProviderSettingsDto expected = createValidProvider("test");
        providers.put("test", expected);
        authSettings.setOAuth2Providers(providers);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, authSettings);

        OAuth2ProviderSettingsDto actual = service.getOAuth2ProviderSettings("test");
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void testGetOAuth2ProviderSettings_NotFound() {
        OAuth2ProviderSettingsDto actual = service.getOAuth2ProviderSettings("unknown");
        Assertions.assertNull(actual);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/ui", "/ui/dashboard", "/ui?param=value", "/ui#fragment"})
    void testValidateAndNormalizeRedirect_Valid(String redirect) {
        String result = service.validateAndNormalizeRedirect(redirect);
        Assertions.assertEquals(redirect, result);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "http://malicious.com", "//malicious.com", "https://malicious.com", "malicious.com"})
    void testValidateAndNormalizeRedirect_Invalid(String redirect) {
        String result = service.validateAndNormalizeRedirect(redirect);
        Assertions.assertNull(result);
    }

    @Test
    void testValidateAndNormalizeRedirect_Null() {
        String result = service.validateAndNormalizeRedirect(null);
        Assertions.assertNull(result);
    }

    private OAuth2ProviderSettingsDto createValidProvider(String name) {
        OAuth2ProviderSettingsDto dto = new OAuth2ProviderSettingsDto();
        dto.setName(name);
        dto.setClientId("client-id");
        dto.setClientSecret("client-secret");
        dto.setAuthorizationUrl("http://auth-url");
        dto.setTokenUrl("http://token-url");
        dto.setJwkSetUrl("http://jwk-url");
        dto.setLogoutUrl("http://logout-url");
        dto.setPostLogoutUrl("http://post-logout-url");
        return dto;
    }
}
