package com.otilm.core.service;

import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.impl.OAuth2LoginServiceImpl;
import com.otilm.core.settings.SettingsCache;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SpringBootTest
class OAuth2LoginServiceImplTest {

    @Autowired
    private OAuth2LoginServiceImpl service;

    @Autowired
    private SettingsCache settingsCache;

    @MockitoBean
    private AuditLogInternalService auditLogService;

    @MockitoBean
    private AuditLogExternalService auditLogExternalService;

    @BeforeEach
    void setUp() {
        // Reset cache before each test
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());
    }

    @Test
    void testProviderValid_Success() {
        Assertions.assertTrue(isConsideredValid(createValidProvider("test")));
    }

    @Test
    void testProviderValid_MissingClientId() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setClientId(null);
        Assertions.assertFalse(isConsideredValid(settings));
    }

    @Test
    void testProviderValid_MissingClientSecret() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setClientSecret(null);
        Assertions.assertFalse(isConsideredValid(settings));
    }

    @Test
    void testProviderValid_MissingAuthUrl() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setAuthorizationUrl(null);
        Assertions.assertFalse(isConsideredValid(settings));
    }

    @Test
    void testProviderValid_MissingTokenUrl() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setTokenUrl(null);
        Assertions.assertFalse(isConsideredValid(settings));
    }

    @Test
    void testProviderValid_MissingJwkSet() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setJwkSetUrl(null);
        settings.setJwkSet(null);
        Assertions.assertFalse(isConsideredValid(settings));
    }

    @Test
    void testProviderValid_HasJwkSetContent() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setJwkSetUrl(null);
        settings.setJwkSet("{\"keys\":[]}");
        Assertions.assertTrue(isConsideredValid(settings));
    }

    @Test
    void testProviderValid_MissingLogoutUrl() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setLogoutUrl(null);
        Assertions.assertFalse(isConsideredValid(settings));
    }

    @Test
    void testProviderValid_MissingPostLogoutUrl() {
        OAuth2ProviderSettingsDto settings = createValidProvider("test");
        settings.setPostLogoutUrl(null);
        Assertions.assertFalse(isConsideredValid(settings));
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
    void testResolveProviderOrThrow_Success() {
        OAuth2ProviderSettingsDto expected = createValidProvider("test");
        cacheProviders(Map.of("test", expected));

        OAuth2ProviderSettingsDto actual = service.resolveProviderOrThrow("test", null);

        Assertions.assertEquals(expected, actual);
        verify(auditLogService, never()).logAuthentication(any(), any(), any(), any());
    }

    @Test
    void testResolveProviderOrThrow_UnknownProviderAuditsAndThrows() {
        PlatformAuthenticationException exception = Assertions.assertThrows(PlatformAuthenticationException.class,
                () -> service.resolveProviderOrThrow("unknown", "session-access-token"));

        Assertions.assertTrue(exception.getMessage().contains("Unknown OAuth2 Provider"));
        verify(auditLogService, times(1)).logAuthentication(
                eq(Operation.LOGIN), eq(OperationResult.FAILURE), contains("Unknown OAuth2 Provider"), eq("session-access-token"));
    }

    @Test
    void testValidateRedirectOrThrow_Success() {
        String result = service.validateRedirectOrThrow("/ui/dashboard");

        Assertions.assertEquals("/ui/dashboard", result);
        verify(auditLogService, never()).logAuthentication(any(), any(), any(), any());
    }

    @Test
    void testValidateRedirectOrThrow_InvalidAuditsAndThrows() {
        PlatformAuthenticationException exception = Assertions.assertThrows(PlatformAuthenticationException.class,
                () -> service.validateRedirectOrThrow("//malicious.com"));

        Assertions.assertTrue(exception.getMessage().contains("redirect URL"));
        verify(auditLogService, times(1)).logAuthentication(
                eq(Operation.LOGIN), eq(OperationResult.FAILURE), contains("redirect URL"), isNull());
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

    /**
     * Exercises the private provider-validation logic through the public surface:
     * a provider is valid exactly when {@link OAuth2LoginServiceImpl#getValidOAuth2Providers()} returns it.
     */
    private boolean isConsideredValid(OAuth2ProviderSettingsDto provider) {
        cacheProviders(Map.of(provider.getName(), provider));
        return service.getValidOAuth2Providers().stream().anyMatch(p -> p.getName().equals(provider.getName()));
    }

    private void cacheProviders(Map<String, OAuth2ProviderSettingsDto> providers) {
        AuthenticationSettingsDto authSettings = new AuthenticationSettingsDto();
        authSettings.setOAuth2Providers(new HashMap<>(providers));
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, authSettings);
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
