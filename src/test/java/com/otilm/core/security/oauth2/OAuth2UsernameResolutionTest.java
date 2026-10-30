package com.otilm.core.security.oauth2;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.util.OAuth2Util;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuth2UsernameResolutionTest {

    private static OAuth2ProviderSettingsDto providerWithClaim(String usernameClaim) {
        OAuth2ProviderSettingsDto provider = new OAuth2ProviderSettingsDto();
        provider.setName("test");
        provider.setUsernameClaim(usernameClaim);
        return provider;
    }

    @Test
    void configuredClaimPresent_returnsItsValue() {
        Map<String, Object> claims = Map.of("preferred_username", "alice", "username", "bob");
        assertEquals("alice", OAuth2Util.resolveUsername(providerWithClaim("preferred_username"), claims));
    }

    @Test
    void configuredClaimAbsent_throwsWithoutFallback() {
        Map<String, Object> claims = Map.of("username", "bob", "preferred_username", "alice");
        OAuth2ProviderSettingsDto provider = providerWithClaim("upn");
        PlatformAuthenticationException e = assertThrows(PlatformAuthenticationException.class,
                () -> OAuth2Util.resolveUsername(provider, claims));
        assertTrue(e.getMessage().contains("upn"));
    }

    @Test
    void unconfigured_usesDefaultUsernameClaim() {
        Map<String, Object> claims = Map.of("username", "bob");
        assertEquals("bob", OAuth2Util.resolveUsername(providerWithClaim(null), claims));
    }

    @Test
    void unconfigured_preferredUsernameAloneIsNotAccepted() {
        Map<String, Object> claims = Map.of("preferred_username", "alice");
        OAuth2ProviderSettingsDto provider = providerWithClaim(null);
        assertThrows(PlatformAuthenticationException.class, () -> OAuth2Util.resolveUsername(provider, claims));
    }

    @Test
    void blankConfiguredClaim_treatedAsUnset() {
        Map<String, Object> claims = Map.of("username", "bob");
        assertEquals("bob", OAuth2Util.resolveUsername(providerWithClaim("  "), claims));
    }

    @Test
    void nullProviderSettings_usesDefaultClaim() {
        Map<String, Object> claims = Map.of("username", "bob");
        assertEquals("bob", OAuth2Util.resolveUsername(null, claims));
    }

    @Test
    void nonStringClaimValue_throws() {
        Map<String, Object> claims = Map.of("username", List.of("bob"));
        assertThrows(PlatformAuthenticationException.class, () -> OAuth2Util.resolveUsername(null, claims));
    }

    @Test
    void nullClaimsMap_throwsDomainException() {
        assertThrows(PlatformAuthenticationException.class, () -> OAuth2Util.resolveUsername(null, null));
    }

    @Test
    void blankClaimValue_throws() {
        Map<String, Object> claims = Map.of("username", "   ");
        assertThrows(PlatformAuthenticationException.class, () -> OAuth2Util.resolveUsername(null, claims));
    }

    @Test
    void errorMessage_neverContainsClaimValues() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("preferred_username", "secret-value");
        OAuth2ProviderSettingsDto provider = providerWithClaim(null);
        PlatformAuthenticationException e = assertThrows(PlatformAuthenticationException.class,
                () -> OAuth2Util.resolveUsername(provider, claims));
        assertFalse(e.getMessage().contains("secret-value"));
    }

    @Test
    void lenientVariant_returnsNullInsteadOfThrowing() {
        assertNull(OAuth2Util.resolveUsernameOrNull(providerWithClaim("upn"), Map.of("username", "bob")));
        assertNull(OAuth2Util.resolveUsernameOrNull(null, null));
        assertEquals("bob", OAuth2Util.resolveUsernameOrNull(null, Map.of("username", "bob")));
    }

    @Test
    void effectiveUsernameClaim_reflectsConfiguration() {
        assertEquals("upn", OAuth2Util.effectiveUsernameClaim(providerWithClaim("upn")));
        assertEquals("username", OAuth2Util.effectiveUsernameClaim(providerWithClaim(null)));
        assertEquals("username", OAuth2Util.effectiveUsernameClaim(null));
    }

    private static String signedJwtWithClaims(Map<String, Object> tokenClaims) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .expirationTime(new Date(System.currentTimeMillis() + 60_000));
        tokenClaims.forEach(builder::claim);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), builder.build());
        signedJWT.sign(new RSASSASigner(keyPair.getPrivate()));
        return signedJWT.serialize();
    }

    @Test
    void getAllClaimsAvailable_normalizesConfiguredClaimIntoUsernameKey() throws Exception {
        String token = signedJwtWithClaims(Map.of("preferred_username", "alice", "username", "bob"));
        Map<String, Object> claims = OAuth2Util
                .getAllClaimsAvailable(providerWithClaim("preferred_username"), token, null);
        assertEquals("alice", claims.get("username"));
    }

    @Test
    void getAllClaimsAvailable_defaultClaimPresent_keepsUsername() throws Exception {
        String token = signedJwtWithClaims(Map.of("username", "bob"));
        Map<String, Object> claims = OAuth2Util.getAllClaimsAvailable(providerWithClaim(null), token, null);
        assertEquals("bob", claims.get("username"));
    }

    @Test
    void getAllClaimsAvailable_missingEffectiveClaim_throws() throws Exception {
        String token = signedJwtWithClaims(Map.of("preferred_username", "alice"));
        OAuth2ProviderSettingsDto provider = providerWithClaim(null);
        assertThrows(PlatformAuthenticationException.class,
                () -> OAuth2Util.getAllClaimsAvailable(provider, token, null));
    }

    private static AuthenticationSettingsDto settingsWithProviders(OAuth2ProviderSettingsDto... providers) {
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> map = new HashMap<>();
        for (OAuth2ProviderSettingsDto p : providers) {
            map.put(p.getName(), p);
        }
        settings.setOAuth2Providers(map);
        return settings;
    }

    private static OAuth2ProviderSettingsDto providerWithIssuer(String name, String issuerUrl) {
        OAuth2ProviderSettingsDto provider = new OAuth2ProviderSettingsDto();
        provider.setName(name);
        provider.setIssuerUrl(issuerUrl);
        return provider;
    }

    @Test
    void findProviderByIssuer_uniqueMatch() {
        AuthenticationSettingsDto settings = settingsWithProviders(providerWithIssuer("a", "https://issuer-a"),
                providerWithIssuer("b", "https://issuer-b"));
        assertEquals("a", OAuth2Util.findProviderByIssuer(settings, "https://issuer-a").getName());
    }

    @Test
    void findProviderByIssuer_noMatch_returnsNull() {
        AuthenticationSettingsDto settings = settingsWithProviders(providerWithIssuer("a", "https://issuer-a"));
        assertNull(OAuth2Util.findProviderByIssuer(settings, "https://other"));
        assertNull(OAuth2Util.findProviderByIssuer(null, "https://other"));
        assertNull(OAuth2Util.findProviderByIssuer(settings, null));
    }

    @Test
    void findProviderByIssuer_ambiguousMatch_throws() {
        AuthenticationSettingsDto settings = settingsWithProviders(providerWithIssuer("a", "https://issuer-a"),
                providerWithIssuer("b", "https://issuer-a"));
        assertThrows(PlatformAuthenticationException.class,
                () -> OAuth2Util.findProviderByIssuer(settings, "https://issuer-a"));
    }

    @Test
    void findProviderByIssuer_nullProvidersMap_returnsNull() {
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        settings.setOAuth2Providers(null);
        assertNull(OAuth2Util.findProviderByIssuer(settings, "https://issuer-a"));
    }
}
