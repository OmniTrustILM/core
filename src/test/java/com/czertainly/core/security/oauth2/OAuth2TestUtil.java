package com.czertainly.core.security.oauth2;

import com.czertainly.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.czertainly.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.czertainly.core.util.OAuth2Constants;
import com.czertainly.core.util.SecretEncodingVersion;
import com.czertainly.core.util.SecretsUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.PrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OAuth2TestUtil {

    public static String createJwtTokenValue(PrivateKey privateKey, Integer expiryInMilliseconds, String issuerUrl, String audience, String username) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(audience)
                .expirationTime(expiryInMilliseconds == null ? null : new Date(System.currentTimeMillis() + expiryInMilliseconds))
                .claim(OAuth2Constants.TOKEN_USERNAME_CLAIM_NAME, username)
                .issuer(issuerUrl)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        JWSSigner signer = new RSASSASigner(privateKey);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    public static AuthenticationSettingsDto getAuthenticationSettings(String userInfoUrl, int port, List<String> audiences, String issuerUrl) {
        OAuth2ProviderSettingsDto providerSettingsDto = new OAuth2ProviderSettingsDto();
        providerSettingsDto.setName("test");
        providerSettingsDto.setClientId("client");
        providerSettingsDto.setAuthorizationUrl("http://auth");
        providerSettingsDto.setTokenUrl("http://localhost:" + port + "/token");
        providerSettingsDto.setScope(List.of("openid"));
        providerSettingsDto.setSkew(0);
        providerSettingsDto.setUserInfoUrl(userInfoUrl);
        providerSettingsDto.setAudiences(audiences);
        providerSettingsDto.setIssuerUrl(issuerUrl);
        providerSettingsDto.setClientSecret(SecretsUtil.encryptAndEncodeSecretString("secret", SecretEncodingVersion.V1));
        AuthenticationSettingsDto authenticationSettingsDto = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        providers.put("test", providerSettingsDto);
        authenticationSettingsDto.setOAuth2Providers(providers);
        return authenticationSettingsDto;
    }
}
