package com.otilm.core.integration.security.oauth2;

import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.otilm.core.auth.oauth2.PlatformClientRegistrationRepository;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class PlatformClientRegistrationRepositoryITest extends BaseSpringBootTest {

    @Autowired
    private PlatformClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private SettingExternalService settingService;

    @BeforeEach
    void setUp() {
        OAuth2ProviderSettingsUpdateDto providerSettings = new OAuth2ProviderSettingsUpdateDto();
        providerSettings.setClientSecret("secret");
        providerSettings.setIssuerUrl("issuer");
        providerSettings.setClientId("client");
        providerSettings.setClientSecret("secret");
        providerSettings.setAuthorizationUrl("http");
        providerSettings.setTokenUrl("http");
        providerSettings.setJwkSet("eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImFsZyI6IlJTMjU2IiwibiI6IkFMYy9MbGNrbmt5Q3Z3U05hMVp0MkZRc0ZEU1NwdGpJMkIzeThLdHFiaEFOUTk2cXpXK1dDWFpyS1RYZFhJanNMVk1jY3V0cy9UNCtNM2cwRHlFMUYwVUx0VXNBakZDSnZoVjZ6RnZWai91RE52bXRMbGxSSHJzSkRxRXJsekI1Mjh6dk9lNTVwVENzN0lmeDViRDRQbS9SU2ZMWmJmZkxGMXV0RlQ1Z2p2VHFtQ1NUdG0rM2VpNitGWmJ0Uytna0hFMWRYM0FkOXRSMDRNaXVNYm1ZV2dhVDk4L1lhMGJtV0JMaFpLWkJUcThkRHBWTjFmWHh4S05zZ1hFS0lOZFVHM043RiszbkwwdlJOQWFIQlBab3JVRlNaNkRxc1hQdFIxTVlKRDVxb200OXF5ZThkUlpVWUg4Vnh0WWU1S1VtTVZoenRBNW9JSGNsN01ub29zUVk4b1U9In1dfQ==");
        settingService.updateOAuth2ProviderSettings("provider", providerSettings);
    }

    @Test
    void testRetrieveClientRegistration() {
        Assertions.assertNotNull(clientRegistrationRepository.findByRegistrationId("provider"));
        Assertions.assertNull(clientRegistrationRepository.findByRegistrationId("non-existing"));
    }
}

