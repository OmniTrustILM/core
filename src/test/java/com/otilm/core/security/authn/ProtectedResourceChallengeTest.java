package com.otilm.core.security.authn;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;

class ProtectedResourceChallengeTest {

    private static final String METADATA_URL = "https://ilm.example.com/.well-known/oauth-protected-resource/api";

    @Test
    void addsBearerScheme_whenThereIsNoExistingChallenge() {
        // given
        String noChallenge = null;

        // when
        String header = ProtectedResourceChallenge.headerValue(METADATA_URL, noChallenge);

        // then
        assertThat(header).isEqualTo("Bearer resource_metadata=\"" + METADATA_URL + "\"");
    }

    @Test
    void addsBearerScheme_whenExistingChallengeIsBareBearer() {
        // given
        var bareBearer = "Bearer";

        // when
        String header = ProtectedResourceChallenge.headerValue(METADATA_URL, bareBearer);

        // then
        assertThat(header).isEqualTo("Bearer resource_metadata=\"" + METADATA_URL + "\"");
    }

    @Test
    void keepsErrorParameters_whenExistingChallengeCarriesThem() {
        // given
        var refusedToken = "Bearer error=\"invalid_token\", error_description=\"expired\"";

        // when
        String header = ProtectedResourceChallenge.headerValue(METADATA_URL, refusedToken);

        // then
        assertThat(header).isEqualTo(refusedToken + ", resource_metadata=\"" + METADATA_URL + "\"");
    }

    @Test
    void dropsContextPath_whenBuildingOrigin() {
        // given
        var request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("ilm.example.com");
        request.setServerPort(443);
        request.setContextPath("/api");

        // when
        String origin = ProtectedResourceChallenge.origin(ServletUriComponentsBuilder.fromContextPath(request));

        // then
        assertThat(origin).isEqualTo("https://ilm.example.com");
    }
}
