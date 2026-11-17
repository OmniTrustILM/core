package com.otilm.core.security.authn;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class ProtectedResourceMetadataBearerTokenResolverTest {

    private static final String OTHER_PATH = "/v1/auth/profile";

    private final ProtectedResourceMetadataBearerTokenResolver resolver = new ProtectedResourceMetadataBearerTokenResolver();

    @Test
    void resolvesNoToken_whenGettingTheMetadata() {
        // given
        var request = aRequest("GET", ProtectedResourceChallenge.METADATA_PATH);

        // when
        String token = resolver.resolve(request);

        // then
        assertThat(token).isNull();
    }

    @Test
    void resolvesToken_whenGettingAnotherPath() {
        // given
        var request = aRequest("GET", OTHER_PATH);

        // when
        String token = resolver.resolve(request);

        // then
        assertThat(token).isEqualTo("x");
    }

    @Test
    void resolvesToken_whenPostingToTheMetadataPath() {
        // given
        var request = aRequest("POST", ProtectedResourceChallenge.METADATA_PATH);

        // when
        String token = resolver.resolve(request);

        // then
        assertThat(token).isEqualTo("x");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static MockHttpServletRequest aRequest(String method, String path) {
        var request = new MockHttpServletRequest(method, path);
        request.setServletPath(path);
        request.addHeader("Authorization", "Bearer x");
        return request;
    }
}
