package com.otilm.core.util;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class AuthHelperProtectedResourceMetadataTest {

    private static final String CONTEXT_PATH = "/api";

    private static final String METADATA_PATH = "/.well-known/oauth-protected-resource/api";

    @ParameterizedTest
    @ValueSource(strings = {"", CONTEXT_PATH})
    void permitsTheMetadataRead_whenRequestedWithGet(String contextPath) {
        // given
        var uri = contextPath + METADATA_PATH;

        // when
        boolean permitted = AuthHelper.permitAllEndpointInRequest(uri, "GET", contextPath);

        // then
        assertThat(permitted).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "PUT", "PATCH", "DELETE"})
    void refusesAnonymousWrites_whenMetadataPathIsNotRead(String method) {
        // given
        var uri = CONTEXT_PATH + METADATA_PATH;

        // when
        boolean permitted = AuthHelper.permitAllEndpointInRequest(uri, method, CONTEXT_PATH);

        // then
        assertThat(permitted).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/.well-known/oauth-protected-resource",
            "/api/.well-known/oauth-protected-resource/mcp",
            "/api/.well-known/oauth-protected-resource/api/other",
            "/api/.well-known/oauth-protected-resource/apix"})
    void keepsNeighbouringPathsClosed_whenTheyOnlyResembleTheMetadataPath(String uri) {
        // given
        var anonymousGet = "GET";

        // when
        boolean permitted = AuthHelper.permitAllEndpointInRequest(uri, anonymousGet, CONTEXT_PATH);

        // then
        assertThat(permitted).isFalse();
    }
}
