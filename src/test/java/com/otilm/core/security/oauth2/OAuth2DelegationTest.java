package com.otilm.core.security.oauth2;

import com.otilm.api.model.core.logging.records.DelegateRecord;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.util.OAuth2Util;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OAuth2DelegationTest {

    @Test
    void ordinaryTokensNeedNoDelegateAllowlist() {
        assertThat(OAuth2Util.resolveDelegate(provider(List.of()), Map.of("sub", "alice"))).isNull();
    }

    @Test
    void outerActorIsRecordedWithoutInterpretingNestedActors() {
        var actor = Map.of("client_id", "mcp", "sub", "service-account-mcp", "act", "malformed-inner-actor");
        assertThat(OAuth2Util.resolveDelegate(provider(List.of("mcp")), Map.of("act", actor)))
                .isEqualTo(new DelegateRecord("mcp", "service-account-mcp"));
    }

    @Test
    void customActorClaimDoesNotReadTopLevelClientId() {
        var provider = provider(List.of("worker"));
        provider.setDelegateClaim("sub");
        assertThat(OAuth2Util.resolveDelegate(provider, Map.of("client_id", "wrong", "act", Map.of("sub", "worker"))))
                .isEqualTo(new DelegateRecord("worker", null));
    }

    @Test
    void subjectIsOptionalAndDuplicateSubjectIsOmitted() {
        var provider = provider(List.of("mcp"));
        for (var actor : List
                .of(Map.of("client_id", "mcp"), Map.of("client_id", "mcp", "sub", "mcp"),
                        Map.of("client_id", "mcp", "sub", " "), Map.of("client_id", "mcp", "sub", 7))) {
            assertThat(OAuth2Util.resolveDelegate(provider, Map.of("act", actor)))
                    .isEqualTo(new DelegateRecord("mcp", null));
        }
    }

    @ParameterizedTest
    @MethodSource("invalidActors")
    void malformedActorNeverBecomesAnOrdinaryToken(Object actor) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("act", actor);
        var provider = provider(List.of("mcp"));
        assertThatThrownBy(() -> OAuth2Util.resolveDelegate(provider, claims))
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasMessageContaining("test-provider")
                .hasMessageContaining("client_id");
    }

    static Stream<Object> invalidActors() {
        return Stream
                .of(null, "mcp", 7, List.of("mcp"), Map.of(), Map.of("sub", "mcp"), Map.of("client_id", ""),
                        Map.of("client_id", " "), Map.of("client_id", 3));
    }

    @Test
    void allowlistIsDefaultDenyAndMatchesExactly() {
        Map<String, Object> claims = Map.of("act", Map.of("client_id", "mcp"));
        for (var allowed : List.of(List.<String>of(), List.of("MCP"), List.of("mcp*"), List.of(" mcp"))) {
            var provider = provider(allowed);
            assertThatThrownBy(() -> OAuth2Util.resolveDelegate(provider, claims))
                    .isInstanceOf(PlatformAuthenticationException.class)
                    .hasMessageContaining("mcp")
                    .hasMessageContaining("not allowed");
        }
    }

    @Test
    void missingProviderOrLegacyNullAllowlistCannotAuthorizeDelegation() {
        Map<String, Object> claims = Map.of("act", Map.of("client_id", "mcp"));
        var provider = provider(null);
        assertThatThrownBy(() -> OAuth2Util.resolveDelegate(null, claims))
                .isInstanceOf(PlatformAuthenticationException.class);
        assertThatThrownBy(() -> OAuth2Util.resolveDelegate(provider, claims))
                .isInstanceOf(PlatformAuthenticationException.class);
    }

    @Test
    void invalidActorDiagnosticsDoNotRenderArbitraryActorObjects() {
        assertThatThrownBy(() -> OAuth2Util
                .resolveDelegate(provider(List.of()), Map.of("act", Map.of("client_id", List.of("sensitive-payload")))))
                .hasMessageNotContaining("sensitive-payload");
    }

    private static OAuth2ProviderSettingsDto provider(List<String> allowed) {
        var provider = new OAuth2ProviderSettingsDto();
        provider.setName("test-provider");
        provider.setAllowedDelegates(allowed);
        return provider;
    }
}
