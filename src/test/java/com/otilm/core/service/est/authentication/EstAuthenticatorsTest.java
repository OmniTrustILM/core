package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstAuthenticatorsTest {

    private static final String LABEL = "devices";
    private static final String CERTIFICATE_HEADER = "ssl-client-cert";

    @Mock
    private CertificateRequest csr;

    private final EstClientCredentials credentials = EstClientCredentials
            .from(new MockHttpServletRequest(), CERTIFICATE_HEADER);

    @ParameterizedTest
    @EnumSource(EstAuthenticationPolicy.class)
    void callsOnlyTheProfilesAuthenticator(EstAuthenticationPolicy policy) {
        // given
        Map<EstAuthenticationPolicy, EstAuthenticator> byPolicy = authenticatorsOfEveryPolicy();
        EstAuthenticators authenticators = new EstAuthenticators(List.copyOf(byPolicy.values()));
        EstRoute route = routeOf(policy);
        EstClient profilesClient = new EstClient(policy, "certificate:0a1b", null);
        when(byPolicy.get(policy).authenticate(route, credentials, csr)).thenReturn(profilesClient);

        // when
        EstClient client = authenticators.authenticate(route, credentials, csr);

        // then
        assertThat(client).isSameAs(profilesClient);
        byPolicy
                .values()
                .stream()
                .filter(authenticator -> authenticator != byPolicy.get(policy))
                .forEach(authenticator -> verify(authenticator, never()).authenticate(any(), any(), any()));
    }

    @Test
    void failsAtStartup_whenTwoAuthenticatorsClaimOnePolicy() {
        // given
        EstAuthenticator first = authenticatorOf(EstAuthenticationPolicy.RA_BASIC);
        EstAuthenticator second = authenticatorOf(EstAuthenticationPolicy.RA_BASIC);

        // when
        ThrowingCallable createAuthenticators = () -> new EstAuthenticators(List.of(first, second));

        // then
        assertThatThrownBy(createAuthenticators)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(EstAuthenticationPolicy.RA_BASIC.getCode());
    }

    @ParameterizedTest
    @EnumSource(EstAuthenticationPolicy.class)
    void failsAtStartup_whenAPolicyHasNoAuthenticator(EstAuthenticationPolicy unserved) {
        // given
        List<EstAuthenticator> allButOne = Arrays
                .stream(EstAuthenticationPolicy.values())
                .filter(policy -> policy != unserved)
                .map(EstAuthenticatorsTest::authenticatorOf)
                .toList();

        // when
        ThrowingCallable createAuthenticators = () -> new EstAuthenticators(allButOne);

        // then
        assertThatThrownBy(createAuthenticators)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(unserved.getCode());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Map<EstAuthenticationPolicy, EstAuthenticator> authenticatorsOfEveryPolicy() {
        Map<EstAuthenticationPolicy, EstAuthenticator> authenticators = new EnumMap<>(EstAuthenticationPolicy.class);
        Arrays
                .stream(EstAuthenticationPolicy.values())
                .forEach(policy -> authenticators.put(policy, authenticatorOf(policy)));
        return authenticators;
    }

    private static EstAuthenticator authenticatorOf(EstAuthenticationPolicy policy) {
        EstAuthenticator authenticator = mock(EstAuthenticator.class);
        when(authenticator.policy()).thenReturn(policy);
        return authenticator;
    }

    private static EstRoute routeOf(EstAuthenticationPolicy policy) {
        return new EstRoute(anEstProfile().withAuthenticationPolicy(policy).build(), null, false, LABEL);
    }
}
