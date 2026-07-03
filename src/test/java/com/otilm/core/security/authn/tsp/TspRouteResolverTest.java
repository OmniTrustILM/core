package com.otilm.core.security.authn.tsp;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.service.TspProfileInternalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TspRouteResolverTest {

    @Mock private TspProfileInternalService tspProfileService;
    @Mock private SigningProfileInternalService signingProfileService;

    private TspRouteResolver resolver;

    @BeforeEach
    void createResolver() {
        resolver = new TspRouteResolver(tspProfileService, signingProfileService);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static TspProfileModel anyProfile() {
        return new TspProfileModel(UUID.randomUUID(), "p", null, true, null, null, List.of(), List.of(), List.of(), null);
    }

    private static MockHttpServletRequest requestWith(String servletPath) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath(servletPath);
        return request;
    }

    // ── Matches ───────────────────────────────────────────────────────────────

    @Nested
    class Matches {

        @Test
        void returnsFalse_whenPathNull() {
            // when / then
            assertThat(resolver.matches(null)).isFalse();
        }

        @Test
        void returnsTrue_whenDirectPath() {
            // when / then
            assertThat(resolver.matches("/v1/protocols/tsp/p1")).isTrue();
        }

        @Test
        void returnsTrue_whenIndirectPath() {
            // when / then
            assertThat(resolver.matches("/v1/protocols/tsp/signingProfiles/sp1")).isTrue();
        }

        @Test
        void returnsFalse_whenMultiSegmentPath() {
            // when / then
            assertThat(resolver.matches("/v1/protocols/tsp/a/b")).isFalse();
        }

        @Test
        void returnsFalse_whenNoProfileName() {
            // when / then
            assertThat(resolver.matches("/v1/protocols/tsp/")).isFalse();
        }
    }

    // ── Resolve ───────────────────────────────────────────────────────────────

    @Nested
    class Resolve {

        @Test
        void usesTspProfileService_forDirectRoute() throws NotFoundException {
            // given
            TspProfileModel profile = anyProfile();
            when(tspProfileService.resolveTspProfileForAuthentication("p1")).thenReturn(profile);

            // when
            Optional<TspProfileModel> resolved = resolver.resolve(requestWith("/v1/protocols/tsp/p1"));

            // then
            assertThat(resolved.orElseThrow()).isSameAs(profile);
            verifyNoInteractions(signingProfileService);
        }

        @Test
        void usesSigningProfileService_forIndirectRoute() throws NotFoundException {
            // given
            TspProfileModel profile = anyProfile();
            when(signingProfileService.resolveTspProfileForSigningProfileAuthentication("sp1")).thenReturn(Optional.of(profile));

            // when
            Optional<TspProfileModel> resolved = resolver.resolve(requestWith("/v1/protocols/tsp/signingProfiles/sp1"));

            // then
            assertThat(resolved.orElseThrow()).isSameAs(profile);
            verifyNoInteractions(tspProfileService);
        }

        @Test
        void returnsEmpty_whenNonMatchingPath_withoutTouchingServices() throws NotFoundException {
            // when
            Optional<TspProfileModel> resolved = resolver.resolve(requestWith("/v1/protocols/tsp/a/b"));

            // then
            assertThat(resolved).isEmpty();
            verifyNoInteractions(tspProfileService, signingProfileService);
        }
    }
}
