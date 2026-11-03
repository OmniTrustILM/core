package com.otilm.core.security.authn.tsp;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.auth.oauth2.AuthenticationSnapshotRequestHolder;
import com.otilm.core.auth.oauth2.PlatformJwtDecoder;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.service.TspProfileInternalService;
import com.otilm.core.settings.AuthenticationSettingsSnapshot;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.SecretsUtil;
import java.net.URI;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TspAuthenticationFilterTest {

    private static final String CERT_HEADER_NAME = "ssl-client-cert";

    private static final String CERT_HEADER = java.net.URLEncoder
            .encode(com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_PEM,
                    java.nio.charset.StandardCharsets.UTF_8);
    private static final String CERT_THUMBPRINT = com.otilm.core.security.authn.ForwardedCertificateFixtures.THUMBPRINT;

    @Mock
    private TspProfileInternalService tspProfileService;
    @Mock
    private SigningProfileInternalService signingProfileService;
    @Mock
    private PlatformAuthenticationClient authClient;
    @Mock
    private PlatformJwtDecoder jwtDecoder;
    @Mock
    private AuthHelper authHelper;

    private TspAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    @BeforeEach
    void buildFilterAndClearContext() {
        TspSecurityContextWriter contextWriter = new TspSecurityContextWriter(authHelper);
        filter = new TspAuthenticationFilter(new TspRouteResolver(tspProfileService, signingProfileService),
                List
                        .of(new ClientCertificateAuthenticator(authClient, CERT_HEADER_NAME, contextWriter),
                                new BearerTokenAuthenticator(jwtDecoder, authClient, contextWriter),
                                new BasicPasswordAuthenticator(contextWriter)),
                new TspChallengeWriter());
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
        SecurityContextHolder.clearContext();
        AuthenticationSnapshotRequestHolder.clear();
        MDC.clear();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        AuthenticationSnapshotRequestHolder.clear();
        MDC.clear();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Asserts the audit actor MDC reflects the resolved principal (ActorType.USER), not the legacy {@code tsp} system
     * user.
     */
    private static void assertActorIsPrincipal(String expectedUuid, String expectedUsername) {
        assertThat(MDC.get("log_actor_type")).isEqualTo(ActorType.USER.name());
        assertThat(MDC.get("log_actor_uuid")).isEqualTo(expectedUuid);
        assertThat(MDC.get("log_actor_name")).isEqualTo(expectedUsername);
    }

    private static TspProfileModel modelWith(List<TspAuthenticationMethod> methods) {
        return new TspProfileModel(UUID.randomUUID(), "p1", null, true, null, null, List.of(), methods, List.of(),
                null);
    }

    private static TspProfileModel modelWith(List<TspAuthenticationMethod> methods, UUID vaultProfileUuid,
            List<TspProfileModel.BasicCredentialRef> credentials) {
        return new TspProfileModel(UUID.randomUUID(), "p1", null, true, null, null, List.of(), methods, credentials,
                vaultProfileUuid);
    }

    /**
     * Sets both the request URI and the servlet path. The filter anchors its routing on {@code getServletPath()}
     * (context-path-agnostic); these tests run without a context path, so servlet path equals the URI.
     */
    private void setPath(String path) {
        request.setRequestURI(path);
        request.setServletPath(path);
    }

    private static String basicHeader(String user, String pass) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + pass).getBytes());
    }

    private static String fingerprintOf(String username, String password) {
        try {
            return SecretsUtil.calculateSecretContentFingerprint(new BasicAuthSecretContent(username, password));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static AuthenticationInfo authenticatedInfo() {
        return new AuthenticationInfo(AuthMethod.CERTIFICATE, "uuid-1", "alice",
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                "{\"user\":{\"uuid\":\"uuid-1\",\"username\":\"alice\"}}");
    }

    // ── RouteResolution ───────────────────────────────────────────────────────

    @Nested
    class RouteResolution {

        @Test
        void returns401WithoutChallenge_whenMethodDisallowed_certOnlyProfile() throws Exception {
            // given — a client-certificate-only profile has no HTTP-level scheme to advertise: the cert is presented
            // to the TLS-terminating proxy, not via a WWW-Authenticate challenge. The response is 401, header omitted.
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request.addHeader("Authorization", basicHeader("u", "p"));

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(response.getHeader("WWW-Authenticate")).isNull();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
        }

        @Test
        void rejectsBeforeAuth_whenSigningProfileRouteHasNullTspProfileUuid() throws Exception {
            // given
            setPath("/v1/protocols/tsp/signingProfiles/sp1");
            when(signingProfileService.resolveTspProfileForSigningProfileAuthentication("sp1"))
                    .thenReturn(Optional.empty());

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(response.getHeader("WWW-Authenticate")).isNull();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
        }

        @Test
        void resolvesLinkedTspProfile_onSigningProfileRoute() throws Exception {
            // given
            setPath("/v1/protocols/tsp/signingProfiles/sp1");
            when(signingProfileService.resolveTspProfileForSigningProfileAuthentication("sp1"))
                    .thenReturn(Optional.of(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE))));
            request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
            when(authClient.authenticateByCertificate(argThat(cert -> CERT_THUMBPRINT.equals(cert.thumbprint()))))
                    .thenReturn(authenticatedInfo());

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
            assertThat(chain.getRequest()).isNotNull();
        }

        @Test
        void resolvesAsDirectTspProfile_whenDirectNameLooksLikeSigningProfiles() throws Exception {
            // given — a single-segment direct name that happens to be "signingProfiles" must NOT be routed through the
            // indirect signing-profile resolution: there is no trailing name segment, so it is a plain direct name.
            setPath("/v1/protocols/tsp/signingProfiles");
            when(tspProfileService.resolveTspProfileForAuthentication("signingProfiles"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
            when(authClient.authenticateByCertificate(argThat(cert -> CERT_THUMBPRINT.equals(cert.thumbprint()))))
                    .thenReturn(authenticatedInfo());

            // when
            filter.doFilter(request, response, chain);

            // then
            verify(tspProfileService).resolveTspProfileForAuthentication("signingProfiles");
            verifyNoInteractions(signingProfileService);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
            assertThat(chain.getRequest()).isNotNull();
        }

        @Test
        void returns401WithoutAuthentication_whenDirectRouteNotFound() throws Exception {
            // given
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenThrow(new NotFoundException("TspProfile", "p1"));
            request.addHeader(CERT_HEADER_NAME, CERT_HEADER);

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
            verifyNoInteractions(authClient);
        }

        @Test
        void advertisesBearerNotBasic_whenBearerOnlyProfile_andMethodDisallowed() throws Exception {
            // given — present Basic, which is NOT in the allowed set → 401, header must advertise Bearer (not Basic)
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BEARER_TOKEN)));
            request.addHeader("Authorization", basicHeader("u", "p"));

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            String header = response.getHeader("WWW-Authenticate");
            assertThat(header).isNotNull().contains("Bearer").doesNotContain("Basic");
            assertThat(chain.getRequest()).isNull();
        }
    }

    // ── PathAnchoring ─────────────────────────────────────────────────────────

    @Nested
    class PathAnchoring {

        @Test
        void isNotGated_whenMultiSegmentTspPath() throws Exception {
            // given — a multi-segment tail under the prefix must not be treated as a single profile name,
            // nor confused with the indirect signingProfiles route.
            setPath("/v1/protocols/tsp/a/b");

            // when / then
            assertThat(filter.shouldNotFilter(request)).isTrue();

            filter.doFilter(request, response, chain);

            verifyNoInteractions(tspProfileService, signingProfileService);
            assertThat(response.getStatus()).isNotEqualTo(401);
            assertThat(chain.getRequest()).isNotNull();
        }

        @Test
        void isNotGated_whenTrailingSlashTspPath() throws Exception {
            // given
            setPath("/v1/protocols/tsp/p1/");

            // when / then
            assertThat(filter.shouldNotFilter(request)).isTrue();

            filter.doFilter(request, response, chain);

            verifyNoInteractions(tspProfileService, signingProfileService);
            assertThat(response.getStatus()).isNotEqualTo(401);
            assertThat(chain.getRequest()).isNotNull();
        }

        @Test
        void isNotGated_whenSubResourceUnderProfile() throws Exception {
            // given — only the exact single-segment profile path is gated; a deeper sub-resource is not
            setPath("/v1/protocols/tsp/p1/verify");

            // when / then
            assertThat(filter.shouldNotFilter(request)).isTrue();

            filter.doFilter(request, response, chain);

            verifyNoInteractions(tspProfileService, signingProfileService);
            assertThat(chain.getRequest()).isNotNull();
        }
    }

    // ── ClientCertificate ─────────────────────────────────────────────────────

    @Nested
    class ClientCertificate {

        @ParameterizedTest
        @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#supportedHeaders")
        void authenticatesSupportedCertificateHeaders(String header, String content, String thumbprint)
                throws Exception {
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request.addHeader(CERT_HEADER_NAME, header);
            when(authClient
                    .authenticateByCertificate(
                            argThat(cert -> content.equals(cert.content()) && thumbprint.equals(cert.thumbprint()))))
                    .thenReturn(authenticatedInfo());
            filter.doFilter(request, response, chain);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
            verify(authClient)
                    .authenticateByCertificate(
                            argThat(cert -> content.equals(cert.content()) && thumbprint.equals(cert.thumbprint())));
        }

        @ParameterizedTest
        @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#malformedHeaders")
        void refusesMalformedCertificateHeaders(String header) throws Exception {
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request.addHeader(CERT_HEADER_NAME, header);
            filter.doFilter(request, response, chain);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(response.getStatus()).isEqualTo(401);
            verifyNoInteractions(authClient);
        }

        @Test
        void rfcCompanionCandidatesReachAuth() throws Exception {
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request
                    .addHeader(CERT_HEADER_NAME,
                            ":" + com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_DER + ":");
            request
                    .addHeader("Client-Cert-Chain",
                            ":" + com.otilm.core.security.authn.ForwardedCertificateFixtures.ISSUER_DER + ":");
            when(authClient.authenticateByCertificate(any())).thenReturn(authenticatedInfo());
            filter.doFilter(request, response, chain);
            verify(authClient)
                    .authenticateByCertificate(argThat(cert -> cert
                            .chain()
                            .equals(List.of(com.otilm.core.security.authn.ForwardedCertificateFixtures.ISSUER_DER))));
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        }

        @Test
        void malformedRfcCompanionDoesNotReachAuth() throws Exception {
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request
                    .addHeader(CERT_HEADER_NAME,
                            ":" + com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_DER + ":");
            request.addHeader("Client-Cert-Chain", ":dGVzdA==:");
            filter.doFilter(request, response, chain);
            assertThat(response.getStatus()).isEqualTo(401);
            verifyNoInteractions(authClient);
        }

        @Test
        void setsContextFromConnector() throws Exception {
            // given
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
            when(authClient.authenticateByCertificate(argThat(cert -> CERT_THUMBPRINT.equals(cert.thumbprint()))))
                    .thenReturn(authenticatedInfo());

            // when
            filter.doFilter(request, response, chain);

            // then
            verify(authClient).authenticateByCertificate(argThat(cert -> CERT_THUMBPRINT.equals(cert.thumbprint())));
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
            assertThat(chain.getRequest()).isNotNull();
            assertActorIsPrincipal("uuid-1", "alice");
        }
    }

    // ── BearerToken ───────────────────────────────────────────────────────────

    @Nested
    class BearerToken {

        @Test
        void decodesAndAuthenticatesByToken() throws Exception {
            // given
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BEARER_TOKEN)));
            request.addHeader("Authorization", "Bearer the.jwt.token");
            Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
            Jwt jwt = Jwt
                    .withTokenValue("the.jwt.token")
                    .header("alg", "none")
                    .claim("sub", "alice")
                    .claim("jti", "jti-1")
                    .claim("username", "alice")
                    .issuedAt(issuedAt)
                    .expiresAt(issuedAt.plusSeconds(60))
                    .build();
            when(jwtDecoder.decode("the.jwt.token")).thenReturn(jwt);
            when(authClient.authenticateByToken(anyMap(), anyLong())).thenReturn(authenticatedInfo());

            // when
            filter.doFilter(request, response, chain);

            // then
            verify(jwtDecoder).decode("the.jwt.token");
            verify(authClient).authenticateByToken(anyMap(), anyLong());
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
            assertThat(chain.getRequest()).isNotNull();
            assertActorIsPrincipal("uuid-1", "alice");
        }

        private BearerTokenAuthenticator bearerAuthenticator() {
            return new BearerTokenAuthenticator(jwtDecoder, authClient, new TspSecurityContextWriter(authHelper));
        }

        @Test
        void bearerToken_withoutEffectiveUsernameClaim_isRejected() {
            Jwt jwt = mock(Jwt.class);
            when(jwtDecoder.decode(anyString())).thenReturn(jwt);
            when(jwt.getClaims()).thenReturn(Map.of("sub", "abc", "jti", "jti-1"));
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer some-token");

            assertThat(bearerAuthenticator().authenticate(request, mock(TspProfileModel.class))).isFalse();
            verifyNoInteractions(authClient);
        }

        @Test
        void bearerToken_forwardsNormalizedUsername() {
            Jwt jwt = mock(Jwt.class);
            when(jwtDecoder.decode(anyString())).thenReturn(jwt);
            when(jwt.getClaims()).thenReturn(Map.of("username", "alice", "jti", "jti-2"));
            when(authClient.authenticateByToken(anyMap(), anyLong())).thenReturn(authenticatedInfo());
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer some-token");

            assertThat(bearerAuthenticator().authenticate(request, mock(TspProfileModel.class))).isTrue();
            verify(authClient)
                    .authenticateByToken(argThat(claims -> "alice".equals(claims.get("username"))), anyLong());
        }

        @Test
        void bearerToken_resolvesConfiguredClaimFromMatchingProvider() throws Exception {
            Jwt jwt = mock(Jwt.class);
            when(jwtDecoder.decode(anyString())).thenReturn(jwt);
            when(jwt.getIssuer()).thenReturn(URI.create("https://issuer.example.com").toURL());
            when(jwt.getClaims()).thenReturn(Map.of("preferred_username", "alice", "jti", "jti-3"));
            when(authClient.authenticateByToken(anyMap(), anyLong())).thenReturn(authenticatedInfo());
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer some-token");

            OAuth2ProviderSettingsDto provider = new OAuth2ProviderSettingsDto();
            provider.setName("entra");
            provider.setIssuerUrl("https://issuer.example.com");
            provider.setUsernameClaim("preferred_username");
            AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
            settings.setOAuth2Providers(Map.of("entra", provider));

            try (MockedStatic<SettingsCache> settingsMock = mockStatic(SettingsCache.class)) {
                settingsMock
                        .when(SettingsCache::getAuthenticationSnapshot)
                        .thenReturn(new AuthenticationSettingsSnapshot(settings, 7L));

                assertThat(bearerAuthenticator().authenticate(request, mock(TspProfileModel.class))).isTrue();
            }
            verify(authClient).authenticateByToken(argThat(claims -> "alice".equals(claims.get("username"))), eq(7L));
        }

        @Test
        void bearerToken_resolvesIdentityFromTheSnapshotTheDecoderValidatedAgainst() throws Exception {
            OAuth2ProviderSettingsDto provider = new OAuth2ProviderSettingsDto();
            provider.setName("entra");
            provider.setIssuerUrl("https://issuer.example.com");
            provider.setUsernameClaim("preferred_username");
            AuthenticationSettingsDto validatedSettings = new AuthenticationSettingsDto();
            validatedSettings.setOAuth2Providers(Map.of("entra", provider));

            Jwt jwt = mock(Jwt.class);
            when(jwt.getIssuer()).thenReturn(URI.create("https://issuer.example.com").toURL());
            when(jwt.getClaims()).thenReturn(Map.of("preferred_username", "alice", "jti", "jti-4"));
            // the decoder publishes the snapshot it validated against, as the real one does
            when(jwtDecoder.decode(anyString())).thenAnswer(invocation -> {
                AuthenticationSnapshotRequestHolder.set(new AuthenticationSettingsSnapshot(validatedSettings, 9L));
                return jwt;
            });
            when(authClient.authenticateByToken(anyMap(), anyLong())).thenReturn(authenticatedInfo());
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer some-token");

            // no SettingsCache stubbing: only the published snapshot knows this provider and this generation
            assertThat(bearerAuthenticator().authenticate(request, mock(TspProfileModel.class))).isTrue();
            verify(authClient).authenticateByToken(argThat(claims -> "alice".equals(claims.get("username"))), eq(9L));
        }
    }

    // ── BasicPassword ─────────────────────────────────────────────────────────

    @Nested
    class BasicPassword {

        @Test
        void authenticatesAsMappedUser_whenFingerprintMatches() throws Exception {
            // given
            UUID mappedUser = UUID.randomUUID();
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                            List
                                    .of(new TspProfileModel.BasicCredentialRef("alice", mappedUser,
                                            fingerprintOf("alice", "s3cret")))));
            request.addHeader("Authorization", basicHeader("alice", "s3cret"));

            // when
            filter.doFilter(request, response, chain);

            // then
            verify(authHelper).authenticateAsUser(mappedUser);
            assertThat(chain.getRequest()).isNotNull();
        }

        @Test
        void returns401_whenFingerprintMismatch() throws Exception {
            // given
            UUID mappedUser = UUID.randomUUID();
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                            List
                                    .of(new TspProfileModel.BasicCredentialRef("alice", mappedUser,
                                            fingerprintOf("alice", "right")))));
            request.addHeader("Authorization", basicHeader("alice", "wrong"));

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            verify(authHelper, never()).authenticateAsUser(any());
            assertThat(chain.getRequest()).isNull();
        }

        @Test
        void returns401WithoutForwarding_whenPasswordBlank() throws Exception {
            // given
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BASIC_PASSWORD)));
            request.addHeader("Authorization", basicHeader("alice", ""));

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            verify(authHelper, never()).authenticateAsUser(any());
            assertThat(chain.getRequest()).isNull();
        }

        @Test
        void returns401_whenUsernameUnknown() throws Exception {
            // given
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                            List.of(new TspProfileModel.BasicCredentialRef("alice", UUID.randomUUID(), "x"))));
            request.addHeader("Authorization", basicHeader("mallory", "s3cret"));

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            verify(authHelper, never()).authenticateAsUser(any());
            assertThat(chain.getRequest()).isNull();
        }

        @Test
        void advertisesBasicRealm_whenBasicMethodEnabled() throws Exception {
            // given — present a Bearer token, which is NOT in the allowed set → 401, header must advertise Basic realm
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BASIC_PASSWORD)));
            request.addHeader("Authorization", "Bearer some.jwt");

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            String header = response.getHeader("WWW-Authenticate");
            assertThat(header).isNotNull().contains("Basic realm=\"p1\"");
        }
    }

    // ── FailClosed ────────────────────────────────────────────────────────────

    @Nested
    class FailClosed {

        @Test
        void failsClosed_whenClientCertificateAuthClientThrows() throws Exception {
            // given — CLIENT_CERTIFICATE profile, cert header present, but authenticateByCertificate throws.
            // The filter must catch it, return 401, and NOT continue the chain.
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
            when(authClient.authenticateByCertificate(argThat(cert -> CERT_THUMBPRINT.equals(cert.thumbprint()))))
                    .thenThrow(new PlatformAuthenticationException("upstream auth failure"));

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
        }

        @Test
        void failsClosed_whenCertHeaderMalformed() throws Exception {
            // given — CLIENT_CERTIFICATE profile, but the cert header contains non-base64 content outside the PEM
            // wrapper, causing Base64.getDecoder().decode to throw IllegalArgumentException. The filter must fail
            // closed.
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request.addHeader(CERT_HEADER_NAME, "!!not-valid-base64!!");

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
        }

        @Test
        void failsClosed_whenBearerDecodeReturnsNull() throws Exception {
            // given — BEARER_TOKEN profile, jwtDecoder.decode returns null → filter must return 401, not continue
            // chain.
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BEARER_TOKEN)));
            request.addHeader("Authorization", "Bearer the.jwt.token");
            when(jwtDecoder.decode("the.jwt.token")).thenReturn(null);

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
            verify(authClient, never()).authenticateByToken(anyMap(), anyLong());
        }

        @Test
        void failsClosed_whenBearerDecodeThrows() throws Exception {
            // given — BEARER_TOKEN profile, jwtDecoder.decode throws a RuntimeException → filter must catch and 401.
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BEARER_TOKEN)));
            request.addHeader("Authorization", "Bearer bad.token");
            when(jwtDecoder.decode("bad.token")).thenThrow(new PlatformAuthenticationException("token decode failed"));

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
            verify(authClient, never()).authenticateByToken(anyMap(), anyLong());
        }

        @Test
        void failsClosedWithoutCallingConnector_whenBasicCredentialsHaveNoColon() throws Exception {
            // given — BASIC_PASSWORD profile, Authorization is "Basic <base64 of a string with no colon>".
            // decodeBasicCredentials returns null → filter must return 401 without ever consulting secretService.
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                            List.of(new TspProfileModel.BasicCredentialRef("alice", UUID.randomUUID(), "x"))));
            String noColon = Base64.getEncoder().encodeToString("nocredentials".getBytes());
            request.addHeader("Authorization", "Basic " + noColon);

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
            verify(authHelper, never()).authenticateAsUser(any());
        }

        @Test
        void failsClosedWithoutCallingConnector_whenBasicInvalidBase64() throws Exception {
            // given — BASIC_PASSWORD profile, Authorization contains invalid Base64 — decodeBasicCredentials catches
            // IllegalArgumentException and returns null → filter must return 401 without consulting secretService.
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                            List.of(new TspProfileModel.BasicCredentialRef("alice", UUID.randomUUID(), "x"))));
            request.addHeader("Authorization", "Basic !!!not-base64!!!");

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
            verify(authHelper, never()).authenticateAsUser(any());
        }
    }

    @Test
    void clientCertificateAuthenticatorLogsControlledParserReason() throws Throwable {
        request.addHeader(CERT_HEADER_NAME, "private-certificate%%%");
        var authenticator = new ClientCertificateAuthenticator(authClient, CERT_HEADER_NAME,
                new TspSecurityContextWriter(authHelper));
        var messages = com.otilm.core.security.authn.ForwardedCertificateFixtures
                .captureLogs(ClientCertificateAuthenticator.class,
                        () -> assertThat(authenticator
                                .authenticate(request, modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE))))
                                .isFalse());
        assertThat(messages)
                .anyMatch(message -> message.contains("Invalid certificate transport encoding"))
                .noneMatch(message -> message.contains("private-certificate%%%"));
        verifyNoInteractions(authClient);
    }

    @Test
    void clientCertificateAuthenticatorDoesNotLogUncontrolledServiceMessage() throws Throwable {
        request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
        when(authClient.authenticateByCertificate(any()))
                .thenThrow(new PlatformAuthenticationException("service-private-material",
                        new com.otilm.core.security.exception.AuthenticationServiceException(503,
                                "service-private-material")));
        var authenticator = new ClientCertificateAuthenticator(authClient, CERT_HEADER_NAME,
                new TspSecurityContextWriter(authHelper));
        var messages = com.otilm.core.security.authn.ForwardedCertificateFixtures
                .captureLogs(ClientCertificateAuthenticator.class,
                        () -> assertThat(authenticator
                                .authenticate(request, modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE))))
                                .isFalse());
        assertThat(messages)
                .anyMatch(message -> message.contains("Authentication service unavailable"))
                .noneMatch(message -> message.contains("service-private-material"));
    }

    @Test
    void clientCertificateAuthenticatorDoesNotLogUntaggedInputBearingServletException() throws Throwable {
        request = new MockHttpServletRequest() {
            @Override
            public java.util.Enumeration<String> getHeaders(String name) {
                throw new IllegalArgumentException("derived-private-certificate-material");
            }
        };
        request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
        var authenticator = new ClientCertificateAuthenticator(authClient, CERT_HEADER_NAME,
                new TspSecurityContextWriter(authHelper));
        var messages = com.otilm.core.security.authn.ForwardedCertificateFixtures
                .captureLogs(ClientCertificateAuthenticator.class,
                        () -> assertThat(authenticator
                                .authenticate(request, modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE))))
                                .isFalse());
        assertThat(messages)
                .anyMatch(message -> message.endsWith("Certificate authentication failed"))
                .noneMatch(message -> message.contains("derived-private-certificate-material"));
        verifyNoInteractions(authClient);
    }

}
