package com.otilm.core.security.authn.tsp;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.auth.oauth2.PlatformJwtDecoder;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.CredentialVerificationCache;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.SigningProfileService;
import com.otilm.core.service.TspProfileService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.SecretsUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.slf4j.MDC;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TspAuthenticationFilterTest {

    private static final String CERT_HEADER_NAME = "ssl-client-cert";

    // PEM wrapping base64("test") — after normalize+decode yields DER bytes [0x74, 0x65, 0x73, 0x74]
    // expected thumbprint = SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    private static final String CERT_HEADER = "-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----\n";
    private static final String CERT_THUMBPRINT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    @Mock private TspProfileService tspProfileService;
    @Mock private SigningProfileService signingProfileService;
    @Mock private PlatformAuthenticationClient authClient;
    @Mock private PlatformJwtDecoder jwtDecoder;
    @Mock private CredentialVerificationCache credentialCache;
    @Mock private AuthHelper authHelper;

    private TspAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    @BeforeEach
    void buildFilterAndClearContext() {
        TspSecurityContextWriter contextWriter = new TspSecurityContextWriter(authHelper);
        filter = new TspAuthenticationFilter(
                new TspRouteResolver(tspProfileService, signingProfileService),
                List.of(
                        new ClientCertificateAuthenticator(authClient, CERT_HEADER_NAME, contextWriter),
                        new BearerTokenAuthenticator(jwtDecoder, authClient, contextWriter),
                        new BasicPasswordAuthenticator(credentialCache, contextWriter)),
                new TspChallengeWriter());
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
        SecurityContextHolder.clearContext();
        MDC.clear();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        MDC.clear();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Asserts the audit actor MDC reflects the resolved principal (ActorType.USER), not the legacy {@code tsp} system user. */
    private static void assertActorIsPrincipal(String expectedUuid, String expectedUsername) {
        assertThat(MDC.get("log_actor_type")).isEqualTo(ActorType.USER.name());
        assertThat(MDC.get("log_actor_uuid")).isEqualTo(expectedUuid);
        assertThat(MDC.get("log_actor_name")).isEqualTo(expectedUsername);
    }

    private static TspProfileModel modelWith(List<TspAuthenticationMethod> methods) {
        return new TspProfileModel(UUID.randomUUID(), "p1", null, true, null, null, List.of(), methods, List.of(), null);
    }

    private static TspProfileModel modelWith(List<TspAuthenticationMethod> methods, UUID vaultProfileUuid,
                                             List<TspProfileModel.BasicCredentialRef> credentials) {
        return new TspProfileModel(UUID.randomUUID(), "p1", null, true, null, null, List.of(), methods, credentials, vaultProfileUuid);
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
            return SecretsUtil.calculateSecretContentFingerprint(
                    new BasicAuthSecretContent(username, password));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static AuthenticationInfo authenticatedInfo() {
        return new AuthenticationInfo(AuthMethod.CERTIFICATE, "uuid-1", "alice",
                List.of(new SimpleGrantedAuthority("ROLE_USER")), "{\"user\":{\"uuid\":\"uuid-1\",\"username\":\"alice\"}}");
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
            when(authClient.authenticateByCertificate(CERT_HEADER, CERT_THUMBPRINT)).thenReturn(authenticatedInfo());

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
            when(authClient.authenticateByCertificate(CERT_HEADER, CERT_THUMBPRINT)).thenReturn(authenticatedInfo());

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

        @Test
        void setsContextFromConnector() throws Exception {
            // given
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.CLIENT_CERTIFICATE)));
            request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
            when(authClient.authenticateByCertificate(CERT_HEADER, CERT_THUMBPRINT)).thenReturn(authenticatedInfo());

            // when
            filter.doFilter(request, response, chain);

            // then
            verify(authClient).authenticateByCertificate(CERT_HEADER, CERT_THUMBPRINT);
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
            Jwt jwt = Jwt.withTokenValue("the.jwt.token")
                    .header("alg", "none")
                    .claim("sub", "alice")
                    .claim("jti", "jti-1")
                    .issuedAt(issuedAt)
                    .expiresAt(issuedAt.plusSeconds(60))
                    .build();
            when(jwtDecoder.decode("the.jwt.token")).thenReturn(jwt);
            when(authClient.authenticateByToken(any())).thenReturn(authenticatedInfo());

            // when
            filter.doFilter(request, response, chain);

            // then
            verify(jwtDecoder).decode("the.jwt.token");
            verify(authClient).authenticateByToken(any());
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
            assertThat(chain.getRequest()).isNotNull();
            assertActorIsPrincipal("uuid-1", "alice");
        }
    }

    // ── BasicPassword ─────────────────────────────────────────────────────────

    @Nested
    class BasicPassword {

        @Test
        void authenticatesAsMappedUser_whenFingerprintMatches() throws Exception {
            // given
            UUID secretUuid = UUID.randomUUID();
            UUID mappedUser = UUID.randomUUID();
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1")).thenReturn(modelWith(
                    List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                    List.of(new TspProfileModel.BasicCredentialRef("alice", secretUuid, mappedUser, fingerprintOf("alice", "s3cret")))));
            request.addHeader("Authorization", basicHeader("alice", "s3cret"));
            when(credentialCache.getMappedUser(secretUuid, "s3cret")).thenReturn(Optional.empty());

            // when
            filter.doFilter(request, response, chain);

            // then
            verify(credentialCache).putSuccess(secretUuid, "s3cret", mappedUser);
            verify(authHelper).authenticateAsUser(mappedUser);
            assertThat(chain.getRequest()).isNotNull();
        }

        @Test
        void returns401_whenFingerprintMismatch() throws Exception {
            // given
            UUID secretUuid = UUID.randomUUID();
            UUID mappedUser = UUID.randomUUID();
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1")).thenReturn(modelWith(
                    List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                    List.of(new TspProfileModel.BasicCredentialRef("alice", secretUuid, mappedUser, fingerprintOf("alice", "right")))));
            request.addHeader("Authorization", basicHeader("alice", "wrong"));
            when(credentialCache.getMappedUser(secretUuid, "wrong")).thenReturn(Optional.empty());

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            verify(credentialCache, never()).putSuccess(any(), any(), any());
            verify(authHelper, never()).authenticateAsUser(any());
            assertThat(chain.getRequest()).isNull();
        }

        @Test
        void skipsFingerprintCheck_onCacheHit() throws Exception {
            // given
            UUID secretUuid = UUID.randomUUID();
            UUID mappedUser = UUID.randomUUID();
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1")).thenReturn(modelWith(
                    List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                    List.of(new TspProfileModel.BasicCredentialRef("alice", secretUuid, mappedUser, "x"))));
            request.addHeader("Authorization", basicHeader("alice", "s3cret"));
            when(credentialCache.getMappedUser(secretUuid, "s3cret")).thenReturn(Optional.of(mappedUser));

            // when
            filter.doFilter(request, response, chain);

            // then
            verify(credentialCache, never()).putSuccess(any(), any(), any());
            verify(authHelper).authenticateAsUser(mappedUser);
            assertThat(chain.getRequest()).isNotNull();
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
            UUID secretUuid = UUID.randomUUID();
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1")).thenReturn(modelWith(
                    List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                    List.of(new TspProfileModel.BasicCredentialRef("alice", secretUuid, UUID.randomUUID(), "x"))));
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
            when(authClient.authenticateByCertificate(CERT_HEADER, CERT_THUMBPRINT))
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
            // wrapper, causing Base64.getDecoder().decode to throw IllegalArgumentException. The filter must fail closed.
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
            // given — BEARER_TOKEN profile, jwtDecoder.decode returns null → filter must return 401, not continue chain.
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
            verify(authClient, never()).authenticateByToken(any());
        }

        @Test
        void failsClosed_whenBearerDecodeThrows() throws Exception {
            // given — BEARER_TOKEN profile, jwtDecoder.decode throws a RuntimeException → filter must catch and 401.
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BEARER_TOKEN)));
            request.addHeader("Authorization", "Bearer bad.token");
            when(jwtDecoder.decode("bad.token"))
                    .thenThrow(new PlatformAuthenticationException("token decode failed"));

            // when
            filter.doFilter(request, response, chain);

            // then
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            assertThat(chain.getRequest()).isNull();
            verify(authClient, never()).authenticateByToken(any());
        }

        @Test
        void failsClosedWithoutCallingConnector_whenBasicCredentialsHaveNoColon() throws Exception {
            // given — BASIC_PASSWORD profile, Authorization is "Basic <base64 of a string with no colon>".
            // decodeBasicCredentials returns null → filter must return 401 without ever consulting secretService.
            setPath("/v1/protocols/tsp/p1");
            when(tspProfileService.resolveTspProfileForAuthentication("p1"))
                    .thenReturn(modelWith(List.of(TspAuthenticationMethod.BASIC_PASSWORD), UUID.randomUUID(),
                            List.of(new TspProfileModel.BasicCredentialRef("alice", UUID.randomUUID(), UUID.randomUUID(), "x"))));
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
                            List.of(new TspProfileModel.BasicCredentialRef("alice", UUID.randomUUID(), UUID.randomUUID(), "x"))));
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
}
