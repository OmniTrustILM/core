package com.otilm.core.security.authn;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlatformAuthenticationFilterTest {

    private static final String CERT_HEADER_NAME = "ssl-client-cert";

    private static final String CERT_HEADER = java.net.URLEncoder
            .encode(com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_PEM,
                    java.nio.charset.StandardCharsets.UTF_8);
    private static final String CERT_THUMBPRINT = com.otilm.core.security.authn.ForwardedCertificateFixtures.THUMBPRINT;

    @Mock
    private PlatformAuthenticationClient authClient;

    private PlatformAuthenticationFilter filter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;

    @BeforeEach
    void setUp() {
        filter = new PlatformAuthenticationFilter(authClient, CERT_HEADER_NAME, "");
        request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1"); // non-loopback so isLocalhostAddress = false
        response = new MockHttpServletResponse();
        filterChain = spy(new MockFilterChain());
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // --- authentication routing ---

    @Test
    void noCertHeader_callsNoneAuth() throws Exception {
        // given
        when(authClient.authenticate(eq(AuthMethod.NONE), isNull(), eq(false))).thenReturn(authenticatedInfo());

        // when
        filter.doFilter(request, response, filterChain);

        // then
        verify(authClient).authenticate(AuthMethod.NONE, null, false);
        verify(authClient, never()).authenticateByCertificate(any());
    }

    @Test
    void certHeader_present_callsCertificateAuthWithComputedThumbprint() throws Exception {
        // given
        request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
        when(authClient.authenticateByCertificate(argThat(cert -> CERT_THUMBPRINT.equals(cert.thumbprint()))))
                .thenReturn(authenticatedInfo());

        // when
        filter.doFilter(request, response, filterChain);

        // then - thumbprint identifies the leaf certificate
        verify(authClient).authenticateByCertificate(argThat(cert -> CERT_THUMBPRINT.equals(cert.thumbprint())));
        verify(authClient, never()).authenticate(any(), any(), anyBoolean());
    }

    @ParameterizedTest
    @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#supportedHeaders")
    void authenticatesSupportedCertificateHeaders(String header, String content, String thumbprint) throws Exception {
        request.addHeader(CERT_HEADER_NAME, header);
        when(authClient
                .authenticateByCertificate(
                        argThat(cert -> content.equals(cert.content()) && thumbprint.equals(cert.thumbprint()))))
                .thenReturn(authenticatedInfo());
        filter.doFilter(request, response, filterChain);
        assertInstanceOf(PlatformAuthenticationToken.class, SecurityContextHolder.getContext().getAuthentication());
        verify(authClient)
                .authenticateByCertificate(
                        argThat(cert -> content.equals(cert.content()) && thumbprint.equals(cert.thumbprint())));
    }

    @ParameterizedTest
    @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#malformedHeaders")
    void refusesMalformedCertificateHeaders(String header) {
        request.addHeader(CERT_HEADER_NAME, header);
        assertDoesNotThrow(() -> filter.doFilter(request, response, filterChain));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
        verifyNoInteractions(authClient, filterChain);
    }

    @Test
    void rfcCompanionCandidatesReachAuthThroughConfiguredHeader() throws Exception {
        filter = new PlatformAuthenticationFilter(authClient, "Custom-Cert", "");
        request.addHeader("Custom-Cert", ":" + ForwardedCertificateFixtures.LEAF_DER + ":");
        request.addHeader("Client-Cert-Chain", ":" + ForwardedCertificateFixtures.ISSUER_DER + ":");
        when(authClient.authenticateByCertificate(any())).thenReturn(authenticatedInfo());
        filter.doFilter(request, response, filterChain);
        verify(authClient)
                .authenticateByCertificate(argThat(cert -> cert.content().equals(ForwardedCertificateFixtures.LEAF_DER)
                        && cert.chain().equals(List.of(ForwardedCertificateFixtures.ISSUER_DER))));
    }

    @Test
    void malformedRfcCompanionPreventsCertificateAndAnonymousFallback() throws Exception {
        request.addHeader(CERT_HEADER_NAME, ":" + ForwardedCertificateFixtures.LEAF_DER + ":");
        request.addHeader("Client-Cert-Chain", ":dGVzdA==:");
        request.addHeader("Authorization", "Bearer token");
        filter.doFilter(request, response, filterChain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verifyNoInteractions(authClient);
    }

    // --- SecurityContext outcome ---

    @Test
    void authenticatedResult_setsAuthenticationToken() throws Exception {
        // given
        when(authClient.authenticate(any(), any(), anyBoolean())).thenReturn(authenticatedInfo());

        // when
        filter.doFilter(request, response, filterChain);

        // then
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertInstanceOf(PlatformAuthenticationToken.class, auth);
        assertTrue(auth.isAuthenticated());
    }

    @Test
    void anonymousResult_setsAnonymousToken() throws Exception {
        // given
        when(authClient.authenticate(any(), any(), anyBoolean()))
                .thenReturn(AuthenticationInfo.getAnonymousAuthenticationInfo());

        // when
        filter.doFilter(request, response, filterChain);

        // then
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertInstanceOf(PlatformAnonymousToken.class, auth);
    }

    @Test
    void anonymousCertificateResultTerminatesChain() throws Exception {
        request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
        when(authClient.authenticateByCertificate(any()))
                .thenReturn(AuthenticationInfo.getAnonymousAuthenticationInfo());
        filter.doFilter(request, response, filterChain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        org.junit.jupiter.api.Assertions.assertEquals(401, response.getStatus());
        assertNull(filterChain.getRequest());
    }

    @Test
    void certificateAuthenticationExceptionTerminatesChain() throws Exception {
        request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
        when(authClient.authenticateByCertificate(any())).thenThrow(new BadCredentialsException("refused"));
        filter.doFilter(request, response, filterChain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        org.junit.jupiter.api.Assertions.assertEquals(401, response.getStatus());
        assertNull(filterChain.getRequest());
    }

    @Test
    void oauthEndpointWithoutPriorAuthenticationKeepsItsSelectionWithCertificateHeader() throws Exception {
        request.setRequestURI("/oauth2/authorization/test");
        request.addHeader(CERT_HEADER_NAME, "invalid");
        filter.doFilter(request, response, filterChain);
        verifyNoInteractions(authClient);
        assertInstanceOf(PlatformAnonymousToken.class, SecurityContextHolder.getContext().getAuthentication());
        assertSame(request, filterChain.getRequest());
    }

    // --- exception handling ---

    @Test
    void authException_clearsContextAndContinuesChain() {
        // given
        when(authClient.authenticate(any(), any(), anyBoolean()))
                .thenThrow(new PlatformAuthenticationException("auth service unreachable"));

        // when - must not propagate
        assertDoesNotThrow(() -> filter.doFilter(request, response, filterChain));

        // then - context must be cleared after the failure
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void malformedCertHeader_clearsContextAndTerminatesChain() {
        // given - cert header present but Base64 content is garbage (not valid DER)
        request
                .addHeader(CERT_HEADER_NAME,
                        "-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n");

        // when - must not propagate a 500; the filter should swallow the malformed-header error
        assertDoesNotThrow(() -> filter.doFilter(request, response, filterChain));

        // then - no auth was stored and the auth client was never called
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
        verify(authClient, never()).authenticateByCertificate(any());
        verifyNoInteractions(filterChain);
    }

    @Test
    void nonPlatformAuthException_isRethrown() {
        // given
        when(authClient.authenticate(any(), any(), anyBoolean())).thenThrow(new BadCredentialsException("unexpected"));

        // when / then
        assertThrows(BadCredentialsException.class, () -> filter.doFilter(request, response, filterChain));
    }

    // --- isAuthenticationNeeded guard cases ---

    @Test
    void permitAllEndpoint_setsAnonymousTokenWithPermitAllFlagAndSkipsAuth() throws Exception {
        // given - /v1/health/live matches the /v?/health/** permit-all pattern
        request.setRequestURI("/v1/health/live");
        request.addHeader(CERT_HEADER_NAME, "invalid");

        // when
        filter.doFilter(request, response, filterChain);

        // then
        verifyNoInteractions(authClient);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertInstanceOf(PlatformAnonymousToken.class, auth);
        assertTrue(((PlatformAnonymousToken) auth).isAccessingPermitAllEndpoint());
    }

    @Test
    void alreadyAuthenticated_skipsAuth() throws Exception {
        // given - a prior filter already placed an authenticated token in the context
        PlatformAuthenticationToken existingToken = new PlatformAuthenticationToken(
                new PlatformUserDetails(authenticatedInfo()));
        var ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(existingToken);
        SecurityContextHolder.setContext(ctx);

        // when
        filter.doFilter(request, response, filterChain);

        // then
        verifyNoInteractions(authClient);
        assertSame(existingToken, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void authorizationHeaderOnly_noCertHeader_skipsAuth() throws Exception {
        // given - bearer token present but no cert header; OAuth2 filter handles this path
        request.addHeader("Authorization", "Bearer some.jwt.token");

        // when
        filter.doFilter(request, response, filterChain);

        // then
        verifyNoInteractions(authClient);
    }

    @Test
    void authorizationAndCertHeaderPresent_certTakesPrecedence() throws Exception {
        // given
        request.addHeader("Authorization", "Bearer some.jwt.token");
        request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
        when(authClient.authenticateByCertificate(argThat(cert -> CERT_THUMBPRINT.equals(cert.thumbprint()))))
                .thenReturn(authenticatedInfo());

        // when
        filter.doFilter(request, response, filterChain);

        // then - cert path is chosen even when an Authorization header is present
        verify(authClient).authenticateByCertificate(argThat(cert -> CERT_THUMBPRINT.equals(cert.thumbprint())));
        verify(authClient, never()).authenticate(any(), any(), anyBoolean());
    }

    // --- helpers ---

    private static AuthenticationInfo authenticatedInfo() {
        return new AuthenticationInfo(AuthMethod.CERTIFICATE, "uuid-1", "alice",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }
}
