package com.czertainly.core.security.authn;

import com.czertainly.api.model.core.logging.enums.AuthMethod;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.security.authn.client.CzertainlyAuthenticationClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CzertainlyAuthenticationFilterTest {

    private static final String CERT_HEADER_NAME = "ssl-client-cert";

    // PEM wrapping base64("test") — after normalize+decode yields DER bytes [0x74, 0x65, 0x73, 0x74]
    // expected thumbprint = SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    private static final String CERT_HEADER = "-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----\n";
    private static final String CERT_THUMBPRINT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    @Mock
    private CzertainlyAuthenticationClient authClient;

    private CzertainlyAuthenticationFilter filter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;

    @BeforeEach
    void setUp() {
        filter = new CzertainlyAuthenticationFilter(authClient, CERT_HEADER_NAME, "");
        request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1"); // non-loopback so isLocalhostAddress = false
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
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
        when(authClient.authenticate(eq(AuthMethod.NONE), isNull(), eq(false)))
                .thenReturn(authenticatedInfo());

        // when
        filter.doFilter(request, response, filterChain);

        // then
        verify(authClient).authenticate(AuthMethod.NONE, null, false);
        verify(authClient, never()).authenticateByCertificate(any(), any());
    }

    @Test
    void certHeader_present_callsCertificateAuthWithComputedThumbprint() throws Exception {
        // given
        request.addHeader(CERT_HEADER_NAME, CERT_HEADER);
        when(authClient.authenticateByCertificate(CERT_HEADER, CERT_THUMBPRINT))
                .thenReturn(authenticatedInfo());

        // when
        filter.doFilter(request, response, filterChain);

        // then - thumbprint is the SHA-256 of the DER bytes derived from the PEM content
        verify(authClient).authenticateByCertificate(CERT_HEADER, CERT_THUMBPRINT);
        verify(authClient, never()).authenticate(any(), any(), anyBoolean());
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
        assertInstanceOf(CzertainlyAuthenticationToken.class, auth);
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
        assertInstanceOf(CzertainlyAnonymousToken.class, auth);
    }

    // --- exception handling ---

    @Test
    void czertainlyAuthException_clearsContextAndContinuesChain() {
        // given
        when(authClient.authenticate(any(), any(), anyBoolean()))
                .thenThrow(new CzertainlyAuthenticationException("auth service unreachable"));

        // when - must not propagate
        assertDoesNotThrow(() -> filter.doFilter(request, response, filterChain));

        // then - context must be cleared after the failure
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void malformedCertHeader_clearsContextAndContinuesChain() {
        // given - cert header present but Base64 content is garbage (not valid DER)
        request.addHeader(CERT_HEADER_NAME, "-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n");

        // when - must not propagate a 500; the filter should swallow the malformed-header error
        assertDoesNotThrow(() -> filter.doFilter(request, response, filterChain));

        // then - no auth was stored and the auth client was never called
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(authClient, never()).authenticateByCertificate(any(), any());
    }

    @Test
    void nonCzertainlyAuthException_isRethrown() {
        // given
        when(authClient.authenticate(any(), any(), anyBoolean()))
                .thenThrow(new BadCredentialsException("unexpected"));

        // when / then
        assertThrows(BadCredentialsException.class, () -> filter.doFilter(request, response, filterChain));
    }

    // --- isAuthenticationNeeded guard cases ---

    @Test
    void permitAllEndpoint_setsAnonymousTokenWithPermitAllFlagAndSkipsAuth() throws Exception {
        // given - /v1/health/live matches the /v?/health/** permit-all pattern
        request.setRequestURI("/v1/health/live");

        // when
        filter.doFilter(request, response, filterChain);

        // then
        verifyNoInteractions(authClient);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertInstanceOf(CzertainlyAnonymousToken.class, auth);
        assertTrue(((CzertainlyAnonymousToken) auth).isAccessingPermitAllEndpoint());
    }

    @Test
    void alreadyAuthenticated_skipsAuth() throws Exception {
        // given - a prior filter already placed an authenticated token in the context
        CzertainlyAuthenticationToken existingToken =
                new CzertainlyAuthenticationToken(new CzertainlyUserDetails(authenticatedInfo()));
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
        when(authClient.authenticateByCertificate(CERT_HEADER, CERT_THUMBPRINT))
                .thenReturn(authenticatedInfo());

        // when
        filter.doFilter(request, response, filterChain);

        // then - cert path is chosen even when an Authorization header is present
        verify(authClient).authenticateByCertificate(CERT_HEADER, CERT_THUMBPRINT);
        verify(authClient, never()).authenticate(any(), any(), anyBoolean());
    }

    // --- helpers ---

    private static AuthenticationInfo authenticatedInfo() {
        return new AuthenticationInfo(AuthMethod.CERTIFICATE, "uuid-1", "alice",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }
}
