package com.czertainly.core.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.HttpSessionIdResolver;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the TSP-aware {@link HttpSessionIdResolver} produced by
 * {@link SessionConfig#httpSessionIdResolver(CookieSerializer)}.
 *
 * Spring Session calls {@code resolveSessionIds} lazily (only when application code accesses
 * {@code request.getSession()}), so TSP endpoints — which never touch the session — do not
 * exercise the TSP branches through integration tests alone. These unit tests call the resolver
 * directly to verify the TSP no-op paths.
 */
class SessionConfigUnitTest {

    private final CookieSerializer cookieSerializer = Mockito.mock(CookieSerializer.class);
    private final HttpSessionIdResolver resolver = new SessionConfig().httpSessionIdResolver(cookieSerializer);

    private HttpServletRequest tspRequest() {
        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        Mockito.when(req.getServletPath()).thenReturn("/v1/protocols/tsp/anyProfile");
        return req;
    }

    @Test
    void resolveSessionIds_tspRequest_returnsEmptyList() {
        assertTrue(resolver.resolveSessionIds(tspRequest()).isEmpty());
    }

    @Test
    void setSessionId_tspRequest_isNoop() {
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        resolver.setSessionId(tspRequest(), response, "someSessionId");
        Mockito.verifyNoInteractions(cookieSerializer);
    }

    @Test
    void expireSession_tspRequest_isNoop() {
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        resolver.expireSession(tspRequest(), response);
        Mockito.verifyNoInteractions(cookieSerializer);
    }
}
