package com.czertainly.core.config;

import com.czertainly.api.model.core.logging.enums.AuthMethod;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.security.authn.client.CzertainlyAuthenticationClient;
import com.czertainly.core.util.BaseSpringBootTestNoAuth;
import com.czertainly.core.util.SessionTableHelper;
import jakarta.servlet.http.Cookie;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Verifies that {@link SessionConfig#httpSessionIdResolver(org.springframework.session.web.http.CookieSerializer)}
 * correctly suppresses session handling for TSP protocol requests while preserving normal session behaviour for all
 * other API endpoints.
 */
@AutoConfigureMockMvc
@SpringBootTest
class SessionConfigTest extends BaseSpringBootTestNoAuth {

    /** TSP endpoint under test. */
    private static final String TSP_URL = "/v1/protocols/tsp/anyProfile";

    /**
     * Permit-all endpoint used for non-TSP assertions
     */
    private static final String NON_TSP_URL = "/v1/connector/register";

    @Autowired
    MockMvc mvc;

    /**
     * Spy on the real JDBC-backed repository so that the {@code SessionRepositoryFilter} exercises the actual implementation
     * while still allowing {@link Mockito#verify} assertions.
     */
    @MockitoSpyBean
    JdbcIndexedSessionRepository sessionRepository;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @MockitoBean
    CzertainlyAuthenticationClient authenticationClient;

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        // Use empty context path so the URL constants above are unambiguous
        registry.add("server.servlet.context-path", () -> "");
    }

    @BeforeEach
    void setUp() {
        SessionTableHelper.createSessionTables(jdbcTemplate);

        AuthenticationInfo authInfo = new AuthenticationInfo(
                AuthMethod.CERTIFICATE,
                UUID.randomUUID().toString(),
                "session-test-user",
                List.of()
        );
        Mockito.lenient()
                .when(authenticationClient.authenticateSystemUser(Mockito.any()))
                .thenReturn(authInfo);
    }

    @AfterEach
    void tearDown() {
        SessionTableHelper.dropSessionTables(jdbcTemplate);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private byte[] buildTspRequest() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("test-data".getBytes());
        return new TimeStampRequestGenerator().generate(TSPAlgorithms.SHA256, hash).getEncoded();
    }

    private Cookie sessionCookie(String sessionId) {
        // DefaultCookieSerializer base64url-encodes the session ID when writing cookies
        return new Cookie(CookieConfig.COOKIE_NAME, Base64.getUrlEncoder().encodeToString(sessionId.getBytes()));
    }

    // ── TSP tests ─────────────────────────────────────────────────────────────

    @Test
    void tspRequest_noSetCookieInResponse() throws Exception {
        var result = mvc.perform(
                post(TSP_URL)
                        .servletPath(TSP_URL)
                        .contentType("application/timestamp-query")
                        .content(buildTspRequest()))
                .andReturn();

        assertNull(result.getResponse().getHeader("Set-Cookie"),
                "TSP response must not carry a Set-Cookie header");
    }

    /**
     * Even when a {@code SESSION} cookie is present in the request, the TSP endpoint must ignore it.
     */
    @Test
    void tspRequest_ignoresIncomingSessionCookie() throws Exception {
        mvc.perform(
                post(TSP_URL)
                        .servletPath(TSP_URL)
                        .contentType("application/timestamp-query")
                        .content(buildTspRequest())
                        .cookie(sessionCookie(UUID.randomUUID().toString())));

        Mockito.verify(sessionRepository, Mockito.never())
                .findById(Mockito.anyString());
    }

    // ── Non-TSP tests ─────────────────────────────────────────────────────────

    /**
     * For non-TSP endpoints the {@code czertainly-session} cookie must be forwarded to the session repository so that existing sessions can be resumed.
     */
    @Test
    void nonTspRequest_resolvesIncomingSessionCookie() throws Exception {
        mvc.perform(
                post(NON_TSP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .cookie(sessionCookie(UUID.randomUUID().toString())));

        Mockito.verify(sessionRepository, Mockito.atLeastOnce())
                .findById(Mockito.anyString());
    }

    /**
     * expireSession for a TSP request must not add a Set-Cookie header (the delegate must not be called).
     */
    @Test
    void tspRequest_expireSession_doesNotClearCookie() throws Exception {
        var result = mvc.perform(
                post(TSP_URL)
                        .servletPath(TSP_URL)
                        .contentType("application/timestamp-query")
                        .content(buildTspRequest())
                        .cookie(sessionCookie(UUID.randomUUID().toString())))
                .andReturn();

        assertNull(result.getResponse().getHeader("Set-Cookie"),
                "TSP expireSession must not produce a Set-Cookie header");
    }

}
