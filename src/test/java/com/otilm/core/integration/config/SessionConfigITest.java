package com.otilm.core.integration.config;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.config.CookieConfig;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.util.BaseSpringBootTestNoAuth;
import com.otilm.core.util.SessionTableHelper;
import jakarta.servlet.http.Cookie;
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

import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Verifies that the default {@code CookieHttpSessionIdResolver} preserves normal session behavior for API endpoints.
 */
@AutoConfigureMockMvc
@SpringBootTest
class SessionConfigITest extends BaseSpringBootTestNoAuth {

    /**
     * Permit-all endpoint used for session-resolution assertions.
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
    PlatformAuthenticationClient authenticationClient;

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

    private Cookie sessionCookie(String sessionId) {
        // DefaultCookieSerializer base64url-encodes the session ID when writing cookies
        return new Cookie(CookieConfig.COOKIE_NAME, Base64.getUrlEncoder().encodeToString(sessionId.getBytes()));
    }

    /**
     * For API endpoints the {@code session-id} cookie must be forwarded to the session repository so that existing sessions can be resumed.
     */
    @Test
    void request_resolvesIncomingSessionCookie() throws Exception {
        mvc.perform(
                post(NON_TSP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .cookie(sessionCookie(UUID.randomUUID().toString())));

        Mockito.verify(sessionRepository, Mockito.atLeastOnce())
                .findById(Mockito.anyString());
    }

}
