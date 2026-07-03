package com.otilm.core.integration.config;

import com.otilm.core.config.CookieConfig;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.util.BaseSpringBootTestNoAuth;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies the dedicated {@code @Order(1)} TSP {@link org.springframework.security.web.SecurityFilterChain}:
 * <ul>
 *   <li>a TSP request with no credentials is rejected with {@code 401} by the TSP chain;</li>
 *   <li>the {@code /v1/tspProfiles} management API is served by the catch-all {@code @Order(2)} chain and is
 *       unaffected by the TSP chain's {@code 401} backstop;</li>
 *   <li>a TSP request establishes no session cookie (the JDBC session filter sets no {@code SESSION} cookie).</li>
 * </ul>
 */
@AutoConfigureMockMvc
class TspSecurityChainITest extends BaseSpringBootTestNoAuth {

    @Autowired
    MockMvc mvc;

    @Autowired
    AuthenticationCache authenticationCache;

    @MockitoBean
    private JdbcIndexedSessionRepository sessionRepository;

    @MockitoBean
    private GenericConversionService springSessionConversionService;

    @MockitoBean
    public SessionRepositoryFilter springSessionRepositoryFilter;

    WireMockServer mockServer;

    static final String CERTIFICATE_HEADER_VALUE = "certificate";
    static final String CERTIFICATE_USER_USERNAME = "certificate-user";

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:10003");
        registry.add("server.servlet.context-path", () -> "");
    }

    @BeforeEach
    void resetCachesAndStubAuthService() throws Exception {
        authenticationCache.evictAll();

        Mockito.doAnswer(invocation -> {
            ServletRequest request = invocation.getArgument(0);
            ServletResponse response = invocation.getArgument(1);
            FilterChain filterChain = invocation.getArgument(2);
            filterChain.doFilter(request, response);
            return null;
        }).when(springSessionRepositoryFilter).doFilter(Mockito.any(), Mockito.any(), Mockito.any());

        mockServer = new WireMockServer(10003);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        String certificateUserUuid = UUID.randomUUID().toString();
        addAuthPostStub(CERTIFICATE_HEADER_VALUE, certificateUserUuid, CERTIFICATE_USER_USERNAME);
        addAuthGetSub(certificateUserUuid, CERTIFICATE_USER_USERNAME);
    }

    @AfterEach
    void stopMockServer() {
        mockServer.stop();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void addAuthPostStub(String requestBody, String userUuid, String username) {
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/auth"))
                .withRequestBody(WireMock.containing(requestBody))
                .willReturn(WireMock.okJson(String.format("""
                        {
                          "authenticated": true,
                          "data": {
                            "user": { "uuid": "%s", "username": "%s" },
                            "roles": [ { "name": "superadmin" } ],
                            "permissions": { "allowAllResources": true, "resources": [] }
                          }
                        }
                        """, userUuid, username))));
    }

    private void addAuthGetSub(String userUuid, String username) {
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/" + userUuid)).willReturn(
                WireMock.okJson(String.format("{ \"username\": \"%s\", \"roles\": [{\"name\": \"superadmin\"}]}", username))
        ));
    }

    private String path(String suffix) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + suffix;
    }

    @Test
    void returnsUnauthorized_whenTspRequestHasNoCredentials() throws Exception {
        // when
        MvcResult result = mvc.perform(post(path("/v1/protocols/tsp/Unknown Profile/sign")))
                .andExpect(status().isUnauthorized())
                .andReturn();

        // then — a TSP request establishes no session cookie
        assertThat(result.getResponse().getCookie(CookieConfig.COOKIE_NAME))
                .as("TSP chain must not set a session cookie")
                .isNull();
    }

    @Test
    void servesManagementApiViaCatchAllChain() throws Exception {
        // given — a valid certificate header so the @Order(2) catch-all chain authenticates the caller

        // when — the /v1/tspProfiles management endpoint is served by the catch-all chain
        MvcResult result = mvc.perform(get(path("/v1/tspProfiles"))
                .header("X-APP-CERTIFICATE", CERTIFICATE_HEADER_VALUE)).andReturn();

        // then — the request must not be short-circuited as unauthenticated by the TSP chain
        assertThat(result.getResponse().getStatus())
                .as("management API must not be rejected as unauthenticated by the catch-all chain")
                .isNotEqualTo(401);
    }
}
