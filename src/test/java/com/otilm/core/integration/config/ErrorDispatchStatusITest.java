package com.otilm.core.integration.config;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.core.security.authn.ForwardedCertificateFixtures;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.service.AuditLogExternalService;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.util.WireMockPorts;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sends real requests through the embedded Tomcat: its forward to the error page is a second request that the security
 * chain authorizes, and MockMvc never makes that forward.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"server.servlet.context-path=", "server.address=127.0.0.1"})
class ErrorDispatchStatusITest {

    private static final String CERTIFICATE_HEADER = "X-APP-CERTIFICATE";

    @LocalServerPort
    int port;

    @Autowired
    AuthenticationCache authenticationCache;

    // The same mocks as OAuth2LoginControllerITest, so both classes share one context.
    @MockitoBean
    AuditLogInternalService auditLogService;

    @MockitoBean
    AuditLogExternalService auditLogExternalService;

    private final HttpClient http = HttpClient.newHttpClient();

    private WireMockServer authService;

    @BeforeEach
    void setUp() {
        authenticationCache.evictAll();
        authService = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authService.start();
        authService
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/auth"))
                        .willReturn(WireMock.okJson("{\"authenticated\":false}")));
        authService
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/auth"))
                        .withRequestBody(WireMock
                                .matchingJsonPath("$.certificateContent",
                                        WireMock.equalTo(ForwardedCertificateFixtures.LEAF_DER)))
                        .atPriority(1)
                        .willReturn(WireMock.okJson("""
                                {
                                  "authenticated": true,
                                  "data": {
                                    "user": {"uuid": "%s", "username": "certificate-user"},
                                    "roles": [{"name": "superadmin"}],
                                    "permissions": {"allowAllResources": true, "resources": []}
                                  }
                                }
                                """.formatted(UUID.randomUUID()))));
    }

    @AfterEach
    void tearDown() {
        authService.stop();
    }

    @Test
    void certificateCallerGetsNotAcceptable() throws Exception {
        HttpResponse<String> response = send(request("/v1/auth/profile")
                .header(CERTIFICATE_HEADER, ForwardedCertificateFixtures.LEAF_DER)
                .header("Accept", "application/xml")
                .GET());

        assertThat(response.statusCode()).isEqualTo(406);
    }

    @Test
    void traceIsRefusedAsMethodNotAllowed() throws Exception {
        HttpResponse<String> response = send(
                request("/v1/health/liveness").method("TRACE", HttpRequest.BodyPublishers.noBody()));

        assertThat(response.statusCode()).isEqualTo(405);
        assertThat(response.headers().firstValue("Allow")).isPresent();
    }

    @Test
    void methodTheFirewallRefusesIsBadRequest() throws Exception {
        HttpResponse<String> response = send(
                request("/v1/health/liveness").method("FOO", HttpRequest.BodyPublishers.noBody()));

        assertThat(response.statusCode()).isEqualTo(400);
    }

    @Test
    void errorPageRequestedDirectlyStillNeedsAuthentication() throws Exception {
        HttpResponse<String> response = send(request("/error").GET());

        assertThat(response.statusCode()).isEqualTo(401);
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path));
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
}
