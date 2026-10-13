package com.otilm.core.util;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.otilm.core.config.proxy.MultiServerAuthenticator;
import java.net.Authenticator;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;

/**
 * Covers the raw HTTP contract of the userinfo call. Lives in {@code com.otilm.core.util} because
 * {@link OAuth2Util#getUserInfo} is package-private: its callers swallow every exception, so the error mapping of
 * {@code OAuth2ErrorResponseErrorHandler} is only observable here.
 */
class OAuth2UtilUserInfoTest {

    private WireMockServer mockServer;
    private String userInfoUrl;

    @BeforeEach
    void startServer() {
        mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();
        WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());
        userInfoUrl = LoopbackWireMock.url(mockServer) + "/userinfo";
    }

    @AfterEach
    void stopServer() {
        mockServer.stop();
    }

    @Test
    void testGetUserInfo_DeserializesBodyAndSendsBearerToken() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .willReturn(WireMock.okJson("{\"sub\":\"abc\",\"groups\":[\"a\",\"b\"]}")));

        Map<String, Object> userInfo = OAuth2Util.getUserInfo(userInfoUrl, "the-token");

        Assertions.assertEquals("abc", userInfo.get("sub"));
        Assertions.assertEquals(List.of("a", "b"), userInfo.get("groups"));
        mockServer
                .verify(WireMock.exactly(1),
                        WireMock
                                .getRequestedFor(WireMock.urlPathEqualTo("/userinfo"))
                                .withHeader("Authorization", WireMock.equalTo("Bearer the-token"))
                                .withHeader("Accept", WireMock.containing("application/json")));
    }

    @Test
    void testGetUserInfo_BadRequestIsMappedToOAuth2AuthorizationException() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(400)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"invalid_token\",\"error_description\":\"token expired\"}")));

        OAuth2AuthorizationException exception = Assertions
                .assertThrows(OAuth2AuthorizationException.class,
                        () -> OAuth2Util.getUserInfo(userInfoUrl, "the-token"));

        Assertions.assertEquals("invalid_token", exception.getError().getErrorCode());
    }

    @Test
    void testGetUserInfo_ServerErrorIsPropagated() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .willReturn(WireMock.aResponse().withStatus(500)));

        Assertions.assertThrows(HttpServerErrorException.class, () -> OAuth2Util.getUserInfo(userInfoUrl, "the-token"));
    }

    /**
     * The client must keep honouring the JVM default authenticator that {@code ProxyConfiguration} installs, and must
     * not lose the bearer token while answering the proxy's 407 challenge. WireMock stands in for the proxy: a forward
     * proxy sees the same request line.
     */
    @Test
    void testGetUserInfo_AuthenticatesAgainstConfiguredForwardProxy() {
        String previousHost = System.getProperty("http.proxyHost");
        String previousPort = System.getProperty("http.proxyPort");
        Authenticator previousAuthenticator = Authenticator.getDefault();
        MultiServerAuthenticator proxyAuthenticator = new MultiServerAuthenticator();
        proxyAuthenticator.add(LoopbackWireMock.HOST + ":" + mockServer.port(), "proxy-user", "proxy-password");
        Authenticator.setDefault(proxyAuthenticator);
        System.setProperty("http.proxyHost", LoopbackWireMock.HOST);
        System.setProperty("http.proxyPort", String.valueOf(mockServer.port()));
        try {
            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/userinfo"))
                            .inScenario("proxy-auth")
                            .whenScenarioStateIs(Scenario.STARTED)
                            .willReturn(WireMock
                                    .aResponse()
                                    .withStatus(407)
                                    .withHeader("Proxy-Authenticate", "Basic realm=\"proxy\""))
                            .willSetStateTo("challenged"));
            mockServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/userinfo"))
                            .inScenario("proxy-auth")
                            .whenScenarioStateIs("challenged")
                            .willReturn(WireMock.okJson("{\"sub\":\"abc\"}")));

            Map<String, Object> userInfo = OAuth2Util.getUserInfo("http://userinfo.example.com/userinfo", "the-token");

            Assertions.assertEquals("abc", userInfo.get("sub"));
            String expectedCredentials = Base64
                    .getEncoder()
                    .encodeToString("proxy-user:proxy-password".getBytes(StandardCharsets.UTF_8));
            mockServer
                    .verify(WireMock.exactly(1),
                            WireMock
                                    .getRequestedFor(WireMock.urlPathEqualTo("/userinfo"))
                                    .withHeader("Proxy-Authorization", WireMock.equalTo("Basic " + expectedCredentials))
                                    .withHeader("Authorization", WireMock.equalTo("Bearer the-token")));
        } finally {
            Authenticator.setDefault(previousAuthenticator);
            restoreProperty("http.proxyHost", previousHost);
            restoreProperty("http.proxyPort", previousPort);
        }
    }

    /**
     * The client is shared process-wide, so a cookie jar would replay one user's provider session cookie onto every
     * other user's userinfo and logout call.
     */
    @Test
    void testGetUserInfo_DoesNotReplayProviderCookies() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .willReturn(WireMock
                                .okJson("{\"sub\":\"abc\"}")
                                .withHeader("Set-Cookie", "IDP_SESSION=first-caller-session; Path=/")));

        OAuth2Util.getUserInfo(userInfoUrl, "the-token");
        OAuth2Util.getUserInfo(userInfoUrl, "another-token");

        mockServer
                .verify(WireMock.exactly(2),
                        WireMock
                                .getRequestedFor(WireMock.urlPathEqualTo("/userinfo"))
                                .withHeader("Cookie", WireMock.absent()));
    }

    @Test
    void testGetUserInfo_StalledProviderFailsWithinTheReadTimeout() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .willReturn(WireMock.okJson("{\"sub\":\"abc\"}").withFixedDelay(60_000)));

        Assertions
                .assertTimeoutPreemptively(Duration.ofSeconds(30),
                        () -> Assertions
                                .assertThrows(ResourceAccessException.class,
                                        () -> OAuth2Util.getUserInfo(userInfoUrl, "the-token")));

        mockServer.verify(WireMock.exactly(1), WireMock.getRequestedFor(WireMock.urlPathEqualTo("/userinfo")));
    }

    /**
     * Apache honours {@code Retry-After} verbatim, so a retrying client would let the provider stall every
     * authenticated request for as long as it likes.
     */
    @Test
    void testGetUserInfo_DoesNotRetryOnServiceUnavailable() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .willReturn(WireMock.aResponse().withStatus(503).withHeader("Retry-After", "30")));

        Assertions.assertThrows(HttpServerErrorException.class, () -> OAuth2Util.getUserInfo(userInfoUrl, "the-token"));

        mockServer.verify(WireMock.exactly(1), WireMock.getRequestedFor(WireMock.urlPathEqualTo("/userinfo")));
    }

    /**
     * Apache refuses to follow a cross-authority redirect on a request carrying an {@code Authorization} header. The
     * redirect must surface as an error rather than as a silently empty claim set.
     */
    @Test
    void testGetUserInfo_UnfollowedRedirectIsReportedAsError() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(302)
                                .withHeader("Location", "http://elsewhere.example.com/userinfo")));

        RestClientException exception = Assertions
                .assertThrows(RestClientException.class, () -> OAuth2Util.getUserInfo(userInfoUrl, "the-token"));

        Assertions.assertTrue(exception.getMessage().contains("was not followed"), exception.getMessage());
    }

    /**
     * The message of anything thrown by the shared client is logged, and the logout URI carries the ID token in
     * {@code id_token_hint}, so the query string must never reach the exception message.
     */
    @Test
    void testGetUserInfo_UnfollowedRedirectDoesNotReportQueryString() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(302)
                                .withHeader("Location", "http://elsewhere.example.com/userinfo")));

        RestClientException exception = Assertions
                .assertThrows(RestClientException.class,
                        () -> OAuth2Util.getUserInfo(userInfoUrl + "?id_token_hint=super-secret-token", "the-token"));

        Assertions.assertFalse(exception.getMessage().contains("super-secret-token"), exception.getMessage());
    }

    /**
     * Dropping status-code retries must not also drop the retry on a failed connection, which is what recovers a pooled
     * connection the provider closed concurrently.
     */
    @Test
    void testGetUserInfo_RetriesOnceAfterConnectionFailure() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .inScenario("io-error")
                        .whenScenarioStateIs(Scenario.STARTED)
                        .willReturn(WireMock.aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER))
                        .willSetStateTo("recovered"));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/userinfo"))
                        .inScenario("io-error")
                        .whenScenarioStateIs("recovered")
                        .willReturn(WireMock.okJson("{\"sub\":\"abc\"}")));

        Map<String, Object> userInfo = OAuth2Util.getUserInfo(userInfoUrl, "the-token");

        Assertions.assertEquals("abc", userInfo.get("sub"));
        mockServer.verify(WireMock.exactly(2), WireMock.getRequestedFor(WireMock.urlPathEqualTo("/userinfo")));
    }

    private static void restoreProperty(String key, String previousValue) {
        if (previousValue == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, previousValue);
        }
    }
}
