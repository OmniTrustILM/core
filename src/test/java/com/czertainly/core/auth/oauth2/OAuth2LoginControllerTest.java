package com.czertainly.core.auth.oauth2;

import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.logging.enums.OperationResult;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.czertainly.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.czertainly.core.service.AuditLogService;
import com.czertainly.core.settings.SettingsCache;
import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.net.HttpCookie;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OAuth2LoginControllerTest {

    private static WireMockServer mockServer;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("server.servlet.context-path", () -> "");
        registry.add("auth-service.base-url", () -> "http://localhost:10003");
    }

    @LocalServerPort
    int port;

    @Autowired
    SettingsCache settingsCache;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    AuditLogService auditLogService;

    private HttpClient http;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        setupSessionTables();
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());
        reset(auditLogService);
    }

    private void setupSessionTables() {
        jdbcTemplate.execute("CREATE SCHEMA IF NOT EXISTS core;");

        // Create spring_session table
        jdbcTemplate.execute("""
                    CREATE TABLE IF NOT EXISTS core.spring_session (
                        PRIMARY_ID CHAR(36) NOT NULL,
                        SESSION_ID CHAR(36) NOT NULL,
                        CREATION_TIME BIGINT NOT NULL,
                        LAST_ACCESS_TIME BIGINT NOT NULL,
                        MAX_INACTIVE_INTERVAL INT NOT NULL,
                        EXPIRY_TIME BIGINT NOT NULL,
                        PRINCIPAL_NAME VARCHAR(100),
                        CONSTRAINT spring_session_pkey PRIMARY KEY(PRIMARY_ID)
                    );
                """);

        // Create spring_session_attributes table
        jdbcTemplate.execute("""
                    CREATE TABLE IF NOT EXISTS core.spring_session_attributes (
                        SESSION_PRIMARY_ID CHAR(36) NOT NULL,
                        ATTRIBUTE_NAME VARCHAR(200) NOT NULL,
                        ATTRIBUTE_BYTES JSONB,
                        CONSTRAINT spring_session_attributes_pkey PRIMARY KEY(SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
                        CONSTRAINT fk_session FOREIGN KEY(SESSION_PRIMARY_ID) REFERENCES core.spring_session(PRIMARY_ID) ON DELETE CASCADE
                    );
                """);
    }

    @AfterEach
    void tearDown() {
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());
        if (mockServer != null) {
            mockServer.stop();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/login", "/v2/oauth2/providers"})
    void shouldFailAndInvalidateSessionWhenErrorPresent(String path) throws Exception {
        // 1) Hit endpoint once to establish a session cookie
        HttpResponse<String> first = http.send(
                HttpRequest.newBuilder(uri(path + "?redirect=/ui"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );
        String sessionCookie = extractSessionCookie(first.headers());
        Assertions.assertNotNull(sessionCookie);

        // 2) Call endpoint with error, using the same cookie → should invalidate
        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(uri(path + "?redirect=/ui&error=oops"))
                        .header("Cookie", sessionCookie)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );

        Assertions.assertTrue(res.statusCode() >= 400);

        // 3) A subsequent call with the same cookie should behave like a fresh session (i.e., server issues a new session cookie)
        HttpResponse<String> after = http.send(
                HttpRequest.newBuilder(uri(path + "?redirect=/ui"))
                        .header("Cookie", sessionCookie)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );
        String newSessionCookie = extractSessionCookie(after.headers());
        Assertions.assertNotNull(newSessionCookie);
        Assertions.assertNotEquals(sessionCookie, newSessionCookie);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/login", "/v2/oauth2/providers"})
    void shouldReturnConfiguredProviders(String path) throws Exception {
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        providers.put("one", validProvider("one", 123));
        providers.put("two", validProvider("two", 456));
        providers.put("bad", new OAuth2ProviderSettingsDto());
        settings.setOAuth2Providers(providers);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settings);

        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(uri(path + "?redirect=/ui"))
                        .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );

        Assertions.assertEquals(200, res.statusCode());
        Assertions.assertTrue(res.headers().firstValue("Content-Type").orElse("").contains("application/json"));

        String json = res.body();
        Assertions.assertTrue(json.contains("\"name\":\"one\""));
        Assertions.assertTrue(json.contains("\"name\":\"two\""));
        Assertions.assertFalse(json.contains("\"name\":\"bad\""));

        String expectedProvider1Path = path.equals("/login") ? "/oauth2/authorization/one/prepare" : "/v2/oauth2/providers/one/login";
        String expectedProvider2Path = path.equals("/login") ? "/oauth2/authorization/two/prepare" : "/v2/oauth2/providers/two/login";
        Assertions.assertTrue(json.contains(expectedProvider1Path));
        Assertions.assertTrue(json.contains(expectedProvider2Path));
    }

    @Test
    void loginShouldRedirectToProviderWhenExactlyOneValidProvider() throws Exception {
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        providers.put("only", validProvider("only", 321));
        settings.setOAuth2Providers(providers);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settings);

        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(uri("/login?redirect=/ui"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );

        // controller does sendRedirect("oauth2/authorization/{provider}") => 302
        Assertions.assertTrue(res.statusCode() >= 300 && res.statusCode() < 400);
        Assertions.assertEquals("http://localhost:" + port + "/oauth2/authorization/only", res.headers().firstValue("Location").orElse(null));

        // We can’t directly introspect server-side session here; instead, verify session cookie exists.
        Assertions.assertNotNull(extractSessionCookie(res.headers()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/oauth2/authorization/%s/prepare", "/v2/oauth2/providers/%s/login"})
    void shouldRedirectWhenProviderKnown(String pathTemplate) throws Exception {
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        providers.put("test", validProvider("test", 999));
        settings.setOAuth2Providers(providers);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settings);

        String path = String.format(pathTemplate, "test");
        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(uri(path + "?redirect=/test-redirect"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );

        Assertions.assertTrue(res.statusCode() >= 300 && res.statusCode() < 400);
        String location = res.headers().firstValue("Location").orElse("");
        Assertions.assertTrue(location.endsWith("/oauth2/authorization/test"),
                "Expected Location to end with '/oauth2/authorization/test' but was: " + location);
    }

    @Test
    void loginShouldSucceedWithTypicalQueryParameter() throws Exception {
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        providers.put("only", validProvider("only", 321));
        settings.setOAuth2Providers(providers);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settings);

        // Typical query parameter: redirect=%2Fadministrator%2F (which is /administrator/)
        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(uri("/login?redirect=%2Fadministrator%2F"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );

        Assertions.assertTrue(res.statusCode() >= 300 && res.statusCode() < 400);
        // The Location should NOT contain the redirect anymore
        Assertions.assertEquals("http://localhost:" + port + "/oauth2/authorization/only", res.headers().firstValue("Location").orElse(null));
    }

    @Test
    void loginShouldSucceedWithQueryAndFragment() throws Exception {
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        providers.put("only", validProvider("only", 321));
        settings.setOAuth2Providers(providers);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settings);

        // redirect=/administrator/?foo=bar#baz
        // Encoded: /login?redirect=%2Fadministrator%2F%3Ffoo%3Dbar%23baz
        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(uri("/login?redirect=%2Fadministrator%2F%3Ffoo%3Dbar%23baz"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );

        Assertions.assertTrue(res.statusCode() >= 300 && res.statusCode() < 400);
        Assertions.assertEquals("http://localhost:" + port + "/oauth2/authorization/only", res.headers().firstValue("Location").orElse(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/oauth2/authorization/unknown/prepare", "/v2/oauth2/providers/unknown/login"})
    void shouldAuditAndFailWhenProviderUnknown(String path) throws Exception {
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());

        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(uri(path + "?redirect=/ui"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );

        Assertions.assertTrue(res.statusCode() >= 400);
        verify(auditLogService, times(1)).logAuthentication(eq(Operation.LOGIN), eq(OperationResult.FAILURE), contains("Unknown OAuth2 Provider"), any());
    }

    @Test
    void jwkSetShouldReturnDecodedJwkSet() throws Exception {
        String jwkJson = "{\"keys\":[]}";
        String jwkEncoded = Base64.getEncoder().encodeToString(jwkJson.getBytes(StandardCharsets.UTF_8));

        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        OAuth2ProviderSettingsDto provider = validProvider("test", 10);
        provider.setJwkSet(jwkEncoded);
        provider.setJwkSetUrl(null);
        providers.put("test", provider);
        settings.setOAuth2Providers(providers);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settings);

        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(uri("/oauth2/test/jwkSet"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );

        Assertions.assertEquals(200, res.statusCode());
        Assertions.assertEquals(MediaType.APPLICATION_JSON_VALUE, res.headers().firstValue("Content-type").orElse(null));
        Assertions.assertEquals(jwkJson, res.body());
    }

    @Test
    void jwkSetShouldFailWhenJwkSetMissing() throws Exception {
        AuthenticationSettingsDto settings = new AuthenticationSettingsDto();
        Map<String, OAuth2ProviderSettingsDto> providers = new HashMap<>();
        OAuth2ProviderSettingsDto provider = validProvider("test", 10);
        provider.setJwkSet(null);
        providers.put("test", provider);
        settings.setOAuth2Providers(providers);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settings);

        HttpResponse<String> res = http.send(
                HttpRequest.newBuilder(uri("/oauth2/test/jwkSet"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );

        Assertions.assertTrue(res.statusCode() >= 400);
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    private static String extractSessionCookie(HttpHeaders headers) {
        // Default for Spring Session/Tomcat is JSESSIONID; for Spring Session it can be SESSION.
        // For CZERTAINLY, the custom session cookie name is czertainly-session.
        List<String> setCookies = headers.allValues("Set-Cookie");
        Optional<String> match = setCookies.stream()
                .map(HttpCookie::parse)
                .flatMap(List::stream)
                .filter(c -> c.getName().equalsIgnoreCase("JSESSIONID") || c.getName().equalsIgnoreCase("SESSION") || c.getName().equalsIgnoreCase("czertainly-session"))
                .findFirst()
                .map(c -> c.getName() + "=" + c.getValue());

        return match.orElse(null);
    }

    private static OAuth2ProviderSettingsDto validProvider(String name, int sessionMaxInactiveInterval) {
        OAuth2ProviderSettingsDto p = new OAuth2ProviderSettingsDto();
        p.setName(name);
        p.setClientId("client");
        p.setClientSecret("secret");
        p.setAuthorizationUrl("http://auth");
        p.setTokenUrl("http://token");
        p.setJwkSetUrl("http://jwk");
        p.setLogoutUrl("http://logout");
        p.setPostLogoutUrl("http://post-logout");
        p.setSessionMaxInactiveInterval(sessionMaxInactiveInterval);
        return p;
    }
}
