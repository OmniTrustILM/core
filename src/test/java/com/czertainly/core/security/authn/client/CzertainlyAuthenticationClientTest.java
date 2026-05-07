package com.czertainly.core.security.authn.client;

import com.czertainly.api.model.core.logging.enums.AuthMethod;
import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.czertainly.core.service.AuditLogService;
import com.czertainly.core.service.impl.AuditLogServiceImpl;
import com.czertainly.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CzertainlyAuthenticationClientTest extends BaseSpringBootTest {
    private static MockWebServer authServiceMock;

    private CzertainlyAuthenticationClient czertainlyAuthenticationClient;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuthenticationCache authenticationCache;

    // @formatter:off
    String RAW_DATA = "{" +
            "\"authenticated\": true," +
            "\"data\": {" +
            "\"user\": {" +
            "\"uuid\": \"a1b2c3d4-0000-0000-0000-000000000001\"," +
            "\"username\": \"FrantisekJednicka\"," +
            "\"enabled\": true" +
            "}," +
            "\"roles\": [" +
            "{\"uuid\":\"32281955-eed2-4520-9f42-15b82c96f928\",\"name\":\"ROLE_ADMINISTRATOR\"}," +
            "{\"uuid\":\"32281955-eed2-4520-9f42-15b82c96f930\",\"name\":\"ROLE_USER\"}" +
            "]" +
            "}" +
            "}";

    @BeforeEach
    void setup() throws IOException {
        authServiceMock = new MockWebServer();
        authServiceMock.start();

        String authServiceBaseUrl = "http://%s:%d".formatted(authServiceMock.getHostName(), authServiceMock.getPort());
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        czertainlyAuthenticationClient = new CzertainlyAuthenticationClient(auditLogService, objectMapper, authenticationCache, authServiceBaseUrl);
        authenticationCache.evictAll();
    }

    @AfterAll
    static void tearDown() throws IOException {
        authServiceMock.close();
        authServiceMock.shutdown();
    }

    @AfterEach
    void cleanup() {
        try {
            // Clear the last request by reading it
            authServiceMock.takeRequest(50, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            // No request found, no cleanup needed
        }
    }

    @Test
    void extractAuthenticationInfoFromResponse() {
        // given
        setUpSuccessfulAuthenticationResponse();

        // when
        AuthenticationInfo info = czertainlyAuthenticationClient.authenticate(AuthMethod.NONE, null, false);

        // then
        assertEquals("FrantisekJednicka", info.getUsername());
        // @formatter:off
        assertEquals("{" +
                        "\"user\":{" +
                        "\"uuid\":\"a1b2c3d4-0000-0000-0000-000000000001\"," +
                        "\"username\":\"FrantisekJednicka\"," +
                        "\"enabled\":true" +
                        "}," +
                        "\"roles\":[" +
                        "{\"uuid\":\"32281955-eed2-4520-9f42-15b82c96f928\",\"name\":\"ROLE_ADMINISTRATOR\"}," +
                        "{\"uuid\":\"32281955-eed2-4520-9f42-15b82c96f930\",\"name\":\"ROLE_USER\"}" +
                        "]" +
                        "}",
                info.getRawData()

        );
        // @formatter:on
        assertEquals(
                List.of("ROLE_ADMINISTRATOR", "ROLE_USER"),
                info.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
        );

    }

    @Test
    void throwsAuthenticationExceptionWhenEmptyBodyIsReturned() {
        // given
        setUpEmptyResponse();

        // when
        Executable willThrow = () -> czertainlyAuthenticationClient.authenticate(AuthMethod.NONE, null, false);

        // then
        assertThrows(CzertainlyAuthenticationException.class, willThrow);
    }

    @Test
    void throwsAuthenticationExceptionWhenServiceReturns500() {
        // given
        setUpFaultyResponse();

        // when
        Executable willThrow = () -> czertainlyAuthenticationClient.authenticate(AuthMethod.NONE, null, false);

        // then
        assertThrows(CzertainlyAuthenticationException.class, willThrow);
    }

    // --- authenticateSystemUser ---

    @Test
    void authenticateSystemUser_cacheMiss_callsAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();

        // when
        AuthenticationInfo result = czertainlyAuthenticationClient.authenticateSystemUser("superadmin");

        // then
        assertEquals("FrantisekJednicka", result.getUsername());
        assertEquals(1, authServiceMock.getRequestCount());
    }

    @Test
    void authenticateSystemUser_cacheHit_doesNotCallAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();
        czertainlyAuthenticationClient.authenticateSystemUser("superadmin"); // prime the cache

        // when
        czertainlyAuthenticationClient.authenticateSystemUser("superadmin");

        // then
        assertEquals(1, authServiceMock.getRequestCount());
    }

    // --- authenticateByUserUuid ---

    @Test
    void authenticateByUserUuid_cacheMiss_callsAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();
        UUID userUuid = UUID.randomUUID();

        // when
        AuthenticationInfo result = czertainlyAuthenticationClient.authenticateByUserUuid(userUuid);

        // then
        assertEquals("FrantisekJednicka", result.getUsername());
        assertEquals(1, authServiceMock.getRequestCount());
    }

    @Test
    void authenticateByUserUuid_cacheHit_doesNotCallAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();
        UUID userUuid = UUID.randomUUID();
        czertainlyAuthenticationClient.authenticateByUserUuid(userUuid); // prime the cache

        // when
        czertainlyAuthenticationClient.authenticateByUserUuid(userUuid);

        // then
        assertEquals(1, authServiceMock.getRequestCount());
    }

    // --- authenticateByCertificate ---

    @Test
    void authenticateByCertificate_cacheMiss_callsAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();

        // when
        AuthenticationInfo result = czertainlyAuthenticationClient.authenticateByCertificate("TEST_CERT_CONTENT", "sha256-fingerprint-abc");

        // then
        assertEquals("FrantisekJednicka", result.getUsername());
        assertEquals(1, authServiceMock.getRequestCount());
    }

    @Test
    void authenticateByCertificate_cacheHit_doesNotCallAuthService() {
        // given - cache key is the fingerprint, not the raw cert content
        setUpSuccessfulAuthenticationResponse();
        czertainlyAuthenticationClient.authenticateByCertificate("TEST_CERT_CONTENT", "sha256-fingerprint-abc"); // prime the cache

        // when - same fingerprint, different raw content; the cache should serve the result
        czertainlyAuthenticationClient.authenticateByCertificate("OTHER_CERT_CONTENT", "sha256-fingerprint-abc");

        // then
        assertEquals(1, authServiceMock.getRequestCount());
    }

    // --- authenticateByToken ---

    @Test
    void authenticateByToken_cacheMiss_callsAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();
        Map<String, Object> claims = Map.of("jti", "jti-test-123");

        // when
        AuthenticationInfo result = czertainlyAuthenticationClient.authenticateByToken(claims);

        // then
        assertEquals("FrantisekJednicka", result.getUsername());
        assertEquals(1, authServiceMock.getRequestCount());
    }

    @Test
    void authenticateByToken_cacheHit_doesNotCallAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();
        Map<String, Object> claims = Map.of("jti", "jti-test-123");
        czertainlyAuthenticationClient.authenticateByToken(claims); // prime the cache

        // when
        czertainlyAuthenticationClient.authenticateByToken(claims);

        // then
        assertEquals(1, authServiceMock.getRequestCount());
    }

    @Test
    void authenticateByToken_nullJti_alwaysCallsAuthService() {
        // given - tokens without a jti claim cannot be uniquely identified, so caching is always skipped
        setUpSuccessfulAuthenticationResponse();
        setUpSuccessfulAuthenticationResponse();
        Map<String, Object> claimsWithoutJti = Map.of("sub", "user-123");

        // when
        czertainlyAuthenticationClient.authenticateByToken(claimsWithoutJti);
        czertainlyAuthenticationClient.authenticateByToken(claimsWithoutJti);

        // then
        assertEquals(2, authServiceMock.getRequestCount());
    }

    RecordedRequest getLastRequest() throws InterruptedException {
        return authServiceMock.takeRequest(500, TimeUnit.MILLISECONDS);
    }
    // @formatter:on

    void setUpSuccessfulAuthenticationResponse() {
        authServiceMock.enqueue(
                new MockResponse()
                        .setResponseCode(200)
                        .setHeader("content-type", "application/json")
                        .setBody(RAW_DATA)
        );
    }

    void setUpEmptyResponse() {
        authServiceMock.enqueue(
                new MockResponse()
                        .setResponseCode(200)
                        .setHeader("content-type", "application/json")
        );
    }

    void setUpFaultyResponse() {
        authServiceMock.enqueue(
                new MockResponse()
                        .setResponseCode(500)
        );
    }
}