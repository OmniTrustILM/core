package com.otilm.core.integration.security.authn.client;

import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.records.ActorRecord;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.function.Executable;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PlatformAuthenticationClientITest extends BaseSpringBootTest {
    private static MockWebServer authServiceMock;

    private PlatformAuthenticationClient authenticationClient;

    @Autowired
    private AuditLogInternalService auditLogService;

    @Autowired
    private AuthenticationCache authenticationCache;

    // @formatter:off
    private static final String RAW_DATA = "{" +
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
        authenticationClient = new PlatformAuthenticationClient(auditLogService, objectMapper, authenticationCache, authServiceBaseUrl);
        authenticationCache.evictAll();
    }

    @AfterAll
    static void tearDown() throws IOException {
        authServiceMock.close();
        authServiceMock.shutdown();
    }

    @AfterEach
    void cleanup() {
        MDC.clear();
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
        AuthenticationInfo info = authenticationClient.authenticate(AuthMethod.NONE, null, false);

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
                        .toList()
        );

    }

    @Test
    void throwsAuthenticationExceptionWhenEmptyBodyIsReturned() {
        // given
        setUpEmptyResponse();

        // when
        Executable willThrow = () -> authenticationClient.authenticate(AuthMethod.NONE, null, false);

        // then
        assertThrows(PlatformAuthenticationException.class, willThrow);
    }

    @Test
    void throwsAuthenticationExceptionWhenServiceReturns500() {
        // given
        setUpFaultyResponse();

        // when
        Executable willThrow = () -> authenticationClient.authenticate(AuthMethod.NONE, null, false);

        // then
        assertThrows(PlatformAuthenticationException.class, willThrow);
    }

    // --- authenticateSystemUser ---

    @Test
    void authenticateSystemUser_cacheMiss_callsAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();

        // when
        AuthenticationInfo result = authenticationClient.authenticateSystemUser("superadmin");

        // then
        assertEquals("FrantisekJednicka", result.getUsername());
        assertEquals(1, authServiceMock.getRequestCount());
    }

    @Test
    void authenticateSystemUser_cacheHit_doesNotCallAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();
        authenticationClient.authenticateSystemUser("superadmin"); // prime the cache

        // when
        authenticationClient.authenticateSystemUser("superadmin");

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
        AuthenticationInfo result = authenticationClient.authenticateByUserUuid(userUuid);

        // then
        assertEquals("FrantisekJednicka", result.getUsername());
        assertEquals(1, authServiceMock.getRequestCount());
    }

    @Test
    void authenticateByUserUuid_cacheHit_doesNotCallAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();
        UUID userUuid = UUID.randomUUID();
        authenticationClient.authenticateByUserUuid(userUuid); // prime the cache

        // when
        authenticationClient.authenticateByUserUuid(userUuid);

        // then
        assertEquals(1, authServiceMock.getRequestCount());
    }

    // --- authenticateByCertificate ---

    @Test
    void authenticateByCertificate_cacheMiss_callsAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();

        // when
        AuthenticationInfo result = authenticationClient.authenticateByCertificate("TEST_CERT_CONTENT", "sha256-fingerprint-abc");

        // then
        assertEquals("FrantisekJednicka", result.getUsername());
        assertEquals(1, authServiceMock.getRequestCount());
    }

    @Test
    void authenticateByCertificate_cacheHit_doesNotCallAuthService() {
        // given - cache key is the fingerprint, not the raw cert content
        setUpSuccessfulAuthenticationResponse();
        authenticationClient.authenticateByCertificate("TEST_CERT_CONTENT", "sha256-fingerprint-abc"); // prime the cache

        // when - same fingerprint, different raw content; the cache should serve the result
        authenticationClient.authenticateByCertificate("OTHER_CERT_CONTENT", "sha256-fingerprint-abc");

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
        AuthenticationInfo result = authenticationClient.authenticateByToken(claims);

        // then
        assertEquals("FrantisekJednicka", result.getUsername());
        assertEquals(1, authServiceMock.getRequestCount());
    }

    @Test
    void authenticateByToken_cacheHit_doesNotCallAuthService() {
        // given
        setUpSuccessfulAuthenticationResponse();
        Map<String, Object> claims = Map.of("jti", "jti-test-123");
        authenticationClient.authenticateByToken(claims); // prime the cache

        // when
        authenticationClient.authenticateByToken(claims);

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
        authenticationClient.authenticateByToken(claimsWithoutJti);
        authenticationClient.authenticateByToken(claimsWithoutJti);

        // then
        assertEquals(2, authServiceMock.getRequestCount());
    }

    // --- actor MDC restoration on cache hits ---

    @Test
    void authenticateSystemUser_cacheHit_restoresActorMdc() {
        // given - cache primed, MDC cleared to simulate a fresh request thread
        setUpSuccessfulAuthenticationResponse();
        authenticationClient.authenticateSystemUser("acme");
        MDC.clear();

        // when - cache hit, loader (and its MDC side effects) skipped
        authenticationClient.authenticateSystemUser("acme");

        // then - the second call was served from cache, yet audit log actor info is complete
        assertEquals(1, authServiceMock.getRequestCount());
        ActorRecord actor = LoggingHelper.getActorInfo();
        assertEquals(AuthMethod.USER_PROXY, actor.authMethod());
        assertEquals("FrantisekJednicka", actor.name());
        assertEquals(UUID.fromString("a1b2c3d4-0000-0000-0000-000000000001"), actor.uuid());
    }

    @Test
    void authenticateByUserUuid_cacheHit_restoresActorMdc() {
        // given
        setUpSuccessfulAuthenticationResponse();
        UUID userUuid = UUID.randomUUID();
        authenticationClient.authenticateByUserUuid(userUuid);
        MDC.clear();

        // when
        authenticationClient.authenticateByUserUuid(userUuid);

        // then
        assertEquals(1, authServiceMock.getRequestCount());
        ActorRecord actor = LoggingHelper.getActorInfo();
        assertEquals(AuthMethod.USER_PROXY, actor.authMethod());
        assertEquals("FrantisekJednicka", actor.name());
        assertEquals(UUID.fromString("a1b2c3d4-0000-0000-0000-000000000001"), actor.uuid());
    }

    @Test
    void authenticateByCertificate_cacheHit_restoresActorMdc() {
        // given
        setUpSuccessfulAuthenticationResponse();
        authenticationClient.authenticateByCertificate("TEST_CERT_CONTENT", "sha256-fingerprint-mdc");
        MDC.clear();

        // when
        authenticationClient.authenticateByCertificate("TEST_CERT_CONTENT", "sha256-fingerprint-mdc");

        // then - without restoration the actor falls back to CORE/NONE, misattributing the request
        assertEquals(1, authServiceMock.getRequestCount());
        ActorRecord actor = LoggingHelper.getActorInfo();
        assertEquals(AuthMethod.CERTIFICATE, actor.authMethod());
        assertEquals("FrantisekJednicka", actor.name());
        assertEquals(UUID.fromString("a1b2c3d4-0000-0000-0000-000000000001"), actor.uuid());
    }

    @Test
    void authenticateByToken_cacheHit_restoresActorMdc() {
        // given
        setUpSuccessfulAuthenticationResponse();
        Map<String, Object> claims = Map.of("jti", "jti-mdc-test");
        authenticationClient.authenticateByToken(claims);
        MDC.clear();

        // when
        authenticationClient.authenticateByToken(claims);

        // then
        assertEquals(1, authServiceMock.getRequestCount());
        ActorRecord actor = LoggingHelper.getActorInfo();
        assertEquals(AuthMethod.TOKEN, actor.authMethod());
        assertEquals("FrantisekJednicka", actor.name());
        assertEquals(UUID.fromString("a1b2c3d4-0000-0000-0000-000000000001"), actor.uuid());
    }

    @Test
    void authenticateSystemUser_cacheHit_matchesCacheMissActorMdc() {
        // given - cache primed; the miss path overwrote the MDC actor to the authenticated USER identity
        setUpSuccessfulAuthenticationResponse();
        authenticationClient.authenticateSystemUser("acme");
        // a later request reuses the thread with a different enclosing actor (e.g. an internal proxy call)
        MDC.clear();
        LoggingHelper.putActorInfoWhenNull(ActorType.CORE, "b2c3d4e5-0000-0000-0000-000000000002", "existingActor");

        // when - cache hit must reproduce the miss path's actor, not preserve the enclosing one
        authenticationClient.authenticateSystemUser("acme");

        // then - actor is the authenticated USER identity, identical to what a cache miss produces
        assertEquals(1, authServiceMock.getRequestCount());
        ActorRecord actor = LoggingHelper.getActorInfo();
        assertEquals(ActorType.USER, actor.type());
        assertEquals("FrantisekJednicka", actor.name());
        assertEquals(UUID.fromString("a1b2c3d4-0000-0000-0000-000000000001"), actor.uuid());
        assertEquals(AuthMethod.USER_PROXY, actor.authMethod());
    }

    @Test
    void authenticateSystemUser_anonymousResult_leavesLoaderActorMdcUntouched() {
        // given - auth service rejects; anonymous results are never cached, the loader always runs
        authServiceMock.enqueue(
                new MockResponse()
                        .setResponseCode(200)
                        .setHeader("content-type", "application/json")
                        .setBody("{\"authenticated\": false, \"data\": null}")
        );

        // when
        AuthenticationInfo info = authenticationClient.authenticateSystemUser("unknown-user");

        // then - the loader's anonymous MDC put stands; restoreActorMdc must not overwrite it
        Assertions.assertTrue(info.isAnonymous());
        ActorRecord actor = LoggingHelper.getActorInfo();
        assertEquals(ActorType.ANONYMOUS, actor.type());
        assertEquals("anonymousUser", actor.name());
        Assertions.assertNull(actor.uuid());
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
