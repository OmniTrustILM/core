package com.otilm.core.security.authn.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.MDC;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class PlatformAuthenticationClientAuthoritativeTest {
    private static final UUID ACTOR = UUID.fromString("a1000000-0000-0000-0000-000000000001");
    private static final String DATA = "{\"user\":{\"uuid\":\"" + ACTOR
            + "\",\"username\":\"synthetic\",\"enabled\":true},\"roles\":[],\"permissions\":{\"allowAllResources\":false,\"resources\":[]}}";
    private static final Duration AUTHORITY_TIMEOUT = Duration.ofSeconds(2);
    private static final Duration SHORT_TIMEOUT = Duration.ofSeconds(1);
    private static final Duration TRANSPORT_TIMEOUT = Duration.ofMillis(100);
    private MockWebServer server;
    private PlatformAuthenticationClient client;
    private AuditLogInternalService audit;
    private AuthenticationCache cache;

    @BeforeEach
    void setup() throws Exception {
        server = new MockWebServer();
        server.start();
        audit = mock(AuditLogInternalService.class);
        cache = mock(AuthenticationCache.class);
        client = new PlatformAuthenticationClient(audit,
                new ObjectMapper()
                        .disable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES),
                cache, server.url("/").toString());
    }

    @AfterEach
    void cleanup() throws Exception {
        Thread.interrupted();
        server.shutdown();
        MDC.clear();
    }

    @Test
    void alwaysFetchesReturnedRawDataWithoutAuthenticationCache() throws Exception {
        respond("{\"authenticated\":true,\"data\":" + DATA + "}");
        respond("{\"authenticated\":true,\"data\":" + DATA.replace("false", "true") + "}");
        assertThat(authenticate(AUTHORITY_TIMEOUT).getRawData()).isEqualTo(DATA);
        assertThat(authenticate(AUTHORITY_TIMEOUT).getRawData()).contains("\"allowAllResources\":true");
        assertThat(server.getRequestCount()).isEqualTo(2);
        var body = new ObjectMapper().readTree(server.takeRequest().getBody().readUtf8());
        assertThat(body.path("userUuid").asText()).isEqualTo(ACTOR.toString());
        verifyNoInteractions(cache, audit);
    }

    @Test
    void authoritativeRequestMatchesPublishedOrdinaryJsonContract() throws Exception {
        respond("{\"authenticated\":true,\"data\":" + DATA + "}");
        respond("{\"authenticated\":true,\"data\":" + DATA + "}");
        client.authenticate(com.otilm.api.model.core.logging.enums.AuthMethod.USER_PROXY, ACTOR, false);
        authenticate(AUTHORITY_TIMEOUT);
        var ordinary = server.takeRequest(2, TimeUnit.SECONDS);
        var strict = server.takeRequest(2, TimeUnit.SECONDS);
        assertThat(ordinary).isNotNull();
        assertThat(strict).isNotNull();
        assertThat(strict.getPath()).isEqualTo(ordinary.getPath()).isEqualTo("/auth");
        var mapper = new ObjectMapper();
        var ordinaryBody = mapper.readTree(ordinary.getBody().readUtf8());
        var strictBody = mapper.readTree(strict.getBody().readUtf8());
        assertThat(strictBody).isEqualTo(ordinaryBody);
        assertThat(strictBody.path("userUuid").asText()).isEqualTo(ACTOR.toString());
        assertThat(strictBody.has("authMethod")).isFalse();
        verifyNoInteractions(cache, audit);
    }

    @ParameterizedTest
    @MethodSource("invalidResponses")
    void rejectsInvalidAuthenticatedEvidence(String response) {
        respond(response);
        assertThatThrownBy(() -> authenticate(AUTHORITY_TIMEOUT))
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasNoCause();
        assertThat(server.getRequestCount()).isEqualTo(1);
        verifyNoInteractions(cache, audit);
    }

    static Stream<String> invalidResponses() {
        String valid = "{\"authenticated\":true,\"data\":" + DATA + "}";
        return Stream
                .of("", "null", "{}", "{\"authenticated\":false}",
                        valid.replace("authenticated\":true", "authenticated\":\"true\""),
                        valid.replace(ACTOR.toString(), "a2000000-0000-0000-0000-000000000002"),
                        valid.replace("\"enabled\":true", "\"enabled\":false"),
                        valid.replace("\"enabled\":true", "\"enabled\":\"true\""),
                        valid.replace("\"synthetic\"", "\"anonymousUser\""), valid.replace("\"synthetic\"", "null"),
                        valid.replace("\"roles\":[]", "\"roles\":null"),
                        valid.replace("\"roles\":[]", "\"roles\":[{}]"),
                        valid.replace("\"roles\":[]", "\"roles\":[null]"),
                        valid
                                .replace("\"permissions\":{\"allowAllResources\":false,\"resources\":[]}",
                                        "\"permissions\":null"),
                        "{\"authenticated\":true,\"data\":null}", "{\"authenticated\":true,\"data\":\"not-json\"}");
    }

    @Test
    void actualDelayedTransportTimesOutWithoutDetachedCallback() {
        server
                .enqueue(new MockResponse()
                        .setHeader("Content-Type", "application/json")
                        .setBody("{\"authenticated\":true,\"data\":" + DATA + "}")
                        .setBodyDelay(800, TimeUnit.MILLISECONDS));
        long start = System.nanoTime();
        assertThatThrownBy(() -> authenticate(TRANSPORT_TIMEOUT))
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasNoCause();
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(AUTHORITY_TIMEOUT);
        assertThat(server.getRequestCount()).isEqualTo(1);
        verifyNoInteractions(audit);
    }

    @Test
    void errorBodyCannotReachNamedLoggerOrAudit() throws Throwable {
        String canary = "synthetic-private-upstream-body";
        server.enqueue(new MockResponse().setResponseCode(403).setBody(canary));
        var messages = com.otilm.core.security.authn.ForwardedCertificateFixtures
                .captureLogs(PlatformAuthenticationClient.class,
                        () -> assertThatThrownBy(() -> authenticate(AUTHORITY_TIMEOUT))
                                .isInstanceOf(PlatformAuthenticationException.class)
                                .hasNoCause()
                                .hasMessageNotContaining(canary));
        assertThat(messages).noneMatch(message -> message.contains(canary));
        verifyNoInteractions(audit);
    }

    @Test
    void invalidBoundOrInterruptedThreadCannotContactAuthority() {
        for (Duration timeout : java.util.Arrays
                .asList(null, Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(6))) {
            assertThatThrownBy(() -> authenticate(timeout))
                    .isInstanceOf(PlatformAuthenticationException.class)
                    .hasNoCause();
        }
        assertThatThrownBy(() -> client.authenticateByUserUuidAuthoritatively(null, SHORT_TIMEOUT))
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasNoCause();
        Thread.currentThread().interrupt();
        assertThatThrownBy(() -> authenticate(SHORT_TIMEOUT))
                .isInstanceOf(PlatformAuthenticationException.class)
                .hasNoCause();
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
        assertThat(server.getRequestCount()).isZero();
        verifyNoInteractions(cache, audit);
    }

    private AuthenticationInfo authenticate(Duration timeout) {
        return client.authenticateByUserUuidAuthoritatively(ACTOR, timeout);
    }

    private void respond(String body) {
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setBody(body));
    }
}
