package com.otilm.core.security.ai;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.AuthorizationEnforcerImpl;
import com.otilm.core.security.authz.opa.AuthorizationCache;
import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class AiModelManagementAuthorizationTest {
    private static final UUID ACTOR = UUID.fromString("a1000000-0000-0000-0000-000000000001");
    private static final UUID MODEL = UUID.fromString("b1000000-0000-0000-0000-000000000001");
    private static final String ALLOW = "{\"result\":{\"authorized\":true,\"allow\":[\"ModelConnect\"],\"deny\":[]}}";
    private static final String OBJECT_ALLOW = "{\"result\":{\"actionAllowedForGroupOfObjects\":false,\"allowedObjects\":[\""
            + MODEL + "\"],\"forbiddenObjects\":[]}}";
    private final ObjectMapper mapper = new ObjectMapper();
    private final AuthenticationCache authenticationCache = mock(AuthenticationCache.class);
    private final AuthorizationCache authorizationCache = mock(AuthorizationCache.class);
    private final AuditLogInternalService audit = mock(AuditLogInternalService.class);
    private MockWebServer auth;
    private MockWebServer opa;
    private AiModelManagementAuthorization authorization;

    @BeforeEach
    void setup() throws Exception {
        auth = new MockWebServer();
        auth.start();
        opa = new MockWebServer();
        opa.start();
        var client = new PlatformAuthenticationClient(audit, mapper, authenticationCache, auth.url("/").toString());
        authorization = new AiModelManagementAuthorization(client, new AuthorizationEnforcerImpl(null, client,
                new OpaClient(mapper, opa.url("/").toString(), authorizationCache)));
    }

    @AfterEach
    void cleanup() throws Exception {
        Thread.interrupted();
        auth.shutdown();
        opa.shutdown();
        SecurityContextHolder.clearContext();
        MDC.clear();
        Thread.interrupted();
        verifyNoInteractions(authenticationCache, authorizationCache, audit);
    }

    @Test
    void usesOnlyFreshPinnedActorAndExactModelConnectWithoutChangingCallerContext() throws Exception {
        var caller = new TestingAuthenticationToken("caller", "credential-canary");
        SecurityContextHolder.getContext().setAuthentication(caller);
        MDC.put("correlation", "caller-correlation");
        enqueueAllow("connect-only");

        authorization.requireConnect(ACTOR, MODEL, budget());

        assertConnectRequests("connect-only");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(caller);
        assertThat(MDC.getCopyOfContextMap()).containsOnlyKeys("correlation");
        assertThat(MDC.get("correlation")).isEqualTo("caller-correlation");
    }

    @Test
    void laterRevocationIsNotHiddenByEarlierSuccess() {
        enqueueAllow("allowed");
        authorization.requireConnect(ACTOR, MODEL, budget());
        auth.enqueue(authenticated(principal(ACTOR, "detail-only")));
        opa.enqueue(json("{\"result\":{\"authorized\":false,\"allow\":[],\"deny\":[]}}"));

        denied(() -> authorization.requireConnect(ACTOR, MODEL, budget()));

        assertThat(auth.getRequestCount()).isEqualTo(2);
        assertThat(opa.getRequestCount()).isEqualTo(3);
    }

    @ParameterizedTest
    @MethodSource("invalidActors")
    void deniesInvalidCurrentActorsBeforePolicy(String response) {
        auth.enqueue(json(response));
        denied(() -> authorization.requireConnect(ACTOR, MODEL, budget()));
        assertThat(opa.getRequestCount()).isZero();
    }

    static Stream<String> invalidActors() {
        return Stream
                .of("{}", "null", authBody(principal(ACTOR, "anonymous").replace("synthetic", "anonymousUser")),
                        authBody(principal(UUID.randomUUID(), "foreign")));
    }

    @ParameterizedTest
    @MethodSource("invalidMethods")
    void deniesMissingMalformedOrContradictoryMethodPermission(String response) {
        auth.enqueue(authenticated(principal(ACTOR, "fresh")));
        opa.enqueue(json(response));
        denied(() -> authorization.requireConnect(ACTOR, MODEL, budget()));
        assertThat(opa.getRequestCount()).isEqualTo(1);
    }

    static Stream<String> invalidMethods() {
        return Stream
                .of("{}", "null", "not-json", "{\"result\":true}",
                        "{\"result\":{\"authorized\":true,\"allow\":[],\"deny\":[]}}",
                        "{\"result\":{\"authorized\":true,\"allow\":[\"yes\"],\"deny\":[\"no\"]}}",
                        "{\"result\":{\"authorized\":\"true\",\"allow\":[\"yes\"],\"deny\":[]}}");
    }

    @ParameterizedTest
    @MethodSource("invalidObjects")
    void explicitDenyOrMissingExactObjectPermissionOverridesAllow(String response) {
        auth.enqueue(authenticated(principal(ACTOR, "fresh")));
        opa.enqueue(json(ALLOW));
        opa.enqueue(json(response));
        denied(() -> authorization.requireConnect(ACTOR, MODEL, budget()));
        assertThat(opa.getRequestCount()).isEqualTo(2);
    }

    static Stream<String> invalidObjects() {
        return Stream
                .of("{}",
                        "{\"result\":{\"actionAllowedForGroupOfObjects\":false,\"allowedObjects\":[],\"forbiddenObjects\":[]}}",
                        "{\"result\":{\"actionAllowedForGroupOfObjects\":false,\"allowedObjects\":[\"c1000000-0000-0000-0000-000000000001\"],\"forbiddenObjects\":[]}}",
                        "{\"result\":{\"actionAllowedForGroupOfObjects\":true,\"allowedObjects\":[\"" + MODEL
                                + "\"],\"forbiddenObjects\":[\"" + MODEL + "\"]}}",
                        "{\"result\":{\"actionAllowedForGroupOfObjects\":true,\"allowedObjects\":[\"invalid\"],\"forbiddenObjects\":[]}}");
    }

    @Test
    void groupConnectAllowsModelUnlessExplicitlyForbidden() throws Exception {
        auth.enqueue(authenticated(principal(ACTOR, "group-use")));
        opa.enqueue(json(ALLOW));
        opa
                .enqueue(json(
                        "{\"result\":{\"actionAllowedForGroupOfObjects\":true,\"allowedObjects\":[],\"forbiddenObjects\":[]}}"));
        authorization.requireConnect(ACTOR, MODEL, budget());
        assertThat(auth.getRequestCount()).isEqualTo(1);
        assertThat(opa.getRequestCount()).isEqualTo(2);
        assertConnectRequests("group-use");
    }

    @Test
    void authHttpFailureDoesNotStartPolicyRequests() {
        auth.enqueue(new MockResponse().setResponseCode(503).setBody("auth-secret-canary"));
        denied(() -> authorization.requireConnect(ACTOR, MODEL, budget()));
        assertThat(opa.getRequestCount()).isZero();
    }

    @Test
    void policyHttpFailureFailsClosed() {
        auth.enqueue(authenticated(principal(ACTOR, "fresh")));
        opa.enqueue(new MockResponse().setResponseCode(503).setBody("policy-secret-canary"));
        denied(() -> authorization.requireConnect(ACTOR, MODEL, budget()));
    }

    @Test
    void stalledPolicyIsBoundedByRemainingOperationBudget() {
        enqueueAllow("warm-transport");
        authorization.requireConnect(ACTOR, MODEL, budget());
        auth.enqueue(authenticated(principal(ACTOR, "fresh")));
        opa.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));
        long started = System.nanoTime();
        denied(() -> authorization
                .requireConnect(ACTOR, MODEL, AiRuntimeOperationBudget.start(Duration.ofMillis(400))));
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(3));
        assertThat(opa.getRequestCount()).isEqualTo(3);
    }

    @Test
    void interruptedOperationStartsNoAuthorityRequest() {
        Thread.currentThread().interrupt();
        denied(() -> authorization.requireConnect(ACTOR, MODEL, budget()));
        assertThat(auth.getRequestCount()).isZero();
        assertThat(opa.getRequestCount()).isZero();
    }

    @Test
    void operationalLogsContainOnlyDecisionAndOpaqueCorrelation() {
        Logger logger = (Logger) LoggerFactory.getLogger(AiModelManagementAuthorization.class);
        Level previous = logger.getLevel();
        var events = new ListAppender<ILoggingEvent>();
        events.start();
        logger.setLevel(Level.DEBUG);
        logger.addAppender(events);
        try {
            enqueueAllow("authority-secret-canary");
            authorization.requireConnect(ACTOR, MODEL, budget());
            auth.enqueue(new MockResponse().setResponseCode(503).setBody("auth-secret-canary"));
            denied(() -> authorization.requireConnect(ACTOR, MODEL, budget()));
            assertThat(events.list).hasSize(2).allSatisfy(event -> {
                assertThat(event.getFormattedMessage())
                        .matches(
                                "AI model authorization operation=connect code=(AUTHORIZED|DENIED) correlation=[0-9a-f-]{36}");
                assertThat(event.getThrowableProxy()).isNull();
                assertThat(event.getFormattedMessage()).doesNotContain("canary", ACTOR.toString(), MODEL.toString());
            });
            assertThat(events.list.get(0).getFormattedMessage()).contains("code=AUTHORIZED");
            assertThat(events.list.get(1).getFormattedMessage()).contains("code=DENIED");
        } finally {
            logger.detachAppender(events);
            logger.setLevel(previous);
            events.stop();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void interruptDuringActualAuthorityIoPreservesCancellation(boolean stallAuth) throws Exception {
        if (stallAuth) {
            auth.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));
        } else {
            auth.enqueue(authenticated(principal(ACTOR, "fresh")));
            opa.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));
        }
        var interrupted = new AtomicBoolean();
        var outcome = new AtomicReference<Throwable>();
        Thread worker = new Thread(() -> {
            try {
                authorization.requireConnect(ACTOR, MODEL, budget());
            } catch (Throwable failure) {
                outcome.set(failure);
            } finally {
                interrupted.set(Thread.currentThread().isInterrupted());
            }
        }, "model-authority-interrupt-test");
        worker.start();
        try {
            assertThat((stallAuth ? auth : opa).takeRequest(3, TimeUnit.SECONDS)).isNotNull();
            worker.interrupt();
            worker.join(2000);
            assertThat(worker.isAlive()).isFalse();
            assertThat(outcome.get()).isInstanceOf(AccessDeniedException.class).hasNoCause();
            assertThat(interrupted).isTrue();
        } finally {
            worker.interrupt();
            worker.join(6000);
            assertThat(worker.isAlive()).isFalse();
        }
    }

    private void assertConnectRequests(String revision) throws Exception {
        var authRequest = auth.takeRequest(1, TimeUnit.SECONDS);
        assertThat(authRequest).isNotNull();
        assertThat(authRequest.getPath()).isEqualTo("/auth");
        assertThat(mapper.readTree(authRequest.getBody().readUtf8()).path("userUuid").asText())
                .isEqualTo(ACTOR.toString());
        for (String policy : new String[]{"method", "objects"}) {
            var request = opa.takeRequest(1, TimeUnit.SECONDS);
            assertThat(request).isNotNull();
            assertThat(request.getPath()).isEqualTo("/v1/data/" + policy);
            JsonNode input = mapper.readTree(request.getBody().readUtf8()).path("input");
            assertThat(input.at("/requestedResource/name").asText()).isEqualTo("aiModels");
            assertThat(input.at("/requestedResource/action").asText()).isEqualTo("connect");
            assertThat(input.at("/requestedResource/uuids").size()).isEqualTo(1);
            assertThat(input.at("/requestedResource/uuids/0").asText()).isEqualTo(MODEL.toString());
            assertThat(input.at("/principal/revision").asText()).isEqualTo(revision);
        }
    }

    private void enqueueAllow(String revision) {
        auth.enqueue(authenticated(principal(ACTOR, revision)));
        opa.enqueue(json(ALLOW));
        opa.enqueue(json(OBJECT_ALLOW));
    }

    private static String principal(UUID actor, String revision) {
        return "{\"user\":{\"uuid\":\"" + actor
                + "\",\"username\":\"synthetic\",\"enabled\":true},\"roles\":[],\"revision\":\"" + revision
                + "\",\"permissions\":{\"allowAllResources\":false,\"resources\":[]}}";
    }

    private static void denied(Runnable operation) {
        assertThatThrownBy(operation::run)
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Model connection authority unavailable")
                .hasNoCause();
    }

    private static MockResponse authenticated(String principal) {
        return json(authBody(principal));
    }

    private static String authBody(String principal) {
        return "{\"authenticated\":true,\"data\":" + principal + "}";
    }

    private static MockResponse json(String body) {
        return new MockResponse().setHeader("Content-Type", "application/json").setBody(body);
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }
}
