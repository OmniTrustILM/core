package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.core.config.cache.AuthorizationCacheProperties;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.ReadThroughCache;
import com.otilm.core.security.ai.AiReadInvocation;
import com.otilm.core.security.ai.AiReadInvocationContext;
import com.otilm.core.security.ai.CertificateReadScope;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.service.AuditLogInternalService;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.QueueDispatcher;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.MDC;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class OpaClientScopedTest {
    private static final UUID ACTOR = UUID.fromString("a1000000-0000-0000-0000-000000000001");
    private static final UUID PROFILE = UUID.fromString("b1000000-0000-0000-0000-000000000001");
    private static final UUID CERTIFICATE = UUID.fromString("c1000000-0000-0000-0000-000000000001");
    private static final String ALLOW = "{\"result\":{\"authorized\":true,\"allow\":[\"ExplicitGrant\"],\"deny\":[]}}";
    private static final String DENY = "{\"result\":{\"authorized\":false,\"allow\":[],\"deny\":[]}}";
    private static final String OBJECTS = "{\"result\":{\"actionAllowedForGroupOfObjects\":false,\"allowedObjects\":[\""
            + CERTIFICATE + "\"],\"forbiddenObjects\":[]}}";
    private static final Duration AUTHORITY_TIMEOUT = Duration.ofSeconds(2);
    private static final Duration INVOCATION_TIMEOUT = Duration.ofSeconds(3);
    private static final Duration TRANSPORT_TIMEOUT = Duration.ofMillis(300);
    private static final CertificateReadScope READ_SCOPE = new CertificateReadScope(PROFILE, Set.of(CERTIFICATE));
    private static final String INITIAL_PRINCIPAL = principal("initial");
    private static final String STALE_PRINCIPAL = principal("stale");
    private OpaRequestedResource certificateRequest;
    private final ObjectMapper mapper = new ObjectMapper();
    private final AtomicReference<String> authResponse = new AtomicReference<>();
    private MockWebServer auth;
    private MockWebServer opa;
    private OpaClient client;
    private AiReadInvocation invocation;
    private AuditLogInternalService audit;

    @BeforeEach
    void setup() throws Exception {
        auth = new MockWebServer();
        auth.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return json(authResponse.get());
            }
        });
        auth.start();
        opa = new MockWebServer();
        QueueDispatcher dispatcher = new QueueDispatcher();
        dispatcher.setFailFast(true);
        opa.setDispatcher(dispatcher);
        opa.start();
        audit = mock(AuditLogInternalService.class);
        invocation = new AiReadInvocation(new PlatformAuthenticationClient(audit, mapper,
                mock(AuthenticationCache.class), auth.url("/").toString()));
        client = client();
        certificateRequest = new OpaRequestedResource(Map.of("name", "certificates", "action", "list"));
        setPrincipal("initial");
    }

    @AfterEach
    void cleanup() throws Exception {
        auth.shutdown();
        opa.shutdown();
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        MDC.clear();
        Thread.interrupted();
    }

    @Test
    void refreshesAuthRawDataAtActualMethodVote() throws Exception {
        opa.enqueue(json(ALLOW));
        invocation.call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT, () -> {
            setPrincipal("changed-at-method");
            assertThat(client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null).isAuthorized())
                    .isTrue();
            assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo(ACTOR.toString());
            assertThat(MDC.get("log_actor_uuid")).isEqualTo(ACTOR.toString());
            return null;
        });
        assertThat(auth.getRequestCount()).isEqualTo(2);
        assertThat(request().at("/input/principal/revision").asText()).isEqualTo("changed-at-method");
    }

    @Test
    void refreshesAuthRawDataAtActualObjectVote() throws Exception {
        opa.enqueue(json(ALLOW));
        opa.enqueue(json(OBJECTS));
        invocation.call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT, () -> {
            client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null);
            setPrincipal("changed-at-object");
            assertThat(
                    client.checkObjectAccess("objects", certificateRequest, STALE_PRINCIPAL, null).getAllowedObjects())
                    .containsExactly(CERTIFICATE.toString());
            return null;
        });
        assertThat(auth.getRequestCount()).isEqualTo(3);
        request();
        assertThat(request().at("/input/principal/revision").asText()).isEqualTo("changed-at-object");
    }

    @Test
    void warmResourceAllowCannotHideRevocation() {
        opa.enqueue(json(ALLOW));
        client.checkResourceAccess("method", certificateRequest, INITIAL_PRINCIPAL, null);
        opa.enqueue(json(DENY));
        assertThatThrownBy(() -> invocation
                .call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT,
                        () -> client.checkResourceAccess("method", certificateRequest, INITIAL_PRINCIPAL, null)))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause();
        assertThat(opa.getRequestCount()).isEqualTo(2);
        assertThat(auth.getRequestCount()).isEqualTo(2);
    }

    @Test
    void warmObjectAllowCannotHideRevocation() {
        opa.enqueue(json(OBJECTS));
        client.checkObjectAccess("objects", certificateRequest, INITIAL_PRINCIPAL, null);
        opa
                .enqueue(json(
                        "{\"result\":{\"actionAllowedForGroupOfObjects\":false,\"allowedObjects\":[],\"forbiddenObjects\":[]}}"));
        assertThatThrownBy(() -> invocation
                .call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT,
                        () -> client.checkObjectAccess("objects", certificateRequest, INITIAL_PRINCIPAL, null)))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause();
        assertThat(opa.getRequestCount()).isEqualTo(2);
        assertThat(auth.getRequestCount()).isEqualTo(2);
    }

    @Test
    void otherReplicaCacheCannotRestoreOldAuthority() {
        OpaClient other = client();
        opa.enqueue(json(ALLOW));
        opa.enqueue(json(ALLOW));
        client.checkResourceAccess("method", certificateRequest, INITIAL_PRINCIPAL, null);
        other.checkResourceAccess("method", certificateRequest, INITIAL_PRINCIPAL, null);
        opa.enqueue(json(DENY));
        assertThatThrownBy(() -> invocation
                .call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT,
                        () -> other.checkResourceAccess("method", certificateRequest, INITIAL_PRINCIPAL, null)))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause();
        assertThat(opa.getRequestCount()).isEqualTo(3);
        assertThat(client.checkResourceAccess("method", certificateRequest, INITIAL_PRINCIPAL, null).isAuthorized())
                .isTrue();
        assertThat(opa.getRequestCount()).isEqualTo(3);
    }

    @ParameterizedTest
    @MethodSource("invalidMethodResults")
    void rejectsMalformedOrNonallowMethodEvidence(String body) {
        opa.enqueue(json(body));
        assertThatThrownBy(() -> invocation
                .call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT,
                        () -> client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null)))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause();
        assertThat(opa.getRequestCount()).isEqualTo(1);
    }

    static Stream<String> invalidMethodResults() {
        return Stream
                .of("", "null", "{}", "{\"result\":null}", "{\"result\":[]}", "not-json",
                        ALLOW.replace("\"authorized\":true,", ""), ALLOW.replace("true", "\"true\""),
                        ALLOW.replace("\"allow\":[\"ExplicitGrant\"]", "\"allow\":[]"),
                        ALLOW.replace("\"allow\":[\"ExplicitGrant\"]", "\"allow\":null"),
                        ALLOW.replace("\"allow\":[\"ExplicitGrant\"]", "\"allow\":[42]"),
                        ALLOW.replace(",\"deny\":[]", ""), ALLOW.replace("\"deny\":[]", "\"deny\":null"),
                        ALLOW.replace("\"deny\":[]", "\"deny\":{}"),
                        ALLOW.replace("\"deny\":[]", "\"deny\":[\"ExplicitDeny\"]"), DENY);
    }

    @ParameterizedTest
    @MethodSource("invalidObjectResults")
    void rejectsMalformedObjectEvidenceBeforeMappingDefaults(String body) {
        opa.enqueue(json(body));
        assertThatThrownBy(() -> invocation
                .call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT,
                        () -> client.checkObjectAccess("objects", certificateRequest, STALE_PRINCIPAL, null)))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause();
        assertThat(opa.getRequestCount()).isEqualTo(1);
    }

    static Stream<String> invalidObjectResults() {
        return Stream
                .concat(Stream
                        .of("{}", "{\"result\":null}", OBJECTS.replace(CERTIFICATE.toString(), "not-a-uuid"),
                                OBJECTS.replace(CERTIFICATE.toString(), "1-1-1-1-1")),
                        Stream
                                .of("actionAllowedForGroupOfObjects", "allowedObjects", "forbiddenObjects")
                                .flatMap(field -> Stream.of("missing", "null", "wrong").map(shape -> {
                                    try {
                                        var root = (com.fasterxml.jackson.databind.node.ObjectNode) new ObjectMapper()
                                                .readTree(OBJECTS);
                                        var result = (com.fasterxml.jackson.databind.node.ObjectNode) root
                                                .get("result");
                                        if (shape.equals("missing")) {
                                            result.remove(field);
                                        } else if (shape.equals("null")) {
                                            result.putNull(field);
                                        } else {
                                            result.put(field, "wrong-type");
                                        }
                                        return root.toString();
                                    } catch (Exception failure) {
                                        throw new AssertionError(failure);
                                    }
                                })));
    }

    @Test
    void changedOrAnonymousActorStopsBeforeOpa() throws Exception {
        invocation.call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT, () -> {
            authResponse.set("{\"authenticated\":false}");
            assertThatThrownBy(() -> client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasNoCause();
            return null;
        });
        assertThat(auth.getRequestCount()).isEqualTo(2);
        assertThat(opa.getRequestCount()).isZero();
    }

    @Test
    void actualOpaBodyTimeoutIsBoundedAndCancelsTheRequest() {
        opa.enqueue(json(ALLOW).setBodyDelay(1, TimeUnit.SECONDS));
        long start = System.nanoTime();
        AtomicBoolean continued = new AtomicBoolean();
        assertThatThrownBy(() -> invocation.call(ACTOR, READ_SCOPE, TRANSPORT_TIMEOUT, () -> {
            client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null);
            continued.set(true);
            return null;
        })).isInstanceOf(AccessDeniedException.class).hasNoCause();
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(800));
        assertThat(continued).isFalse();
        assertThat(opa.getRequestCount()).isEqualTo(1);
        assertThat(AiReadInvocationContext.isActive()).isFalse();
    }

    @Test
    void interruptionCancelsTransportAndCleansReusedWorker() throws Exception {
        opa.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));
        AtomicBoolean continued = new AtomicBoolean();
        AtomicReference<Thread> running = new AtomicReference<>();
        try (var worker = Executors.newSingleThreadExecutor()) {
            var future = worker.submit(() -> {
                running.set(Thread.currentThread());
                assertThatThrownBy(() -> invocation.call(ACTOR, READ_SCOPE, INVOCATION_TIMEOUT, () -> {
                    assertThatThrownBy(
                            () -> client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null))
                            .isInstanceOf(AccessDeniedException.class)
                            .hasNoCause();
                    assertThat(Thread.currentThread().isInterrupted()).isTrue();
                    assertThat(auth.getRequestCount()).isEqualTo(2);
                    assertThat(opa.getRequestCount()).isEqualTo(1);
                    assertThatThrownBy(
                            () -> client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null))
                            .isInstanceOf(AccessDeniedException.class)
                            .hasNoCause();
                    assertThat(Thread.currentThread().isInterrupted()).isTrue();
                    assertThat(auth.getRequestCount()).isEqualTo(2);
                    assertThat(opa.getRequestCount()).isEqualTo(1);
                    continued.set(true);
                    return null;
                })).isInstanceOf(AccessDeniedException.class).hasNoCause();
                assertThat(AiReadInvocationContext.isActive()).isFalse();
                assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
                assertThat(RequestContextHolder.getRequestAttributes()).isNull();
                assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
                return true;
            });
            assertThat(opa.takeRequest(2, TimeUnit.SECONDS)).isNotNull();
            running.get().interrupt();
            assertThat(future.get(2, TimeUnit.SECONDS)).isTrue();
            assertThat(worker
                    .submit(() -> !AiReadInvocationContext.isActive()
                            && SecurityContextHolder.getContext().getAuthentication() == null)
                    .get(2, TimeUnit.SECONDS)).isTrue();
        }
        assertThat(continued).isTrue();
        assertThat(auth.getRequestCount()).isEqualTo(2);
        assertThat(opa.getRequestCount()).isEqualTo(1);
        verifyNoInteractions(audit);
    }

    @Test
    void errorBodyAndCauseCannotReachNamedLoggerOrAudit() throws Throwable {
        String canary = "synthetic-private-policy-body";
        opa.enqueue(new MockResponse().setResponseCode(500).setBody(canary));
        var messages = com.otilm.core.security.authn.ForwardedCertificateFixtures
                .captureLogs(OpaClient.class, () -> assertThatThrownBy(() -> invocation
                        .call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT,
                                () -> client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null)))
                        .isInstanceOf(AccessDeniedException.class)
                        .hasNoCause()
                        .hasMessageNotContaining(canary));
        assertThat(messages).noneMatch(message -> message.contains(canary));
        verifyNoInteractions(audit);
    }

    @Test
    void parallelPrincipalsCannotBorrowAuthorityAtActualHttpVotes() throws Exception {
        UUID other = UUID.fromString("a2000000-0000-0000-0000-000000000002");
        auth.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                try {
                    String actor = mapper.readTree(request.getBody().readUtf8()).path("userUuid").asText();
                    return json("{\"authenticated\":true,\"data\":"
                            + principal("parallel").replace(ACTOR.toString(), actor) + "}");
                } catch (Exception failure) {
                    return new MockResponse().setResponseCode(500);
                }
            }
        });
        opa.enqueue(json(ALLOW));
        opa.enqueue(json(ALLOW));
        var barrier = new java.util.concurrent.CyclicBarrier(2);
        Set<Long> actorThreads = java.util.concurrent.ConcurrentHashMap.newKeySet();
        Set<Long> cleanThreads = java.util.concurrent.ConcurrentHashMap.newKeySet();
        try (var workers = Executors.newFixedThreadPool(2)) {
            var results = workers
                    .invokeAll(List.<java.util.concurrent.Callable<String>>of(
                            () -> parallelVote(ACTOR, barrier, actorThreads),
                            () -> parallelVote(other, barrier, actorThreads)));
            assertThat(results.get(0).get()).isEqualTo(ACTOR.toString());
            assertThat(results.get(1).get()).isEqualTo(other.toString());
            var clean = workers
                    .invokeAll(List.<java.util.concurrent.Callable<Boolean>>of(
                            () -> emptyWorkerAtBarrier(barrier, cleanThreads),
                            () -> emptyWorkerAtBarrier(barrier, cleanThreads)));
            assertThat(clean.get(0).get()).isTrue();
            assertThat(clean.get(1).get()).isTrue();
        }
        assertThat(actorThreads).hasSize(2).isEqualTo(cleanThreads);
        assertThat(Set
                .of(request().at("/input/principal/user/uuid").asText(),
                        request().at("/input/principal/user/uuid").asText()))
                .containsExactlyInAnyOrder(ACTOR.toString(), other.toString());
        assertThat(auth.getRequestCount()).isEqualTo(4);
        verifyNoInteractions(audit);
    }

    private boolean emptyWorkerAtBarrier(java.util.concurrent.CyclicBarrier barrier, Set<Long> threads)
            throws Exception {
        threads.add(Thread.currentThread().threadId());
        barrier.await(2, TimeUnit.SECONDS);
        return !AiReadInvocationContext.isActive() && SecurityContextHolder.getContext().getAuthentication() == null
                && RequestContextHolder.getRequestAttributes() == null && MDC.getCopyOfContextMap() == null;
    }

    private String parallelVote(UUID actor, java.util.concurrent.CyclicBarrier barrier, Set<Long> threads)
            throws Exception {
        threads.add(Thread.currentThread().threadId());
        return invocation.call(actor, READ_SCOPE, INVOCATION_TIMEOUT, () -> {
            barrier.await(2, TimeUnit.SECONDS);
            client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null);
            String actual = SecurityContextHolder.getContext().getAuthentication().getName();
            assertThat(MDC.get("log_actor_uuid")).isEqualTo(actor.toString());
            assertThat(com.otilm.core.logging.LoggingHelper.getActorInfo().uuid()).isEqualTo(actor);
            return actual;
        });
    }

    @Test
    void actorReplacementAndUnauthenticatedTokenStopBeforeAuthorityHttp() throws Exception {
        invocation.call(ACTOR, READ_SCOPE, AUTHORITY_TIMEOUT, () -> {
            var original = SecurityContextHolder.getContext().getAuthentication();
            var replacement = new com.otilm.core.security.authn.PlatformAuthenticationToken(
                    new com.otilm.core.security.authn.PlatformUserDetails(
                            new com.otilm.core.security.authn.client.AuthenticationInfo(
                                    com.otilm.api.model.core.logging.enums.AuthMethod.USER_PROXY, PROFILE.toString(),
                                    "other", List.of(), principal("synthetic"))));
            SecurityContextHolder.getContext().setAuthentication(replacement);
            assertThatThrownBy(() -> client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null))
                    .isInstanceOf(AccessDeniedException.class);
            SecurityContextHolder.getContext().setAuthentication(original);
            original.setAuthenticated(false);
            assertThatThrownBy(() -> client.checkResourceAccess("method", certificateRequest, STALE_PRINCIPAL, null))
                    .isInstanceOf(AccessDeniedException.class);
            SecurityContextHolder
                    .getContext()
                    .setAuthentication(new com.otilm.core.security.authn.PlatformAuthenticationToken(
                            ((com.otilm.core.security.authn.PlatformAuthenticationToken) original).getPrincipal()));
            return null;
        });
        assertThat(auth.getRequestCount()).isEqualTo(1);
        assertThat(opa.getRequestCount()).isZero();
    }

    private OpaClient client() {
        SimpleCacheManager manager = new SimpleCacheManager();
        manager
                .setCaches(List
                        .of(new ReadThroughCache(CacheConfig.RESOURCE_AUTHZ_CACHE,
                                Caffeine.newBuilder().maximumSize(100).buildAsync()),
                                new ReadThroughCache(CacheConfig.OBJECT_AUTHZ_CACHE,
                                        Caffeine.newBuilder().maximumSize(100).buildAsync())));
        manager.initializeCaches();
        return new OpaClient(mapper, opa.url("/").toString(),
                new PlatformAuthorizationCache(manager, mapper, new AuthorizationCacheProperties(true, 5, 100, 100)));
    }

    private JsonNode request() throws Exception {
        return mapper.readTree(opa.takeRequest(1, TimeUnit.SECONDS).getBody().readUtf8());
    }

    private void setPrincipal(String revision) {
        authResponse.set("{\"authenticated\":true,\"data\":" + principal(revision) + "}");
    }

    private static String principal(String revision) {
        return "{\"user\":{\"uuid\":\"" + ACTOR
                + "\",\"username\":\"synthetic\",\"enabled\":true},\"roles\":[],\"revision\":\"" + revision
                + "\",\"permissions\":{\"allowAllResources\":false,\"resources\":[]}}";
    }

    private static MockResponse json(String body) {
        return new MockResponse().setHeader("Content-Type", "application/json").setBody(body);
    }

}
