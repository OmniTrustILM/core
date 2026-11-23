package com.otilm.core.security.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.util.AuthHelper;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class AiReadInvocationTest {
    private static final UUID ACTOR = UUID.fromString("a1000000-0000-0000-0000-000000000001");
    private static final UUID OTHER = UUID.fromString("a2000000-0000-0000-0000-000000000002");
    private static final UUID PROFILE = UUID.fromString("b1000000-0000-0000-0000-000000000001");
    private static final Duration AUTHORITY_TIMEOUT = Duration.ofSeconds(2);
    private static final Duration NESTED_TIMEOUT = Duration.ofSeconds(1);
    private static final Duration PARALLEL_TIMEOUT = Duration.ofSeconds(3);
    private static final Duration INITIAL_AUTH_TIMEOUT = Duration.ofMillis(100);
    private static final Duration CALLBACK_TIMEOUT = Duration.ofMillis(200);
    private static final CertificateReadScope READ_SCOPE = new CertificateReadScope(PROFILE, Set.of(ACTOR));
    private MockWebServer server;
    private PlatformAuthenticationClient authentication;

    @BeforeEach
    void setup() throws Exception {
        server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                try {
                    String actor = new ObjectMapper().readTree(request.getBody().readUtf8()).path("userUuid").asText();
                    return new MockResponse()
                            .setHeader("Content-Type", "application/json")
                            .setBody("{\"authenticated\":true,\"data\":" + principal(UUID.fromString(actor)) + "}");
                } catch (Exception failure) {
                    return new MockResponse().setResponseCode(500);
                }
            }
        });
        server.start();
        authentication = new PlatformAuthenticationClient(mock(AuditLogInternalService.class), new ObjectMapper(),
                mock(AuthenticationCache.class), server.url("/").toString());
        clearThread();
    }

    @AfterEach
    void cleanup() throws Exception {
        clearThread();
        Thread.interrupted();
        server.shutdown();
    }

    @ParameterizedTest
    @ValueSource(strings = {"success", "denial", "runtime", "checked", "timeout", "interruption"})
    void restoresCallerContextsOnEveryExit(String exit) throws Exception {
        SecurityContext caller = SecurityContextHolder.createEmptyContext();
        caller
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(
                        new AuthenticationInfo(com.otilm.api.model.core.logging.enums.AuthMethod.USER_PROXY,
                                OTHER.toString(), "caller", List.of(), principal(OTHER)))));
        SecurityContextHolder.setContext(caller);
        var request = new ServletRequestAttributes(new MockHttpServletRequest());
        RequestContextHolder.setRequestAttributes(request, false);
        Map<String, String> callerMdc = Map
                .of("unrelated", "caller-value", "log_actor_uuid", OTHER.toString(), "log_actor_delegate_identifier",
                        "delegate", "log_source_path", "/caller", "log_resource_uuid", "resource");
        MDC.setContextMap(callerMdc);
        var operationEntered = new java.util.concurrent.atomic.AtomicBoolean();
        AuthHelper.ThrowingSupplier<String, Exception> operation = () -> {
            operationEntered.set(true);
            assertThat(RequestContextHolder.getRequestAttributes()).isNull();
            assertThat(MDC.get("unrelated")).isNull();
            assertThat(MDC.get("log_actor_delegate_identifier")).isNull();
            assertThat(MDC.get("log_source_path")).isNull();
            assertThat(SecurityContextHolder.getContext()).isNotSameAs(caller);
            assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo(ACTOR.toString());
            assertThat(LoggingHelper.getActorInfo().uuid()).isEqualTo(ACTOR);
            MDC.put("operation-only", "value");
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
            switch (exit) {
                case "denial" -> throw new AccessDeniedException("Synthetic denial");
                case "runtime" -> throw new IllegalStateException("Synthetic runtime");
                case "checked" -> throw new java.io.IOException("Synthetic checked");
                case "timeout" -> {
                    var context = AiReadInvocationContext.current().orElseThrow();
                    org.awaitility.Awaitility
                            .await()
                            .pollInSameThread()
                            .atMost(AUTHORITY_TIMEOUT)
                            .until(() -> authorityExpired(context));
                }
                case "interruption" -> Thread.currentThread().interrupt();
                default -> {
                    return "result";
                }
            }
            return "result";
        };
        if (exit.equals("success")) {
            assertThat(invoke(ACTOR, AUTHORITY_TIMEOUT, operation)).isEqualTo("result");
        } else {
            assertThatThrownBy(
                    () -> invoke(ACTOR, exit.equals("timeout") ? CALLBACK_TIMEOUT : AUTHORITY_TIMEOUT, operation))
                    .isInstanceOf(exit.equals("checked") ? java.io.IOException.class : RuntimeException.class);
        }
        assertThat(operationEntered).isTrue();
        assertThat(SecurityContextHolder.getContext()).isSameAs(caller);
        assertThat(RequestContextHolder.getRequestAttributes()).isSameAs(request);
        assertThat(MDC.getCopyOfContextMap()).isEqualTo(callerMdc);
        assertThat(active()).isFalse();
        if (exit.equals("interruption")) {
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void restoresPopulatedCallerContextsWhenInitialFreshAuthenticationFails(boolean timeout) {
        var caller = SecurityContextHolder.createEmptyContext();
        caller
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(
                        new AuthenticationInfo(com.otilm.api.model.core.logging.enums.AuthMethod.USER_PROXY,
                                OTHER.toString(), "caller", List.of(), principal(OTHER)))));
        SecurityContextHolder.setContext(caller);
        var request = new ServletRequestAttributes(new MockHttpServletRequest());
        RequestContextHolder.setRequestAttributes(request, false);
        Map<String, String> callerMdc = Map
                .of("unrelated", "caller-value", "log_actor_uuid", OTHER.toString(), "log_actor_delegate_identifier",
                        "delegate", "log_source_path", "/caller", "log_resource_uuid", "resource");
        MDC.setContextMap(callerMdc);
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest ignored) {
                return timeout
                        ? new MockResponse()
                                .setHeader("Content-Type", "application/json")
                                .setBody("{\"authenticated\":true,\"data\":" + principal(ACTOR) + "}")
                                .setBodyDelay(800, TimeUnit.MILLISECONDS)
                        : new MockResponse().setResponseCode(403).setBody("synthetic-private-initial-auth-body");
            }
        });
        var operationRan = new java.util.concurrent.atomic.AtomicBoolean();
        assertThatThrownBy(() -> invoke(ACTOR, timeout ? INITIAL_AUTH_TIMEOUT : AUTHORITY_TIMEOUT, () -> {
            operationRan.set(true);
            return "unused";
        }))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause()
                .hasMessageNotContaining("synthetic-private-initial-auth-body");
        assertThat(operationRan).isFalse();
        assertThat(server.getRequestCount()).isEqualTo(1);
        assertThat(SecurityContextHolder.getContext()).isSameAs(caller);
        assertThat(RequestContextHolder.getRequestAttributes()).isSameAs(request);
        assertThat(MDC.getCopyOfContextMap()).isEqualTo(callerMdc);
        assertThat(active()).isFalse();
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("unauthenticatedCallerExits")
    void restoresUnauthenticatedCallerContextOnEveryExit(boolean deferred, String exit) throws Exception {
        var caller = SecurityContextHolder.createEmptyContext();
        var resolutions = new java.util.concurrent.atomic.AtomicInteger();
        if (deferred) {
            SecurityContextHolder.setDeferredContext(() -> {
                resolutions.incrementAndGet();
                return caller;
            });
        } else {
            SecurityContextHolder.setContext(caller);
        }
        var request = new ServletRequestAttributes(new MockHttpServletRequest());
        RequestContextHolder.setRequestAttributes(request, false);
        Map<String, String> callerMdc = Map.of("unrelated", "empty-caller", "log_source_path", "/caller");
        MDC.setContextMap(callerMdc);
        boolean initialFailure = exit.startsWith("initial-");
        if (initialFailure) {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest ignored) {
                    return exit.equals("initial-timeout")
                            ? new MockResponse().setBody("{}").setBodyDelay(800, TimeUnit.MILLISECONDS)
                            : new MockResponse().setResponseCode(403);
                }
            });
        }
        var entered = new java.util.concurrent.atomic.AtomicBoolean();
        AuthHelper.ThrowingSupplier<String, Exception> operation = () -> {
            entered.set(true);
            assertThat(resolutions).hasValue(deferred ? 1 : 0);
            assertThat(SecurityContextHolder.getContext()).isNotSameAs(caller);
            assertThat(RequestContextHolder.getRequestAttributes()).isNull();
            assertThat(MDC.get("unrelated")).isNull();
            switch (exit) {
                case "denial" -> throw new AccessDeniedException("Synthetic denial");
                case "runtime" -> throw new IllegalStateException("Synthetic runtime");
                case "checked" -> throw new java.io.IOException("Synthetic checked");
                case "timeout" -> {
                    var context = AiReadInvocationContext.current().orElseThrow();
                    org.awaitility.Awaitility
                            .await()
                            .pollInSameThread()
                            .atMost(AUTHORITY_TIMEOUT)
                            .until(() -> authorityExpired(context));
                }
                case "interruption" -> Thread.currentThread().interrupt();
                default -> {
                    return "result";
                }
            }
            return "result";
        };
        Duration timeout = exit.equals("timeout")
                ? CALLBACK_TIMEOUT
                : exit.equals("initial-timeout") ? INITIAL_AUTH_TIMEOUT : AUTHORITY_TIMEOUT;
        if (exit.equals("success")) {
            assertThat(invoke(ACTOR, timeout, operation)).isEqualTo("result");
        } else {
            assertThatThrownBy(() -> invoke(ACTOR, timeout, operation))
                    .isInstanceOf(exit.equals("checked") ? java.io.IOException.class : RuntimeException.class);
        }
        assertThat(entered.get()).isEqualTo(!initialFailure);
        assertThat(resolutions).hasValue(deferred ? 1 : 0);
        assertThat(SecurityContextHolder.getDeferredContext()).isNotNull();
        assertThat(resolutions).hasValue(deferred ? 1 : 0);
        assertThat(SecurityContextHolder.getContext()).isSameAs(caller);
        assertThat(resolutions).hasValue(deferred ? 1 : 0);
        assertThat(RequestContextHolder.getRequestAttributes()).isSameAs(request);
        assertThat(MDC.getCopyOfContextMap()).isEqualTo(callerMdc);
        assertThat(active()).isFalse();
    }

    static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> unauthenticatedCallerExits() {
        return java.util.stream.Stream
                .of(false, true)
                .flatMap(deferred -> java.util.stream.Stream
                        .of("success", "denial", "runtime", "checked", "timeout", "interruption", "initial-failure",
                                "initial-timeout")
                        .map(exit -> org.junit.jupiter.params.provider.Arguments.of(deferred, exit)));
    }

    @Test
    void repeatedInvocationsKeepCallerContextResolutionBoundedOnReusedWorker() throws Exception {
        try (var worker = Executors.newSingleThreadExecutor()) {
            var observed = worker.submit(() -> {
                var caller = SecurityContextHolder.createEmptyContext();
                var request = new ServletRequestAttributes(new MockHttpServletRequest());
                RequestContextHolder.setRequestAttributes(request, false);
                Map<String, String> callerMdc = Map.of("unrelated", "reused-caller");
                MDC.setContextMap(callerMdc);
                var depths = new java.util.ArrayList<Long>();
                SecurityContextHolder.setDeferredContext(() -> {
                    depths.add(StackWalker.getInstance().walk(java.util.stream.Stream::count));
                    return caller;
                });
                try {
                    for (int attempt = 0; attempt < 8; attempt++) {
                        assertThat(invoke(ACTOR, AUTHORITY_TIMEOUT, () -> "result")).isEqualTo("result");
                        assertThat(SecurityContextHolder.getContext()).isSameAs(caller);
                        assertThat(RequestContextHolder.getRequestAttributes()).isSameAs(request);
                        assertThat(MDC.getCopyOfContextMap()).isEqualTo(callerMdc);
                        assertThat(active()).isFalse();
                    }
                    return List.copyOf(depths);
                } finally {
                    clearThread();
                }
            });
            var depths = observed.get(10, TimeUnit.SECONDS);
            System.out.println("[AI-PROOF] repeated caller-context resolution depths=" + depths);
            assertThat(depths).isNotEmpty().allMatch(depth -> depth <= depths.getFirst() + 2);
            assertThat(server.getRequestCount()).isEqualTo(8);
            assertThat(worker.submit(this::emptyWorker).get(2, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void inFlightInitialAuthenticationInterruptionRestoresCallerAndRetainsInterrupt() throws Exception {
        var release = new java.util.concurrent.CountDownLatch(1);
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest ignored) throws InterruptedException {
                if (!release.await(3, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Synthetic Auth response was not released");
                }
                return new MockResponse().setBody("{}");
            }
        });
        var running = new java.util.concurrent.atomic.AtomicReference<Thread>();
        var operationRan = new java.util.concurrent.atomic.AtomicBoolean();
        try (var worker = Executors.newSingleThreadExecutor()) {
            try {
                var result = worker.submit(() -> {
                    var caller = SecurityContextHolder.createEmptyContext();
                    SecurityContextHolder.setContext(caller);
                    var request = new ServletRequestAttributes(new MockHttpServletRequest());
                    RequestContextHolder.setRequestAttributes(request, false);
                    Map<String, String> callerMdc = Map.of("unrelated", "interrupted-caller");
                    MDC.setContextMap(callerMdc);
                    running.set(Thread.currentThread());
                    assertThatThrownBy(() -> invoke(ACTOR, PARALLEL_TIMEOUT, () -> {
                        operationRan.set(true);
                        return "unused";
                    })).isInstanceOf(AccessDeniedException.class).hasNoCause();
                    assertThat(Thread.currentThread().isInterrupted()).isTrue();
                    assertThat(active()).isFalse();
                    assertThat(SecurityContextHolder.getContext()).isSameAs(caller);
                    assertThat(RequestContextHolder.getRequestAttributes()).isSameAs(request);
                    assertThat(MDC.getCopyOfContextMap()).isEqualTo(callerMdc);
                    clearThread();
                    Thread.interrupted();
                    return true;
                });
                assertThat(server.takeRequest(2, TimeUnit.SECONDS)).isNotNull();
                running.get().interrupt();
                assertThat(result.get(2, TimeUnit.SECONDS)).isTrue();
                assertThat(operationRan).isFalse();
                assertThat(server.getRequestCount()).isEqualTo(1);
                assertThat(worker.submit(this::emptyWorker).get(2, TimeUnit.SECONDS)).isTrue();
            } finally {
                release.countDown();
            }
        }
    }

    @Test
    void leavesEmptyThreadEmpty() throws Exception {
        assertThat(invoke(ACTOR, AUTHORITY_TIMEOUT, () -> "result")).isEqualTo("result");
        assertThat(active()).isFalse();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(RequestContextHolder.getRequestAttributes()).isNull();
        assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void rejectsCrossActorNestedScope() throws Exception {
        rejectsNested(OTHER);
    }

    @Test
    void rejectsSameScopeNestedOpening() throws Exception {
        rejectsNested(ACTOR);
    }

    private void rejectsNested(UUID nested) throws Exception {
        invoke(ACTOR, AUTHORITY_TIMEOUT, () -> {
            var outer = SecurityContextHolder.getContext();
            assertThatThrownBy(() -> invoke(nested, NESTED_TIMEOUT, () -> "nested"))
                    .isInstanceOf(AccessDeniedException.class);
            assertThat(SecurityContextHolder.getContext()).isSameAs(outer);
            assertThat(active()).isTrue();
            return "outer";
        });
        assertThat(server.getRequestCount()).isEqualTo(1);
        assertThat(active()).isFalse();
    }

    @Test
    void parallelPrincipalsCannotBorrowAuthority() throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(2);
        Set<Long> actorThreads = java.util.concurrent.ConcurrentHashMap.newKeySet();
        Set<Long> cleanThreads = java.util.concurrent.ConcurrentHashMap.newKeySet();
        try (var workers = Executors.newFixedThreadPool(2)) {
            var results = workers
                    .invokeAll(List.<java.util.concurrent.Callable<String>>of(
                            () -> invoke(ACTOR, PARALLEL_TIMEOUT, () -> actorAtBarrier(barrier, actorThreads)),
                            () -> invoke(OTHER, PARALLEL_TIMEOUT, () -> actorAtBarrier(barrier, actorThreads))));
            assertThat(results.get(0).get()).isEqualTo(ACTOR.toString());
            assertThat(results.get(1).get()).isEqualTo(OTHER.toString());
            var clean = workers
                    .invokeAll(List.<java.util.concurrent.Callable<Boolean>>of(
                            () -> emptyWorkerAtBarrier(barrier, cleanThreads),
                            () -> emptyWorkerAtBarrier(barrier, cleanThreads)));
            assertThat(clean.get(0).get()).isTrue();
            assertThat(clean.get(1).get()).isTrue();
        }
        assertThat(actorThreads).hasSize(2).isEqualTo(cleanThreads);
        assertThat(server.getRequestCount()).isEqualTo(2);
    }

    private boolean emptyWorkerAtBarrier(CyclicBarrier barrier, Set<Long> threads) throws Exception {
        threads.add(Thread.currentThread().threadId());
        barrier.await(2, TimeUnit.SECONDS);
        return emptyWorker();
    }

    private String actorAtBarrier(CyclicBarrier barrier, Set<Long> threads) throws Exception {
        threads.add(Thread.currentThread().threadId());
        barrier.await(2, TimeUnit.SECONDS);
        String actor = SecurityContextHolder.getContext().getAuthentication().getName();
        assertThat(LoggingHelper.getActorInfo().uuid()).hasToString(actor);
        assertThat(active()).isTrue();
        return actor;
    }

    private boolean emptyWorker() {
        return !active() && SecurityContextHolder.getContext().getAuthentication() == null
                && RequestContextHolder.getRequestAttributes() == null && MDC.getCopyOfContextMap() == null;
    }

    @Test
    void boundsScopeAfterTakingImmutableSnapshot() {
        Set<UUID> all = java.util.stream.IntStream
                .range(0, 101)
                .mapToObj(index -> new UUID(0, index))
                .collect(java.util.stream.Collectors.toSet());
        Set<UUID> growingInput = new java.util.AbstractSet<>() {
            @Override
            public int size() {
                return 100;
            }

            @Override
            public java.util.Iterator<UUID> iterator() {
                return all.iterator();
            }
        };
        assertThatThrownBy(() -> new CertificateReadScope(PROFILE, growingInput))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validatesFiniteScopeAndCopiesCallerSet() {
        var certificates = new java.util.HashSet<>(Set.of(ACTOR));
        var scope = new CertificateReadScope(PROFILE, certificates);
        certificates.add(OTHER);
        assertThat(scope.certificateUuids()).containsExactly(ACTOR);
        var immutableCertificates = scope.certificateUuids();
        assertThatThrownBy(() -> immutableCertificates.add(OTHER)).isInstanceOf(UnsupportedOperationException.class);
        Set<UUID> emptyCertificates = Set.of();
        assertThat(new CertificateReadScope(PROFILE, emptyCertificates).certificateUuids()).isEmpty();
        assertThatThrownBy(() -> new CertificateReadScope(null, emptyCertificates))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new CertificateReadScope(PROFILE, null)).isInstanceOf(NullPointerException.class);
        Set<UUID> includesNull = new java.util.HashSet<>(java.util.Arrays.asList((UUID) null));
        assertThatThrownBy(() -> new CertificateReadScope(PROFILE, includesNull))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void invalidOpeningInputsDoNotChangeCallerOrContactAuth() {
        var entry = new AiReadInvocation(authentication);
        var scope = new CertificateReadScope(PROFILE, Set.of());
        var caller = SecurityContextHolder.getContext();
        MDC.put("unrelated", "preserved");
        for (Duration timeout : java.util.Arrays
                .asList(null, Duration.ZERO, Duration.ofSeconds(-1), Duration.ofSeconds(31))) {
            assertThatThrownBy(() -> entry.call(ACTOR, scope, timeout, () -> "unused"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> entry.call(null, scope, NESTED_TIMEOUT, () -> "unused"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> entry.call(ACTOR, null, NESTED_TIMEOUT, () -> "unused"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> entry.call(ACTOR, scope, NESTED_TIMEOUT, null))
                .isInstanceOf(NullPointerException.class);
        assertThat(SecurityContextHolder.getContext()).isSameAs(caller);
        assertThat(MDC.get("unrelated")).isEqualTo("preserved");
        assertThat(server.getRequestCount()).isZero();
        assertThat(active()).isFalse();
    }

    @Test
    void closedContextCannotBeReusedAndNewThreadsHaveNoAuthority() throws Exception {
        var captured = new java.util.concurrent.atomic.AtomicReference<AiReadInvocationContext>();
        invoke(ACTOR, Duration.ofSeconds(30), () -> {
            captured.set(AiReadInvocationContext.current().orElseThrow());
            assertThat(captured.get().scope().raProfileUuid()).isEqualTo(PROFILE);
            assertThat(captured.get().pinnedActorUuid()).isEqualTo(ACTOR);
            assertThat(captured.get().invocationUuid()).isNotNull();
            assertThat(captured.get().remainingAuthorityTimeout())
                    .isPositive()
                    .isLessThanOrEqualTo(Duration.ofSeconds(5));
            try (var child = Executors.newSingleThreadExecutor()) {
                assertThat(child.submit(this::emptyWorker).get(1, TimeUnit.SECONDS)).isTrue();
            }
            return "result";
        });
        var closedContext = captured.get();
        assertThatThrownBy(closedContext::remainingAuthorityTimeout).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(closedContext::refreshPrincipal).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void queryTimeoutUsesWholeSecondsWithinRemainingBudgetAndFiveSecondCap() throws Exception {
        var captured = new java.util.concurrent.atomic.AtomicReference<AiReadInvocationContext>();
        invoke(ACTOR, Duration.ofSeconds(30), () -> {
            var context = AiReadInvocationContext.current().orElseThrow();
            captured.set(context);
            assertThat(context.remainingQueryTimeoutSeconds()).isEqualTo(5);
            return "result";
        });
        var closedContext = captured.get();
        assertThatThrownBy(closedContext::remainingQueryTimeoutSeconds).isInstanceOf(AccessDeniedException.class);
        invoke(ACTOR, Duration.ofMillis(1900), () -> {
            assertThat(AiReadInvocationContext.current().orElseThrow().remainingQueryTimeoutSeconds()).isEqualTo(1);
            return "result";
        });
    }

    @Test
    void interruptedOpeningStopsBeforeAuthentication() {
        Thread.currentThread().interrupt();
        assertThatThrownBy(() -> invoke(ACTOR, AUTHORITY_TIMEOUT, () -> "unused"))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
        assertThat(server.getRequestCount()).isZero();
        assertThat(active()).isFalse();
    }

    @Test
    void nullPlatformPrincipalIsControlledDenial() throws Exception {
        invoke(ACTOR, AUTHORITY_TIMEOUT, () -> {
            var current = (PlatformAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
            var malformed = new PlatformAuthenticationToken(current.getPrincipal()) {
                @Override
                public PlatformUserDetails getPrincipal() {
                    return null;
                }
            };
            var context = AiReadInvocationContext.current().orElseThrow();
            assertThatThrownBy(() -> context.requirePinnedActor(malformed))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasNoCause();
            return "result";
        });
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    private String invoke(UUID actor, Duration timeout, AuthHelper.ThrowingSupplier<String, Exception> operation)
            throws Exception {
        return new AiReadInvocation(authentication).call(actor, READ_SCOPE, timeout, operation);
    }

    private static boolean authorityExpired(AiReadInvocationContext context) {
        try {
            context.remainingAuthorityTimeout();
            return false;
        } catch (AccessDeniedException expired) {
            return true;
        }
    }

    private boolean active() {
        return AiReadInvocationContext.isActive();
    }

    private static String principal(UUID actor) {
        return "{\"user\":{\"uuid\":\"" + actor + "\",\"username\":\"synthetic-" + actor
                + "\",\"enabled\":true},\"roles\":[],\"permissions\":{\"allowAllResources\":false,\"resources\":[]}}";
    }

    private static void clearThread() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
        MDC.clear();
    }
}
