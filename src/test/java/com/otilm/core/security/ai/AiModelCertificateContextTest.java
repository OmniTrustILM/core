package com.otilm.core.security.ai;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.handler.StoredCertificateHealth;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AiModelCertificateContextTest {
    private static final UUID ACTOR = UUID.fromString("a1000000-0000-0000-0000-000000000001");
    private static final UUID MODEL = UUID.fromString("b1000000-0000-0000-0000-000000000001");
    private static final UUID PROFILE = UUID.fromString("c1000000-0000-0000-0000-000000000001");
    private static final UUID FIRST = UUID.fromString("d1000000-0000-0000-0000-000000000001");
    private static final UUID SECOND = UUID.fromString("d2000000-0000-0000-0000-000000000002");
    private final AiModelUseAuthorization model = mock(AiModelUseAuthorization.class);
    private final PlatformAuthenticationClient auth = mock(PlatformAuthenticationClient.class);
    private final CertificateExternalService certificates = mock(CertificateExternalService.class);
    private AiModelCertificateContext context;

    @BeforeEach
    void setup() {
        context = new AiModelCertificateContext(model, new AiReadInvocation(auth), certificates);
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenReturn(principal());
    }

    @AfterEach
    void cleanup() {
        Thread.interrupted();
        SecurityContextHolder.clearContext();
        MDC.clear();
        assertThat(AiReadInvocationContext.isActive()).isFalse();
    }

    @Test
    void modelUsePrecedesEveryScopedReadAndReturnsOnlyTheExactImmutableContext() throws Exception {
        var events = new ArrayList<String>();
        doAnswer(call -> {
            events.add("model");
            return null;
        }).when(model).requireUse(eq(ACTOR), eq(MODEL), any());
        when(certificates.getStoredCertificateHealth(any(), any())).thenAnswer(call -> {
            UUID id = call.getArgument(1, com.otilm.core.security.authz.SecuredUUID.class).getValue();
            assertThat(call.getArgument(0, com.otilm.core.security.authz.SecuredParentUUID.class).getValue())
                    .isEqualTo(PROFILE);
            assertThat(AiReadInvocationContext.current().orElseThrow().scope()).isEqualTo(scope());
            assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo(ACTOR.toString());
            assertThat(MDC.get("caller")).isNull();
            events.add(id.toString());
            return health(id, PROFILE);
        });
        var caller = SecurityContextHolder.createEmptyContext();
        caller.setAuthentication(new TestingAuthenticationToken("unrelated", "synthetic-credential"));
        SecurityContextHolder.setContext(caller);
        MDC.put("caller", "retained");

        var result = context.read(ACTOR, MODEL, scope(), AiRuntimeOperationBudget.start());

        assertThat(events).containsExactly("model", FIRST.toString(), SECOND.toString());
        assertThat(result).containsExactly(health(FIRST, PROFILE), health(SECOND, PROFILE));
        assertThatThrownBy(result::clear).isInstanceOf(UnsupportedOperationException.class);
        assertThat(SecurityContextHolder.getContext()).isSameAs(caller);
        assertThat(MDC.get("caller")).isEqualTo("retained");
    }

    @Test
    void modelDenialPreventsAllProtectedReadsAndHidesTheFailureBody() {
        doThrow(new AccessDeniedException("synthetic-private-model-body"))
                .when(model)
                .requireUse(eq(ACTOR), eq(MODEL), any());
        denied(() -> context.read(ACTOR, MODEL, scope(), AiRuntimeOperationBudget.start()));
        verifyNoInteractions(auth, certificates);
    }

    @Test
    void actorRevocationPreventsEveryCertificateRead() {
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any()))
                .thenThrow(new IllegalStateException("synthetic-private-auth-body"));
        denied(() -> context.read(ACTOR, MODEL, scope(), AiRuntimeOperationBudget.start()));
        verifyNoInteractions(certificates);
    }

    @ParameterizedTest
    @ValueSource(strings = {"denied", "missing", "foreign-certificate", "foreign-profile", "null", "interrupted"})
    void anyLostOrChangedRetainedObjectRejectsTheWholeContext(String failure) throws Exception {
        var reachedSecond = new AtomicBoolean();
        when(certificates.getStoredCertificateHealth(any(), any())).thenAnswer(call -> {
            UUID id = call.getArgument(1, com.otilm.core.security.authz.SecuredUUID.class).getValue();
            if (id.equals(FIRST)) {
                return health(FIRST, PROFILE);
            }
            reachedSecond.set(true);
            return switch (failure) {
                case "denied" -> throw new AccessDeniedException("synthetic-private-policy-body");
                case "missing" -> throw new com.otilm.api.exception.NotFoundException("synthetic-private-object");
                case "foreign-certificate" -> health(FIRST, PROFILE);
                case "foreign-profile" -> health(SECOND, MODEL);
                case "null" -> null;
                default -> {
                    Thread.currentThread().interrupt();
                    yield health(SECOND, PROFILE);
                }
            };
        });
        denied(() -> context.read(ACTOR, MODEL, scope(), AiRuntimeOperationBudget.start()));
        assertThat(reachedSecond).isTrue();
        assertThat(Thread.currentThread().isInterrupted()).isEqualTo(failure.equals("interrupted"));
    }

    @Test
    void eachNewPreparationRechecksModelPermission() throws Exception {
        when(certificates.getStoredCertificateHealth(any(), any()))
                .thenAnswer(call -> health(
                        call.getArgument(1, com.otilm.core.security.authz.SecuredUUID.class).getValue(), PROFILE));
        assertThat(context.read(ACTOR, MODEL, scope(), AiRuntimeOperationBudget.start())).hasSize(2);
        doThrow(new AccessDeniedException("revoked")).when(model).requireUse(eq(ACTOR), eq(MODEL), any());
        denied(() -> context.read(ACTOR, MODEL, scope(), AiRuntimeOperationBudget.start()));
        verify(model, org.mockito.Mockito.times(2)).requireUse(eq(ACTOR), eq(MODEL), any());
        verify(certificates, org.mockito.Mockito.times(2)).getStoredCertificateHealth(any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"actor", "model", "scope", "budget", "interrupted"})
    void invalidOrInterruptedPreparationNeverStartsAuthorization(String invalid) {
        if (invalid.equals("interrupted")) {
            Thread.currentThread().interrupt();
        }
        denied(() -> context
                .read(invalid.equals("actor") ? null : ACTOR, invalid.equals("model") ? null : MODEL,
                        invalid.equals("scope") ? null : scope(),
                        invalid.equals("budget") ? null : AiRuntimeOperationBudget.start()));
        verifyNoInteractions(model, auth, certificates);
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void exhaustedSharedBudgetPreventsReturningProtectedContext(int retainedObjects) throws Exception {
        var budget = mock(AiRuntimeOperationBudget.class);
        when(budget.remaining()).thenReturn(Duration.ofSeconds(2));
        when(certificates.getStoredCertificateHealth(any(), any())).thenAnswer(call -> {
            when(budget.remaining()).thenThrow(new AiRuntimeOperationBudget.Unavailable(false));
            return health(FIRST, PROFILE);
        });
        var retained = retainedObjects == 1 ? new CertificateReadScope(PROFILE, Set.of(FIRST)) : scope();
        denied(() -> context.read(ACTOR, MODEL, retained, budget));
        verify(certificates).getStoredCertificateHealth(any(), any());
    }

    @Test
    void emptyRetainedScopeReturnsNoObjectsAndStillRequiresCurrentAuthority() {
        assertThat(context
                .read(ACTOR, MODEL, new CertificateReadScope(PROFILE, Set.of()), AiRuntimeOperationBudget.start()))
                .isEmpty();
        verify(model).requireUse(eq(ACTOR), eq(MODEL), any());
        verify(auth).authenticateByUserUuidAuthoritatively(eq(ACTOR), any());
        verifyNoInteractions(certificates);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void springSuspendsAmbientTransactionForAllAuthorityAndReadCalls(boolean denied) throws Exception {
        var source = mock(javax.sql.DataSource.class);
        var connection = mock(java.sql.Connection.class);
        when(source.getConnection()).thenReturn(connection);
        when(connection.getAutoCommit()).thenReturn(true);
        var manager = new org.springframework.jdbc.datasource.DataSourceTransactionManager(source);
        var factory = new org.springframework.aop.framework.ProxyFactory(context);
        factory.setProxyTargetClass(true);
        factory
                .addAdvice(new org.springframework.transaction.interceptor.TransactionInterceptor(manager,
                        new org.springframework.transaction.annotation.AnnotationTransactionAttributeSource()));
        var proxy = (AiModelCertificateContext) factory.getProxy();
        doAnswer(call -> {
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isFalse();
            return null;
        }).when(model).requireUse(eq(ACTOR), eq(MODEL), any());
        when(auth.authenticateByUserUuidAuthoritatively(eq(ACTOR), any())).thenAnswer(call -> {
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isFalse();
            return principal();
        });
        when(certificates.getStoredCertificateHealth(any(), any())).thenAnswer(call -> {
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isFalse();
            if (denied) {
                throw new AccessDeniedException("synthetic-private-policy-body");
            }
            return health(call.getArgument(1, com.otilm.core.security.authz.SecuredUUID.class).getValue(), PROFILE);
        });
        new org.springframework.transaction.support.TransactionTemplate(manager).executeWithoutResult(ignored -> {
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isTrue();
            if (denied) {
                denied(() -> proxy.read(ACTOR, MODEL, scope(), AiRuntimeOperationBudget.start()));
            } else {
                assertThat(proxy.read(ACTOR, MODEL, scope(), AiRuntimeOperationBudget.start())).hasSize(2);
            }
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                    .isActualTransactionActive()).isTrue();
        });
    }

    @Test
    void diagnosticLogsContainOnlyFixedMetadataAndCorrelation() {
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(AiModelCertificateContext.class);
        var previous = logger.getLevel();
        var events = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        events.start();
        logger.addAppender(events);
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        try {
            var empty = new CertificateReadScope(PROFILE, Set.of());
            context.read(ACTOR, MODEL, empty, AiRuntimeOperationBudget.start());
            doThrow(new AccessDeniedException("synthetic-private-model-body"))
                    .when(model)
                    .requireUse(eq(ACTOR), eq(MODEL), any());
            denied(() -> context.read(ACTOR, MODEL, empty, AiRuntimeOperationBudget.start()));
            assertThat(events.list).hasSize(2).allSatisfy(event -> {
                assertThat(event.getFormattedMessage())
                        .matches(
                                "AI model context operation=certificate-read code=(AUTHORIZED|DENIED) correlation=[0-9a-f-]{36}");
                assertThat(event.getThrowableProxy()).isNull();
            });
        } finally {
            logger.detachAppender(events);
            logger.setLevel(previous);
            events.stop();
        }
    }

    private static CertificateReadScope scope() {
        return new CertificateReadScope(PROFILE, Set.of(SECOND, FIRST));
    }

    private static StoredCertificateHealth health(UUID id, UUID profile) {
        return new StoredCertificateHealth(id, profile, null, null, null, null, null, null, null, null, null, Map.of(),
                StoredCertificateHealth.Evidence.MISSING);
    }

    private static AuthenticationInfo principal() {
        String raw = "{\"user\":{\"uuid\":\"" + ACTOR
                + "\",\"username\":\"synthetic\",\"enabled\":true},\"roles\":[],\"permissions\":{}}";
        return new AuthenticationInfo(AuthMethod.USER_PROXY, ACTOR.toString(), "synthetic", List.of(), raw);
    }

    private static void denied(Runnable operation) {
        assertThatThrownBy(operation::run)
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause()
                .hasMessage("Model certificate context unavailable");
    }
}
