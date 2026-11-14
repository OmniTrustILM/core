package com.otilm.core.service.ai;

import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiModelRunInputRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.service.writer.ai.AiModelRunInputWriter;
import com.zaxxer.hikari.HikariDataSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamConstants;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.jdbc.datasource.AbstractDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AiRuntimeJdbcConnectionProviderTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void queryTimerUsesStoredOwnedFactoryAfterStartup(boolean holdCancellation) throws Exception {
        int timers = org.postgresql.Driver.getSharedTimer().getRefCount();
        try (var peer = new AiRuntimeJdbcLoopback();
                var source = source(peer.url());
                var owner = new ProviderOwner(source);
                var caller = java.util.concurrent.Executors.newSingleThreadExecutor()) {
            peer.mode = AiRuntimeJdbcLoopback.Mode.QUERY_DRIP;
            peer.holdCancellation = holdCancellation;
            var result = caller
                    .submit(() -> org.assertj.core.api.Assertions
                            .catchThrowable(() -> within(Duration.ofMillis(holdCancellation ? 1800 : 3000), () -> {
                                try (var connection = owner.provider.getConnection();
                                        var statement = connection.createStatement()) {
                                    statement.setQueryTimeout(1);
                                    statement.execute("SELECT 7");
                                }
                                return null;
                            })));
            try {
                assertThat(result.get(2, TimeUnit.SECONDS))
                        .isInstanceOfSatisfying(SQLException.class, failure -> assertThat(failure.getSQLState())
                                .startsWith(holdCancellation ? "08" : "57014"));
                assertThat(peer.cancellations.get()).isEqualTo(1);
            } finally {
                owner.provider.stop();
                caller.shutdown();
                assertThat(caller.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
            }
        }
        assertThat(org.postgresql.Driver.getSharedTimer().getRefCount()).isEqualTo(timers);
    }

    @Test
    void wholeBorrowBudgetBoundsDrippingQueryWithoutStatementTimeout() throws Exception {
        try (var peer = new AiRuntimeJdbcLoopback();
                var source = source(peer.url());
                var owner = new ProviderOwner(source);
                var caller = java.util.concurrent.Executors.newSingleThreadExecutor()) {
            peer.mode = AiRuntimeJdbcLoopback.Mode.QUERY_DRIP;
            var result = caller.submit(() -> org.assertj.core.api.Assertions.catchThrowable(() -> {
                try (var connection = within(Duration.ofMillis(800), owner.provider::getConnection);
                        var statement = connection.createStatement()) {
                    assertThat(AiRuntimeJdbcBudget.current()).isNull();
                    statement.execute("SELECT 7");
                }
            }));
            try {
                assertThat(result.get(1200, TimeUnit.MILLISECONDS))
                        .isInstanceOfSatisfying(SQLException.class,
                                failure -> assertThat(failure.getSQLState()).startsWith("08"));
            } finally {
                owner.provider.stop();
                caller.shutdown();
                assertThat(caller.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
            }
        }
    }

    @Test
    void returnedBorrowWatchdogCannotAbortSamePhysicalConnectionOnItsNextBorrow() throws Exception {
        try (var peer = new AiRuntimeJdbcLoopback();
                var source = source(peer.url());
                var owner = new ProviderOwner(source);
                var observer = java.util.concurrent.Executors.newSingleThreadScheduledExecutor()) {
            org.postgresql.jdbc.PgConnection first;
            try (var connection = within(Duration.ofMillis(800), owner.provider::getConnection)) {
                first = connection.unwrap(org.postgresql.jdbc.PgConnection.class);
            }
            try (var connection = within(Duration.ofSeconds(2), owner.provider::getConnection)) {
                assertThat(connection.unwrap(org.postgresql.jdbc.PgConnection.class)).isSameAs(first);
                var checkpoint = new java.util.concurrent.CountDownLatch(1);
                observer.schedule(checkpoint::countDown, 900, TimeUnit.MILLISECONDS);
                assertThat(checkpoint.await(1500, TimeUnit.MILLISECONDS)).isTrue();
                assertThat(connection.isValid(1)).isTrue();
            }
            observer.shutdown();
            assertThat(observer.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void ordinaryJpaTransactionRejectsFirstAiWriterScopeWithoutChangingItsTransaction() throws Exception {
        var source = new org.hsqldb.jdbc.JDBCDataSource();
        source.setUrl("jdbc:hsqldb:mem:aiJdbcExistingTransaction");
        source.setUser("SA");
        try (var owner = new ProviderOwner(source); var factory = factory(owner.provider, false)) {
            var manager = new org.springframework.orm.jpa.JpaTransactionManager(factory);
            manager.setJpaDialect(new org.springframework.orm.jpa.vendor.HibernateJpaDialect());
            manager.afterPropertiesSet();
            var runtime = mock(AiRuntimeRepository.class);
            var writer = writer(manager, runtime);
            new org.springframework.transaction.support.TransactionTemplate(manager).execute(ignored -> {
                var entityManager = org.springframework.orm.jpa.EntityManagerFactoryUtils
                        .getTransactionalEntityManager(factory);
                assertThat(entityManager.createNativeQuery("VALUES(1)", Integer.class).getSingleResult()).isEqualTo(1);
                assertThatThrownBy(() -> writer
                        .connection(UUID.randomUUID(), AiRuntimeOperationBudget.start(Duration.ofMillis(50))))
                        .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
                assertThat(org.springframework.transaction.support.TransactionSynchronizationManager
                        .isActualTransactionActive()).isTrue();
                assertThat(entityManager.createNativeQuery("VALUES(1)", Integer.class).getSingleResult()).isEqualTo(1);
                org.mockito.Mockito.verifyNoInteractions(runtime);
                return null;
            });
        }
    }

    @Test
    void existingJpaTransactionWithSameAiBudgetAllowsNestedWriter() throws Exception {
        try (var peer = new AiRuntimeJdbcLoopback();
                var source = source(peer.url());
                var owner = new ProviderOwner(source);
                var factory = factory(owner.provider, true)) {
            var manager = new org.springframework.orm.jpa.JpaTransactionManager(factory);
            manager.setJpaDialect(new org.springframework.orm.jpa.vendor.HibernateJpaDialect());
            manager.afterPropertiesSet();
            var writer = writer(manager, mock(AiRuntimeRepository.class));
            var budget = AiRuntimeOperationBudget.start();
            var result = within(budget, () -> new org.springframework.transaction.support.TransactionTemplate(manager)
                    .execute(ignored -> writer.connection(UUID.randomUUID(), budget)));
            assertThat(result).isEmpty();
            assertThat(source.isRunning()).isFalse();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"commit", "rollback"})
    void lastMomentCompletionCannotRecycleAbortedPhysicalConnection(String operation) throws Exception {
        try (var peer = new AiRuntimeJdbcLoopback();
                var source = source(peer.url());
                var owner = new ProviderOwner(source)) {
            var time = new java.util.concurrent.atomic.AtomicLong();
            var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(1), time::get);
            var physical = within(budget, () -> {
                try (var connection = owner.provider.getConnection()) {
                    var raw = connection.unwrap(org.postgresql.jdbc.PgConnection.class);
                    time.set(TimeUnit.MILLISECONDS.toNanos(950));
                    assertThatThrownBy(() -> {
                        if (operation.equals("commit")) {
                            connection.commit();
                        } else {
                            connection.rollback();
                        }
                    })
                            .isInstanceOfSatisfying(SQLException.class,
                                    failure -> assertThat(failure.getSQLState()).startsWith("08"));
                    assertThat(raw.isClosed()).isTrue();
                    return raw;
                }
            });
            try (var next = bounded(owner.provider::getConnection)) {
                assertThat(next.unwrap(org.postgresql.jdbc.PgConnection.class)).isNotSameAs(physical);
                assertThat(next.isValid(1)).isTrue();
            }
        }
    }

    @Test
    void hibernateConfigurationRetainsNormalSqlAndDatasourceMetadata() throws Exception {
        try (var source = new HikariDataSource()) {
            source.setJdbcUrl("jdbc:hsqldb:mem:aiJdbcOrdinary");
            source.setDriverClassName("org.hsqldb.jdbc.JDBCDriver");
            source.setUsername("SA");
            source.setPassword("");
            var wiring = new AiRuntimeJdbcConfiguration();
            var provider = wiring.aiRuntimeJdbcConnectionProvider(source);
            var properties = new java.util.HashMap<String, Object>();
            wiring.aiRuntimeJdbcProviderCustomizer(provider).customize(properties);
            var configuration = new org.hibernate.cfg.Configuration();
            configuration.getProperties().putAll(properties);
            configuration.setProperty("hibernate.hbm2ddl.auto", "none");
            try (var factory = configuration.buildSessionFactory(); var session = factory.openSession()) {
                assertThat(session.createNativeQuery("VALUES(1)", Integer.class).getSingleResult()).isEqualTo(1);
                assertThat(provider.unwrap(DataSource.class)).isSameAs(source);
            } finally {
                provider.stop();
            }
        }
    }

    @Test
    void nestedBudgetScopePreservesOriginalAndRestoresAfterFailure() throws Throwable {
        var scope = new AiRuntimeJdbcBudget();
        var budget = AiRuntimeOperationBudget.start();
        var outer = mock(ProceedingJoinPoint.class);
        var inner = mock(ProceedingJoinPoint.class);
        when(inner.proceed()).thenAnswer(ignored -> {
            assertThat(AiRuntimeJdbcBudget.current()).isSameAs(budget);
            throw new IllegalStateException("Synthetic nested failure");
        });
        when(outer.proceed()).thenAnswer(ignored -> {
            assertThatThrownBy(() -> scope.invoke(inner, budget)).isInstanceOf(IllegalStateException.class);
            assertThat(AiRuntimeJdbcBudget.current()).isSameAs(budget);
            assertThatThrownBy(() -> scope.invoke(inner, AiRuntimeOperationBudget.start()))
                    .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            return "restored";
        });
        assertThat(scope.invoke(outer, budget)).isEqualTo("restored");
        assertThat(AiRuntimeJdbcBudget.current()).isNull();
    }

    @Test
    void ordinaryConnectionsAndLifecycleRetainTheirDatasource() throws Exception {
        var source = mock(DataSource.class);
        var connection = mock(Connection.class);
        when(source.getConnection()).thenReturn(connection);
        when(source.getConnection("actor", "synthetic")).thenReturn(connection);
        var provider = new AiRuntimeJdbcConnectionProvider(source);
        provider.configure(Map.of());
        assertThat(provider.getConnection()).isSameAs(connection);
        assertThat(provider.getConnection("actor", "synthetic")).isSameAs(connection);
        assertThat(provider.unwrap(DataSource.class)).isSameAs(source);
        assertThat(provider.unwrap(AiRuntimeJdbcConnectionProvider.class)).isSameAs(provider);
        assertThat(provider.isUnwrappableAs(DataSource.class)).isTrue();
        assertThat(provider.supportsAggressiveRelease()).isTrue();
        provider.closeConnection(connection);
        verify(connection).close();
        provider.stop();
        provider.stop();
        assertThatThrownBy(provider::getConnection).hasMessage("Provider is closed");
    }

    @Test
    void serializationRejectsLiveProviderResources() throws Exception {
        try (var owner = new ProviderOwner(mock(DataSource.class));
                var bytes = new ByteArrayOutputStream();
                var output = new ObjectOutputStream(bytes)) {
            assertThatThrownBy(() -> output.writeObject(owner.provider))
                    .isInstanceOf(NotSerializableException.class)
                    .hasMessage("AI JDBC provider serialization unavailable");
        }
    }

    @Test
    void deserializationRejectsProviderWithoutRuntimeResources() throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var output = new DataOutputStream(bytes)) {
            output.writeShort(ObjectStreamConstants.STREAM_MAGIC);
            output.writeShort(ObjectStreamConstants.STREAM_VERSION);
            output.writeByte(ObjectStreamConstants.TC_OBJECT);
            output.writeByte(ObjectStreamConstants.TC_CLASSDESC);
            output.writeUTF(AiRuntimeJdbcConnectionProvider.class.getName());
            output.writeLong(1L);
            output.writeByte(ObjectStreamConstants.SC_SERIALIZABLE);
            output.writeShort(0);
            output.writeByte(ObjectStreamConstants.TC_ENDBLOCKDATA);
            output.writeByte(ObjectStreamConstants.TC_NULL);
        }
        try (var input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            assertThatThrownBy(input::readObject)
                    .isInstanceOf(NotSerializableException.class)
                    .hasMessage("AI JDBC provider serialization unavailable");
        }
    }

    @Test
    void actualWriterInstallsBudgetBeforeTransactionAcquisition() {
        var source = mock(DataSource.class);
        var provider = new AiRuntimeJdbcConnectionProvider(source);
        try {
            var transactionalSource = new AbstractDataSource() {
                @Override
                public Connection getConnection() throws SQLException {
                    return provider.getConnection();
                }

                @Override
                public Connection getConnection(String user, String password) throws SQLException {
                    return provider.getConnection(user, password);
                }
            };
            var writer = writer(new DataSourceTransactionManager(transactionalSource), mock(AiRuntimeRepository.class));
            long started = System.nanoTime();
            assertThatThrownBy(
                    () -> writer.connection(UUID.randomUUID(), AiRuntimeOperationBudget.start(Duration.ofMillis(50))))
                    .hasRootCauseInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(300));
            assertThat(AiRuntimeJdbcBudget.current()).isNull();
            org.mockito.Mockito.verifyNoInteractions(source);
        } finally {
            provider.stop();
        }
    }

    @Test
    void sourcePropertiesAndTlsIdentitySettingsAreCopiedWithoutMutation() {
        try (var source = source("jdbc:postgresql://127.0.0.1:5432/synthetic"
                + "?gssEncMode=disable&sslmode=verify-full&sslpassword=&sslrootcert=synthetic-root.pem")) {
            var original = new Properties();
            original.putAll(source.getDataSourceProperties());
            int loginTimeout = DriverManager.getLoginTimeout();
            var properties = AiRuntimeJdbcConnectionProvider.connectionProperties(source);
            assertThat(properties.getProperty("sslmode")).isEqualTo("verify-full");
            assertThat(properties.getProperty("sslrootcert")).isEqualTo("synthetic-root.pem");
            try (var provider = new ProviderOwner(source)) {
                assertThat(source.getConnectionTimeout()).isEqualTo(30000);
                assertThat(source.getDataSourceProperties()).isEqualTo(original);
                assertThat(DriverManager.getLoginTimeout()).isEqualTo(loginTimeout);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "256.0.0.1", "127.00.0.1", "127.0.0.1,127.0.0.2", "[::1]"})
    void unsupportedEndpointFailsClosedForAiOnly(String host) {
        try (var source = source("jdbc:postgresql://" + host + ":5432/synthetic?gssEncMode=disable")) {
            assertThatThrownBy(() -> AiRuntimeJdbcConnectionProvider.connectionProperties(source))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "socketFactory=untrusted.Factory",
            "socketFactoryArg=untrusted",
            "connectExecutor=untrusted.Executor",
            "sslhostnameverifier=untrusted.Verifier",
            "sslpasswordcallback=untrusted.Callback",
            "authenticationPluginClassName=untrusted.Plugin",
            "sslfactory=org.postgresql.ssl.NonValidatingFactory"})
    void urlPropertiesCannotOverrideOwnedTransportOrTlsVerification(String property) {
        try (var source = source("jdbc:postgresql://127.0.0.1/synthetic?gssEncMode=disable&" + property)) {
            assertThatThrownBy(() -> AiRuntimeJdbcConnectionProvider.connectionProperties(source))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void exhaustedPrivatePoolObeysRemainingBudgetAndOrdinaryPoolIsUnused() throws Exception {
        try (var peer = new AiRuntimeJdbcLoopback();
                var source = source(peer.url());
                var owner = new ProviderOwner(source)) {
            var provider = owner.provider;
            try (var first = bounded(provider::getConnection); var second = bounded(provider::getConnection)) {
                long started = System.nanoTime();
                assertThatThrownBy(() -> within(Duration.ofMillis(800), provider::getConnection))
                        .isInstanceOf(SQLException.class);
                assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(800));
                assertThat(first.isClosed()).isFalse();
                assertThat(second.isClosed()).isFalse();
                assertThat(source.isRunning()).isFalse();
            }
        }
    }

    @Test
    void poolWorkerTrackingPrunesRetiredThreadsAndRetainsUnfinishedThreads() throws Exception {
        try (var source = source("jdbc:postgresql://127.0.0.1:5432/synthetic?gssEncMode=disable&sslmode=disable");
                var owner = new ProviderOwner(source)) {
            var pool = (HikariDataSource) ReflectionTestUtils.getField(owner.provider, "ai");
            var workers = (java.util.Set<?>) ReflectionTestUtils.getField(owner.provider, "workers");
            var factory = pool.getThreadFactory();
            int initialWorkers = workers.size();
            var pending = factory.newThread(() -> {
            });
            var started = new java.util.concurrent.CountDownLatch(1);
            var release = new java.util.concurrent.CountDownLatch(1);
            var live = factory.newThread(() -> {
                started.countDown();
                try {
                    release.await();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            });
            try {
                live.start();
                assertThat(started.await(1, TimeUnit.SECONDS)).isTrue();
                for (int i = 0; i < 64; i++) {
                    var retired = factory.newThread(() -> {
                    });
                    retired.start();
                    retired.join(1000);
                    assertThat(retired.getState()).isEqualTo(Thread.State.TERMINATED);
                    assertThat(workers).hasSize(initialWorkers + 3);
                    assertThat(workers.toArray()).contains(pending, live);
                    assertThat(pending.getState()).isEqualTo(Thread.State.NEW);
                    assertThat(live.isAlive()).isTrue();
                }
                assertThat(source.isRunning()).isFalse();
            } finally {
                release.countDown();
                pending.start();
                pending.join(1000);
                live.join(1000);
                assertThat(pending.isAlive()).isFalse();
                assertThat(live.isAlive()).isFalse();
            }
        }
    }

    @Test
    void shutdownClosesDrippingStartupBeforeJoiningOwnedPoolWorkers() throws Exception {
        try (var peer = new AiRuntimeJdbcLoopback(); var source = source(peer.url())) {
            peer.mode = AiRuntimeJdbcLoopback.Mode.STARTUP_DRIP;
            var provider = new AiRuntimeJdbcConnectionProvider(source);
            long started = System.nanoTime();
            try {
                assertThatThrownBy(() -> within(Duration.ofMillis(800), provider::getConnection))
                        .isInstanceOf(SQLException.class);
            } finally {
                provider.stop();
            }
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
            assertThat(source.isRunning()).isFalse();
        }
    }

    @Test
    void watchdogAbortsDrippingRealDriverValidationBeforeBorrowDeadline() throws Exception {
        String old = System.getProperty("com.zaxxer.hikari.aliveBypassWindowMs");
        System.setProperty("com.zaxxer.hikari.aliveBypassWindowMs", "-1");
        try (var peer = new AiRuntimeJdbcLoopback();
                var source = source(peer.url());
                var owner = new ProviderOwner(source)) {
            try (var connection = bounded(owner.provider::getConnection)) {
                assertThat(connection.isClosed()).isFalse();
            }
            peer.mode = AiRuntimeJdbcLoopback.Mode.VALIDATION_DRIP;
            long started = System.nanoTime();
            assertThatThrownBy(() -> within(Duration.ofMillis(1100), owner.provider::getConnection))
                    .isInstanceOf(SQLException.class);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(1100));
        } finally {
            if (old == null) {
                System.clearProperty("com.zaxxer.hikari.aliveBypassWindowMs");
            } else {
                System.setProperty("com.zaxxer.hikari.aliveBypassWindowMs", old);
            }
        }
    }

    private static HikariDataSource source(String url) {
        var source = new HikariDataSource();
        source.setJdbcUrl(url);
        source.setDriverClassName("org.postgresql.Driver");
        source.setUsername("synthetic");
        source.setPassword("");
        return source;
    }

    private static org.hibernate.SessionFactory factory(AiRuntimeJdbcConnectionProvider provider, boolean postgres) {
        var properties = new java.util.HashMap<String, Object>();
        new AiRuntimeJdbcConfiguration().aiRuntimeJdbcProviderCustomizer(provider).customize(properties);
        var configuration = new org.hibernate.cfg.Configuration();
        configuration.getProperties().putAll(properties);
        configuration.setProperty("hibernate.hbm2ddl.auto", "none");
        if (postgres) {
            configuration.setProperty("hibernate.boot.allow_jdbc_metadata_access", "false");
            configuration.setProperty("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
        }
        return configuration.buildSessionFactory();
    }

    private static AiModelRunInputWriter writer(org.springframework.transaction.PlatformTransactionManager manager,
            AiRuntimeRepository runtime) {
        var target = new AiModelRunInputWriter(runtime, mock(AiModelDispatchRepository.class),
                mock(AiModelRunInputRepository.class));
        var proxy = new AspectJProxyFactory(target);
        proxy.addAspect(new AiRuntimeJdbcBudget());
        var transactions = new TransactionInterceptor();
        transactions.setTransactionManager(manager);
        transactions.setTransactionAttributeSource(new AnnotationTransactionAttributeSource());
        proxy.addAdvice(transactions);
        return proxy.getProxy();
    }

    private static <T> T bounded(Callable<T> operation) throws Exception {
        return within(Duration.ofSeconds(5), operation);
    }

    private static <T> T within(Duration timeout, Callable<T> operation) throws Exception {
        return within(AiRuntimeOperationBudget.start(timeout), operation);
    }

    private static <T> T within(AiRuntimeOperationBudget budget, Callable<T> operation) throws Exception {
        var invocation = mock(ProceedingJoinPoint.class);
        try {
            when(invocation.proceed()).thenAnswer(ignored -> operation.call());
            @SuppressWarnings("unchecked")
            T value = (T) new AiRuntimeJdbcBudget().invoke(invocation, budget);
            return value;
        } catch (Exception failure) {
            throw failure;
        } catch (Throwable failure) {
            throw new AssertionError(failure);
        }
    }

    private static final class ProviderOwner implements AutoCloseable {
        private final AiRuntimeJdbcConnectionProvider provider;

        private ProviderOwner(DataSource source) {
            provider = new AiRuntimeJdbcConnectionProvider(source);
        }

        @Override
        public void close() {
            provider.stop();
        }
    }
}
