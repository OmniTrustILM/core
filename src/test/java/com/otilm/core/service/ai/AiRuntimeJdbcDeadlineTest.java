package com.otilm.core.service.ai;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AiRuntimeJdbcDeadlineTest {
    @Test
    void cleanupFailureRemainsPrimaryWhenWorkerShutdownIsInterrupted() throws Exception {
        var caller = Thread.currentThread();
        var closing = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var attempt = new AtomicReference<AiRuntimeJdbcDeadline.Attempt>();
        var owner = new AiRuntimeJdbcDeadline();
        owner.connect(() -> {
            try {
                attempt.set(AiRuntimeJdbcDeadline.connecting());
                attempt.get().register(new Socket() {
                    @Override
                    public void close() throws IOException {
                        super.close();
                        if (Thread.currentThread() != caller) {
                            closing.countDown();
                            try {
                                if (!release.await(1, TimeUnit.SECONDS)) {
                                    throw new IOException("Synthetic cleanup guard expired");
                                }
                            } catch (InterruptedException failure) {
                                Thread.currentThread().interrupt();
                                throw new IOException(failure);
                            }
                        }
                        throw new IOException("Synthetic socket cleanup failure");
                    }
                });
            } catch (IOException failure) {
                throw new SQLException(failure);
            }
            return mock(Connection.class);
        });
        try (var lease = attempt.get().lease(java.time.Duration.ofMillis(1))) {
            assertThat(closing.await(1, TimeUnit.SECONDS)).isTrue();
            Thread.currentThread().interrupt();
            try {
                assertThatThrownBy(owner::close)
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessage("AI JDBC socket cleanup unavailable")
                        .hasSuppressedException(new IllegalStateException("AI JDBC deadline shutdown interrupted"));
                assertThat(Thread.currentThread().isInterrupted()).isTrue();
            } finally {
                Thread.interrupted();
                release.countDown();
            }
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void driverErrorClosesOwnedSocketBeforeRethrow(boolean bounded) throws SQLException {
        var physical = mock(Connection.class);
        var failure = new AssertionError("Synthetic driver error");
        when(physical.isValid(1)).thenThrow(failure);
        when(physical.getWarnings()).thenThrow(failure);
        var socket = new AtomicReference<Socket>();
        try (var owner = new AiRuntimeJdbcDeadline(); var connection = owner.connect(() -> {
            try {
                socket.set(new AiRuntimeJdbcSocketFactory().createSocket());
            } catch (IOException problem) {
                throw new SQLException(problem);
            }
            return physical;
        })) {
            org.assertj.core.api.ThrowableAssert.ThrowingCallable operation = bounded
                    ? () -> connection.isValid(1)
                    : connection::getWarnings;
            assertThatThrownBy(operation).isSameAs(failure);
            assertThat(socket.get().isClosed()).isTrue();
        }
    }

    @Test
    void closingBorrowKeepsItsDeadlineUntilPooledCleanupFinishes() throws Exception {
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var physical = mock(Connection.class);
        org.mockito.Mockito.doAnswer(ignored -> {
            release.countDown();
            return null;
        }).when(physical).abort(org.mockito.ArgumentMatchers.any());
        try (var owner = new AiRuntimeJdbcDeadline(); var caller = Executors.newSingleThreadExecutor()) {
            var owned = owner.connect(() -> physical);
            var pooled = mock(Connection.class);
            when(pooled.unwrap(AiRuntimeJdbcDeadline.OwnedConnection.class))
                    .thenReturn(owned.unwrap(AiRuntimeJdbcDeadline.OwnedConnection.class));
            org.mockito.Mockito.doAnswer(ignored -> {
                entered.countDown();
                if (!release.await(1, TimeUnit.SECONDS)) {
                    throw new SQLException("Synthetic pooled cleanup guard");
                }
                return null;
            }).when(pooled).close();
            var borrowed = owner
                    .borrow(pooled, AiRuntimeOperationBudget.start(java.time.Duration.ofMillis(300)), ignored -> {
                    });
            var result = caller.submit(() -> org.assertj.core.api.Assertions.catchThrowable(borrowed::close));
            try {
                assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
                assertThat(result.get(600, TimeUnit.MILLISECONDS)).isInstanceOf(SQLException.class);
            } finally {
                release.countDown();
                caller.shutdown();
                assertThat(caller.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
            }
        }
    }

    @Test
    void nextBorrowDisarmsPredecessorBeforeItsCloseReturnsFromRecycleWindow() throws Exception {
        var recycled = new CountDownLatch(1);
        var finishClose = new CountDownLatch(1);
        var evictions = new java.util.concurrent.atomic.AtomicInteger();
        var socket = new AtomicReference<Socket>();
        try (var owner = new AiRuntimeJdbcDeadline();
                var caller = Executors.newSingleThreadExecutor();
                var observer = Executors.newSingleThreadScheduledExecutor()) {
            var owned = owner.connect(() -> {
                try {
                    socket.set(new AiRuntimeJdbcSocketFactory().createSocket());
                } catch (IOException failure) {
                    throw new SQLException(failure);
                }
                return mock(Connection.class);
            });
            var pooled = mock(Connection.class);
            when(pooled.unwrap(AiRuntimeJdbcDeadline.OwnedConnection.class))
                    .thenReturn(owned.unwrap(AiRuntimeJdbcDeadline.OwnedConnection.class));
            org.mockito.Mockito.doAnswer(ignored -> {
                recycled.countDown();
                if (!finishClose.await(1, TimeUnit.SECONDS)) {
                    throw new SQLException("Synthetic recycle-window guard");
                }
                return null;
            }).when(pooled).close();
            var first = owner
                    .borrow(pooled, AiRuntimeOperationBudget.start(java.time.Duration.ofMillis(400)),
                            ignored -> evictions.incrementAndGet());
            var closing = caller.submit(() -> org.assertj.core.api.Assertions.catchThrowable(first::close));
            try {
                assertThat(recycled.await(1, TimeUnit.SECONDS)).isTrue();
                try (var second = owner
                        .borrow(pooled, AiRuntimeOperationBudget.start(java.time.Duration.ofSeconds(2)),
                                ignored -> evictions.incrementAndGet())) {
                    var checkpoint = new CountDownLatch(1);
                    observer.schedule(checkpoint::countDown, 550, TimeUnit.MILLISECONDS);
                    assertThat(checkpoint.await(1, TimeUnit.SECONDS)).isTrue();
                    assertThat(socket.get().isClosed()).isFalse();
                    finishClose.countDown();
                    assertThat(closing.get(1, TimeUnit.SECONDS)).isNull();
                }
                assertThat(evictions.get()).isZero();
            } finally {
                finishClose.countDown();
                caller.shutdown();
                observer.shutdown();
                assertThat(caller.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
                assertThat(observer.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
            }
        }
    }

    @Test
    void inFlightBorrowAbortMustFinishBeforeLogicalCloseCanReturnConnection() throws Exception {
        var aborting = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var physical = mock(Connection.class);
        org.mockito.Mockito.doAnswer(ignored -> {
            aborting.countDown();
            if (!release.await(1, TimeUnit.SECONDS)) {
                throw new SQLException("Synthetic in-flight abort guard");
            }
            return null;
        }).when(physical).abort(org.mockito.ArgumentMatchers.any());
        try (var owner = new AiRuntimeJdbcDeadline(); var caller = Executors.newSingleThreadExecutor()) {
            var pooled = owner.connect(() -> physical);
            var borrowed = owner
                    .borrow(pooled, AiRuntimeOperationBudget.start(java.time.Duration.ofMillis(200)), ignored -> {
                    });
            assertThat(aborting.await(1, TimeUnit.SECONDS)).isTrue();
            var result = caller.submit(() -> org.assertj.core.api.Assertions.catchThrowable(borrowed::close));
            try {
                assertThatThrownBy(() -> result.get(150, TimeUnit.MILLISECONDS))
                        .isInstanceOf(java.util.concurrent.TimeoutException.class);
            } finally {
                release.countDown();
                caller.shutdown();
                assertThat(caller.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
            }
            assertThat(result.get()).isInstanceOf(SQLException.class);
            assertThatThrownBy(() -> owner.borrow(pooled, AiRuntimeOperationBudget.start(), ignored -> {
            })).isInstanceOf(SQLException.class);
        }
    }

    @Test
    void storedFactoryCreatesOwnedCancellationSocketAfterStartupOnAnotherThread() throws Exception {
        var factory = new AtomicReference<AiRuntimeJdbcSocketFactory>();
        var startup = new AtomicReference<Socket>();
        try (var owner = new AiRuntimeJdbcDeadline();
                var caller = Executors.newSingleThreadExecutor();
                var unrelated = new Socket()) {
            var connection = owner.connect(() -> {
                try {
                    factory.set(new AiRuntimeJdbcSocketFactory());
                    startup.set(factory.get().createSocket());
                } catch (IOException failure) {
                    throw new SQLException(failure);
                }
                return mock(Connection.class);
            });
            var cancellation = caller.submit(() -> factory.get().createSocket()).get(1, TimeUnit.SECONDS);
            assertThat(cancellation.isClosed()).isFalse();
            connection.close();
            assertThat(startup.get().isClosed()).isTrue();
            assertThat(cancellation.isClosed()).isTrue();
            assertThat(unrelated.isClosed()).isFalse();
            caller.shutdown();
            assertThat(caller.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void startupErrorClosesItsRegisteredSocketBeforePropagating() {
        var owned = new AtomicReference<Socket>();
        try (var owner = new AiRuntimeJdbcDeadline()) {
            assertThatThrownBy(() -> owner.connect(() -> {
                try {
                    owned.set(new AiRuntimeJdbcSocketFactory().createSocket());
                } catch (IOException failure) {
                    throw new SQLException(failure);
                }
                throw new AssertionError("Synthetic startup error");
            })).isInstanceOf(AssertionError.class);
            assertThat(owned.get().isClosed()).isTrue();
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"commit", "rollback", "expired"})
    void lateTransactionCompletionAbortsBeforeCallingDriver(String operation) throws Throwable {
        var physical = mock(Connection.class);
        var time = new java.util.concurrent.atomic.AtomicLong();
        var budget = AiRuntimeOperationBudget.start(java.time.Duration.ofSeconds(1), time::get);
        try (var owner = new AiRuntimeJdbcDeadline(); var connection = owner.connect(() -> physical)) {
            var invocation = mock(org.aspectj.lang.ProceedingJoinPoint.class);
            when(invocation.proceed()).thenAnswer(ignored -> {
                time.set(TimeUnit.MILLISECONDS.toNanos(operation.equals("expired") ? 1001 : 950));
                assertThatThrownBy(() -> {
                    if (operation.equals("commit")) {
                        connection.commit();
                    } else {
                        connection.rollback();
                    }
                })
                        .isInstanceOfSatisfying(SQLException.class,
                                failure -> assertThat(failure.getSQLState()).startsWith("08"));
                return null;
            });
            new AiRuntimeJdbcBudget().invoke(invocation, budget);
            verify(physical, never()).commit();
            verify(physical, never()).rollback();
            verify(physical).abort(org.mockito.ArgumentMatchers.any());
        }
    }

    @Test
    void activeRemainingBudgetShortensTheDriverOperationWatchdog() throws Throwable {
        var released = new CountDownLatch(1);
        var physical = mock(Connection.class);
        org.mockito.Mockito.doAnswer(ignored -> {
            if (!released.await(1, TimeUnit.SECONDS)) {
                throw new SQLException("Synthetic operation guard expired");
            }
            return null;
        }).when(physical).commit();
        org.mockito.Mockito.doAnswer(ignored -> {
            released.countDown();
            return null;
        }).when(physical).abort(org.mockito.ArgumentMatchers.any());
        try (var owner = new AiRuntimeJdbcDeadline(); var connection = owner.connect(() -> physical)) {
            var invocation = mock(org.aspectj.lang.ProceedingJoinPoint.class);
            when(invocation.proceed()).thenAnswer(ignored -> {
                assertThatThrownBy(connection::commit)
                        .isInstanceOfSatisfying(SQLException.class,
                                failure -> assertThat(failure.getSQLState()).startsWith("08"));
                return null;
            });
            long started = System.nanoTime();
            new AiRuntimeJdbcBudget()
                    .invoke(invocation, AiRuntimeOperationBudget.start(java.time.Duration.ofMillis(200)));
            assertThat(java.time.Duration.ofNanos(System.nanoTime() - started))
                    .isLessThan(java.time.Duration.ofMillis(200));
        }
    }

    @Test
    void shutdownDuringStartupRejectsLateSocketRegistrationAndLateConnectionReturn() throws Exception {
        var physical = mock(Connection.class);
        try (var deadlines = new AiRuntimeJdbcDeadline()) {
            assertThatThrownBy(() -> deadlines.connect(() -> {
                AiRuntimeJdbcSocketFactory factory;
                try {
                    factory = new AiRuntimeJdbcSocketFactory();
                } catch (IOException failure) {
                    throw new SQLException(failure);
                }
                deadlines.closeConnections();
                assertThatThrownBy(factory::createSocket).isInstanceOf(IOException.class);
                return physical;
            })).isInstanceOf(SQLException.class);
            verify(physical).abort(org.mockito.ArgumentMatchers.any());
        }
    }

    @Test
    void startupFailureClosesRegisteredSocketAndClearsThreadScope() {
        var owned = new AtomicReference<Socket>();
        try (var deadlines = new AiRuntimeJdbcDeadline()) {
            assertThatThrownBy(() -> deadlines.connect(() -> {
                try {
                    owned.set(new AiRuntimeJdbcSocketFactory().createSocket());
                } catch (IOException failure) {
                    throw new SQLException(failure);
                }
                throw new SQLException("Synthetic connection failure");
            })).isInstanceOf(SQLException.class);
            assertThat(owned.get().isClosed()).isTrue();
            assertThatThrownBy(AiRuntimeJdbcSocketFactory::new).isInstanceOf(IOException.class);
        }
    }

    @Test
    void successfulValidationCancelsItsWatchdogBeforeConnectionReuse() throws Exception {
        var physical = mock(Connection.class);
        when(physical.isValid(1)).thenReturn(true);
        var owned = new AtomicReference<Socket>();
        try (var deadlines = new AiRuntimeJdbcDeadline(); var observer = Executors.newSingleThreadScheduledExecutor()) {
            var connection = deadlines.connect(() -> {
                try {
                    owned.set(new AiRuntimeJdbcSocketFactory().createSocket());
                } catch (IOException failure) {
                    throw new SQLException(failure);
                }
                return physical;
            });
            for (int index = 0; index < 20; index++) {
                assertThat(connection.isValid(1)).isTrue();
            }
            var checkpoint = new CountDownLatch(1);
            observer.schedule(checkpoint::countDown, 350, TimeUnit.MILLISECONDS);
            assertThat(checkpoint.await(1, TimeUnit.SECONDS)).isTrue();
            assertThat(owned.get().isClosed()).isFalse();
            assertThat(connection.isValid(1)).isTrue();
            connection.close();
            assertThat(owned.get().isClosed()).isTrue();
            assertThatThrownBy(() -> connection.isValid(1)).isInstanceOf(SQLException.class);
            observer.shutdown();
            assertThat(observer.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void inFlightAbortPreventsSuccessfulValidationFromReturningReusableConnection() throws Exception {
        var validating = new CountDownLatch(1);
        var returnValidation = new CountDownLatch(1);
        var aborting = new CountDownLatch(1);
        var finishAbort = new CountDownLatch(1);
        var physical = mock(Connection.class);
        when(physical.isValid(1)).thenAnswer(ignored -> {
            validating.countDown();
            if (!returnValidation.await(1, TimeUnit.SECONDS)) {
                throw new SQLException("Fixture validation guard");
            }
            return true;
        });
        org.mockito.Mockito.doAnswer(ignored -> {
            aborting.countDown();
            if (!finishAbort.await(1, TimeUnit.SECONDS)) {
                throw new SQLException("Fixture abort guard");
            }
            return null;
        }).when(physical).abort(org.mockito.ArgumentMatchers.any());
        try (var deadlines = new AiRuntimeJdbcDeadline(); var caller = Executors.newSingleThreadExecutor()) {
            var connection = deadlines.connect(() -> physical);
            var result = caller
                    .submit(() -> org.assertj.core.api.Assertions.catchThrowable(() -> connection.isValid(1)));
            try {
                assertThat(validating.await(1, TimeUnit.SECONDS)).isTrue();
                assertThat(aborting.await(1, TimeUnit.SECONDS)).isTrue();
                returnValidation.countDown();
                assertThat(result.get(700, TimeUnit.MILLISECONDS)).isInstanceOf(SQLException.class);
            } finally {
                returnValidation.countDown();
                finishAbort.countDown();
                caller.shutdown();
                assertThat(caller.awaitTermination(1, TimeUnit.SECONDS)).isTrue();
            }
            assertThatThrownBy(() -> connection.isValid(1)).isInstanceOf(SQLException.class);
            var nextPhysical = mock(Connection.class);
            when(nextPhysical.isValid(1)).thenReturn(true);
            try (var next = deadlines.connect(() -> nextPhysical)) {
                assertThat(next.isValid(1)).isTrue();
            }
        }
    }

    @Test
    void closedOwnerRejectsNewAttemptsAndConnectedSocketOverloads() throws Exception {
        var deadlines = new AiRuntimeJdbcDeadline();
        var stored = new AtomicReference<AiRuntimeJdbcSocketFactory>();
        deadlines.connect(() -> {
            try {
                stored.set(new AiRuntimeJdbcSocketFactory());
            } catch (IOException failure) {
                throw new SQLException(failure);
            }
            return mock(Connection.class);
        });
        deadlines.close();
        assertThatThrownBy(() -> deadlines.connect(() -> mock(Connection.class))).isInstanceOf(SQLException.class);
        var factory = stored.get();
        var loopback = InetAddress.getByName("127.0.0.1");
        assertThatThrownBy(() -> factory.createSocket("127.0.0.1", 1)).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> factory.createSocket("127.0.0.1", 1, loopback, 0)).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> factory.createSocket(loopback, 1)).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> factory.createSocket(loopback, 1, loopback, 0)).isInstanceOf(IOException.class);
    }
}
