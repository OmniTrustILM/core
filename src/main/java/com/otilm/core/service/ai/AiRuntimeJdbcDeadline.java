package com.otilm.core.service.ai;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.Socket;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/** Owns finite startup and physical-connection validation cancellation. */
final class AiRuntimeJdbcDeadline implements AutoCloseable {
    static final long VALIDATION_MILLIS = 250;
    static final long CLEANUP_MILLIS = 100;
    private static final ThreadLocal<Attempt> CONNECTING = new ThreadLocal<>();
    private static final ThreadLocal<AiRuntimeOperationBudget> BORROWING = new ThreadLocal<>();
    private final Set<Attempt> attempts = ConcurrentHashMap.newKeySet();
    private final ScheduledThreadPoolExecutor clock = new ScheduledThreadPoolExecutor(2);
    private volatile boolean closed;

    AiRuntimeJdbcDeadline() {
        clock.setRemoveOnCancelPolicy(true);
        clock.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
    }

    static Attempt connecting() throws IOException {
        var attempt = CONNECTING.get();
        if (attempt == null) {
            throw new IOException("AI JDBC connection attempt is unavailable");
        }
        return attempt;
    }

    Connection connect(SqlConnection operation) throws SQLException {
        var attempt = open();
        CONNECTING.set(attempt);
        try (var lease = attempt.lease(Duration.ofSeconds(5))) {
            var connection = operation.get();
            attempt.physical = connection;
            lease.finish();
            attempt.requireOpen();
            return (Connection) Proxy
                    .newProxyInstance(AiRuntimeJdbcDeadline.class.getClassLoader(),
                            new Class<?>[]{Connection.class, OwnedConnection.class},
                            (proxy, method, arguments) -> invokeOwned(attempt, connection, proxy, method, arguments));
        } catch (RuntimeException | SQLException | Error failure) {
            attempt.close();
            throw failure;
        } finally {
            CONNECTING.remove();
        }
    }

    private Object invokeOwned(Attempt attempt, Connection connection, Object proxy, Method method, Object[] arguments)
            throws Throwable {
        if (method.getDeclaringClass() == OwnedConnection.class) {
            var budget = (AiRuntimeOperationBudget) arguments[0];
            long limit = budget.remaining().toNanos() - TimeUnit.MILLISECONDS.toNanos(CLEANUP_MILLIS);
            if (limit <= 0) {
                attempt.close();
                throw unavailable();
            }
            return attempt.borrowLease(Duration.ofNanos(limit), budget);
        }
        if (method.getName().equals("unwrap") && ((Class<?>) arguments[0]).isInstance(proxy)) {
            return proxy;
        }
        if (method.getName().equals("isWrapperFor") && ((Class<?>) arguments[0]).isInstance(proxy)) {
            return true;
        }
        if (method.getName().equals("close")) {
            attempt.close();
            return null;
        }
        return invokePhysical(attempt, connection, method, arguments);
    }

    private Object invokePhysical(Attempt attempt, Connection connection, Method method, Object[] arguments)
            throws Throwable {
        boolean bounded = switch (method.getName()) {
            case "isValid", "getTransactionIsolation", "setTransactionIsolation", "setSchema", "setCatalog",
                    "setReadOnly", "setAutoCommit", "commit", "rollback", "clearWarnings" ->
                true;
            default -> false;
        };
        try (var call = bounded ? attempt.operationLease() : null) {
            Object result = invokeDriver(connection, method, arguments);
            if (call != null) {
                call.finish();
                attempt.requireOpen();
                attempt.checkBudget();
            }
            return result;
        } catch (Error failure) {
            attempt.close();
            throw failure;
        }
    }

    private static Object invokeDriver(Connection connection, Method method, Object[] arguments) throws Throwable {
        try {
            return method.invoke(connection, arguments);
        } catch (InvocationTargetException failure) {
            throw failure.getCause();
        }
    }

    Connection borrow(Connection pooled, AiRuntimeOperationBudget budget, Consumer<Connection> evict)
            throws SQLException {
        var lease = pooled.unwrap(OwnedConnection.class).openBorrow(budget);
        var returned = new AtomicBoolean();
        try {
            return (Connection) Proxy
                    .newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
                            (proxy, method, arguments) -> {
                                var previous = BORROWING.get();
                                BORROWING.set(budget);
                                try {
                                    if (method.getName().equals("close")) {
                                        if (returned.compareAndSet(false, true)) {
                                            closeBorrowed(pooled, lease, evict);
                                        }
                                        return null;
                                    }
                                    try {
                                        return method.invoke(pooled, arguments);
                                    } catch (InvocationTargetException failure) {
                                        throw failure.getCause();
                                    }
                                } finally {
                                    if (previous == null) {
                                        BORROWING.remove();
                                    } else {
                                        BORROWING.set(previous);
                                    }
                                }
                            });
        } catch (RuntimeException | Error failure) {
            try {
                lease.close();
            } catch (SQLException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw failure;
        }
    }

    private static void closeBorrowed(Connection pooled, Lease lease, Consumer<Connection> evict) throws SQLException {
        Throwable failure = null;
        try {
            pooled.close();
        } catch (SQLException | RuntimeException | Error problem) {
            failure = problem;
            evictAfterFailure(pooled, evict, failure);
        }
        try {
            lease.finish();
        } catch (SQLException | RuntimeException | Error problem) {
            if (failure == null) {
                failure = problem;
            } else {
                failure.addSuppressed(problem);
            }
            evictAfterFailure(pooled, evict, failure);
        }
        if (failure instanceof SQLException sql) {
            throw sql;
        }
        if (failure instanceof RuntimeException runtime) {
            throw runtime;
        }
        if (failure instanceof Error error) {
            throw error;
        }
    }

    private static void evictAfterFailure(Connection connection, Consumer<Connection> evict, Throwable failure) {
        try {
            evict.accept(connection);
        } catch (RuntimeException | Error problem) {
            failure.addSuppressed(problem);
        }
    }

    interface OwnedConnection {
        Lease openBorrow(AiRuntimeOperationBudget budget) throws SQLException;
    }

    private synchronized Attempt open() throws SQLException {
        if (closed) {
            throw unavailable();
        }
        var attempt = new Attempt();
        attempts.add(attempt);
        return attempt;
    }

    synchronized void closeConnections() {
        closed = true;
        attempts.forEach(Attempt::close);
        if (!attempts.isEmpty()) {
            throw new IllegalStateException("AI JDBC socket cleanup unavailable");
        }
    }

    @Override
    public void close() {
        try {
            closeConnections();
        } catch (RuntimeException | Error failure) {
            shutdownAfterFailure(failure);
            throw failure;
        }
        shutdownClock();
    }

    private void shutdownAfterFailure(Throwable failure) {
        try {
            shutdownClock();
        } catch (RuntimeException | Error cleanup) {
            failure.addSuppressed(cleanup);
        }
    }

    private void shutdownClock() {
        clock.shutdown();
        try {
            if (!clock.awaitTermination(1, TimeUnit.SECONDS)) {
                throw new IllegalStateException("AI JDBC deadline workers did not terminate");
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("AI JDBC deadline shutdown interrupted");
        }
    }

    private static SQLException unavailable() {
        return new SQLNonTransientConnectionException("AI JDBC connection unavailable", "08006");
    }

    @FunctionalInterface
    interface SqlConnection {
        Connection get() throws SQLException;
    }

    final class Attempt {
        private final Set<Socket> sockets = new HashSet<>();
        private volatile Connection physical;
        private boolean terminated;
        private volatile boolean socketCleanupFailed;
        private Lease borrowing;

        synchronized void register(Socket socket) throws IOException {
            if (terminated) {
                socket.close();
                throw new IOException("AI JDBC attempt expired");
            }
            sockets.removeIf(Socket::isClosed);
            sockets.add(socket);
        }

        synchronized Lease lease(Duration duration) throws SQLException {
            requireOpen();
            return new Lease(this, duration, null);
        }

        Lease borrowLease(Duration duration, AiRuntimeOperationBudget budget) throws SQLException {
            Lease previous;
            synchronized (this) {
                requireOpen();
                previous = borrowing;
                if (previous == null || previous.disarmForReuse()) {
                    borrowing = new Lease(this, duration, budget);
                    return borrowing;
                }
            }
            previous.expire();
            previous.finish();
            throw unavailable();
        }

        void closeBorrow(Lease expected) {
            synchronized (this) {
                if (borrowing != expected) {
                    return;
                }
                terminated = true;
            }
            close();
        }

        Lease operationLease() throws SQLException {
            long limit = TimeUnit.MILLISECONDS.toNanos(VALIDATION_MILLIS);
            var budget = BORROWING.get() == null ? AiRuntimeJdbcBudget.current() : BORROWING.get();
            if (budget != null) {
                try {
                    limit = Math
                            .min(limit, budget.remaining().toNanos() - TimeUnit.MILLISECONDS.toNanos(CLEANUP_MILLIS));
                } catch (AiRuntimeOperationBudget.Unavailable failure) {
                    close();
                    throw unavailable();
                }
                if (limit <= 0) {
                    close();
                    throw unavailable();
                }
            }
            return lease(Duration.ofNanos(limit));
        }

        void checkBudget() throws SQLException {
            var budget = BORROWING.get() == null ? AiRuntimeJdbcBudget.current() : BORROWING.get();
            if (budget != null) {
                try {
                    budget.remaining();
                } catch (AiRuntimeOperationBudget.Unavailable failure) {
                    close();
                    throw unavailable();
                }
            }
        }

        synchronized void requireOpen() throws SQLException {
            if (terminated || closed) {
                throw unavailable();
            }
        }

        void close() {
            synchronized (this) {
                terminated = true;
            }
            for (var socket : sockets) {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    socketCleanupFailed = true;
                }
            }
            if (physical != null) {
                try {
                    physical.abort(Runnable::run);
                } catch (SQLException ignored) {
                    // The independently owned socket handles have already been closed.
                }
                try {
                    physical.close();
                } catch (SQLException ignored) {
                    socketCleanupFailed = true;
                }
            }
            if (!socketCleanupFailed) {
                attempts.remove(this);
            }
        }
    }

    final class Lease implements AutoCloseable {
        private final Attempt attempt;
        private final ScheduledFuture<?> timer;
        private final CountDownLatch done = new CountDownLatch(1);
        private boolean armed = true;
        private boolean expired;
        private boolean finished;
        private final AiRuntimeOperationBudget budget;

        Lease(Attempt attempt, Duration duration, AiRuntimeOperationBudget budget) {
            this.attempt = attempt;
            this.budget = budget;
            timer = clock.schedule(this::expire, duration.toNanos(), TimeUnit.NANOSECONDS);
        }

        private void expire() {
            synchronized (this) {
                if (!armed) {
                    return;
                }
                armed = false;
                expired = true;
            }
            try {
                if (budget == null) {
                    attempt.close();
                } else {
                    attempt.closeBorrow(this);
                }
            } finally {
                done.countDown();
            }
        }

        void finish() throws SQLException {
            synchronized (this) {
                if (finished) {
                    return;
                }
            }
            if (budget != null) {
                try {
                    budget.remaining();
                } catch (AiRuntimeOperationBudget.Unavailable failure) {
                    synchronized (this) {
                        if (finished) {
                            return;
                        }
                    }
                    attempt.closeBorrow(this);
                    close();
                    throw unavailable();
                }
            }
            close();
            synchronized (this) {
                if (expired) {
                    throw unavailable();
                }
                finished = true;
            }
        }

        synchronized boolean disarmForReuse() {
            if (expired) {
                return false;
            }
            if (!finished && budget != null) {
                try {
                    budget.remaining();
                } catch (AiRuntimeOperationBudget.Unavailable failure) {
                    return false;
                }
            }
            armed = false;
            finished = true;
            timer.cancel(false);
            return true;
        }

        @Override
        public void close() throws SQLException {
            boolean wait;
            synchronized (this) {
                armed = false;
                wait = expired;
            }
            timer.cancel(false);
            if (wait) {
                try {
                    if (!done.await(CLEANUP_MILLIS, TimeUnit.MILLISECONDS)) {
                        throw unavailable();
                    }
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                    throw unavailable();
                }
            }
        }
    }
}
