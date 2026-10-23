package com.otilm.core.util;

import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.awaitility.Awaitility;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Races a call against a transaction holding a lock the call needs, for tests of what the call sees once the lock
 * holder commits.
 */
@Component
public class LockContention {

    private static final Duration BLOCKING_TIMEOUT = Duration.ofSeconds(10);
    private static final String SESSIONS_BLOCKED_BY = "SELECT count(*) FROM pg_stat_activity "
            + "WHERE ? = ANY(pg_blocking_pids(pid))";

    private final JdbcTemplate jdbcTemplate;
    private final PlatformTransactionManager transactionManager;

    public LockContention(JdbcTemplate jdbcTemplate, PlatformTransactionManager transactionManager) {
        this.jdbcTemplate = jdbcTemplate;
        this.transactionManager = transactionManager;
    }

    /**
     * Takes the lock in a transaction, starts the call on another thread and commits once the call waits for the lock.
     *
     * @param takeLock statements that lock what the call needs, run through {@link JdbcTemplate}
     * @param call the call that must wait for the lock
     * @return the call, which goes on once the lock holder has committed
     */
    public <T> Future<T> callBlockedBy(Runnable takeLock, Callable<T> call) {
        ExecutorService caller = Executors.newSingleThreadExecutor();
        try {
            return new TransactionTemplate(transactionManager).execute(status -> {
                takeLock.run();
                int lockHolderPid = jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class);
                Future<T> blocked = caller.submit(call);
                Awaitility
                        .await()
                        .atMost(BLOCKING_TIMEOUT)
                        .until(() -> jdbcTemplate.queryForObject(SESSIONS_BLOCKED_BY, Long.class, lockHolderPid) > 0);
                return blocked;
            });
        } finally {
            caller.shutdown();
        }
    }

    /** Races a call without a result, as {@link #callBlockedBy} races one with a result. */
    public Future<?> runBlockedBy(Runnable takeLock, Runnable run) {
        return callBlockedBy(takeLock, Executors.callable(run));
    }
}
