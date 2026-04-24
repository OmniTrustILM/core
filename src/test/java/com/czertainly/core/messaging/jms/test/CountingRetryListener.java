package com.czertainly.core.messaging.jms.test;

import org.springframework.retry.RetryCallback;
import org.springframework.retry.RetryContext;
import org.springframework.retry.RetryListener;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Test-specific RetryListener that provides deterministic observation of retry behavior.
 *
 * <p>This listener is designed for testing and does NOT extend JmsRetryListener to avoid
 * unnecessary logging noise in test output.</p>
 *
 * <p>Design principles:</p>
 * <ul>
 *   <li>Uses AtomicInteger for thread-safe retry counting</li>
 *   <li>Uses CountDownLatch for synchronization with test code</li>
 *   <li>Captures last exception for assertion purposes</li>
 *   <li>Supports reset between test methods</li>
 * </ul>
 */
public class CountingRetryListener implements RetryListener {

    private final AtomicInteger errorCount = new AtomicInteger(0);
    private final AtomicBoolean openCalled = new AtomicBoolean(false);
    private final AtomicBoolean completedSuccessfully = new AtomicBoolean(false);
    private final AtomicReference<Throwable> lastException = new AtomicReference<>();
    private volatile CountDownLatch retryLatch;
    private volatile CountDownLatch completionLatch;

    /**
     * Configure latch to wait for specific number of retry errors.
     * Call this BEFORE the operation that triggers retries.
     */
    public void expectRetryErrors(int expectedErrors) {
        this.retryLatch = new CountDownLatch(expectedErrors);
    }

    /**
     * Configure latch to wait for operation completion (success or final failure).
     */
    public void expectCompletion() {
        this.completionLatch = new CountDownLatch(1);
    }

    @Override
    public <T, E extends Throwable> boolean open(RetryContext context, RetryCallback<T, E> callback) {
        openCalled.set(true);
        return true;
    }

    @Override
    public <T, E extends Throwable> void onError(RetryContext context, RetryCallback<T, E> callback, Throwable throwable) {
        errorCount.incrementAndGet();
        lastException.set(throwable);

        if (retryLatch != null) {
            retryLatch.countDown();
        }
    }

    @Override
    public <T, E extends Throwable> void close(RetryContext context, RetryCallback<T, E> callback, Throwable throwable) {
        // Track whether the operation completed successfully (no exception on final attempt)
        completedSuccessfully.set(throwable == null);

        if (completionLatch != null) {
            completionLatch.countDown();
        }
    }

    // ========== Synchronization Methods ==========

    /**
     * Block until the expected number of retry errors have occurred.
     * Use this to synchronize proxy restoration with retry attempts.
     */
    public boolean awaitRetryErrors(long timeout, TimeUnit unit) throws InterruptedException {
        if (retryLatch == null) {
            throw new IllegalStateException("Call expectRetryErrors() before awaiting");
        }
        return retryLatch.await(timeout, unit);
    }

    /**
     * Block until the operation completes (success or final failure).
     */
    public boolean awaitCompletion(long timeout, TimeUnit unit) throws InterruptedException {
        if (completionLatch == null) {
            throw new IllegalStateException("Call expectCompletion() before awaiting");
        }
        return completionLatch.await(timeout, unit);
    }

    // ========== Assertion Helper Methods ==========

    public boolean isOpenCalled() {
        return openCalled.get();
    }

    public int getAttemptsCount() {
        // If retry operation wasn't started, return 0
        if (!openCalled.get()) {
            return 0;
        }

        // If no errors occurred, operation succeeded on first attempt
        if (errorCount.get() == 0) {
            return 1;
        }

        // If errors occurred and operation eventually succeeded:
        // attempts = failed attempts + 1 successful final attempt
        if (completedSuccessfully.get()) {
            return errorCount.get() + 1;
        }

        // If all attempts failed: attempts = number of errors
        // (each error represents a failed attempt)
        return errorCount.get();
    }

    public int getErrorCount() {
        return errorCount.get();
    }

    public Throwable getLastException() {
        return lastException.get();
    }

    /**
     * Reset all counters and latches. Call in @BeforeEach.
     */
    public void reset() {
        openCalled.set(false);
        completedSuccessfully.set(false);
        errorCount.set(0);
        lastException.set(null);
        retryLatch = null;
        completionLatch = null;
    }
}