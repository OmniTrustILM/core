package com.otilm.core.util;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Makes the same call from several threads at the same moment, for tests of what the calls do to each other. The
 * threads act as the caller of the test.
 */
public final class ConcurrentCalls {

    private static final long TIMEOUT_SECONDS = 60;

    private ConcurrentCalls() {
    }

    /**
     * Starts the call on {@code threads} threads at once and waits for all of them.
     *
     * @return the results of the calls, in no particular order
     * @throws ExecutionException when a call threw: the failure stays with the test
     */
    public static <T> List<T> callTogether(int threads, Callable<T> call)
            throws InterruptedException, ExecutionException, TimeoutException {
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        try {
            Authentication caller = SecurityContextHolder.getContext().getAuthentication();
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch go = new CountDownLatch(1);
            List<Future<T>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(executor.submit(asCaller(caller, () -> {
                    ready.countDown();
                    go.await();
                    return call.call();
                })));
            }
            if (!ready.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new TimeoutException("the threads did not start");
            }
            go.countDown();
            List<T> results = new ArrayList<>();
            for (Future<T> future : futures) {
                results.add(future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * Starts the call on a thread of its own, for a test that acts while the call is under way.
     *
     * @return the call, whose result the test gets once it has done its part
     */
    public static <T> Future<T> callInBackground(Callable<T> call) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            return executor.submit(asCaller(SecurityContextHolder.getContext().getAuthentication(), call));
        } finally {
            executor.shutdown();
        }
    }

    /** Runs the call with a security context of its own that carries the caller's authentication. */
    private static <T> Callable<T> asCaller(Authentication caller, Callable<T> call) {
        return () -> {
            SecurityContext own = SecurityContextHolder.createEmptyContext();
            own.setAuthentication(caller);
            SecurityContextHolder.setContext(own);
            try {
                return call.call();
            } finally {
                SecurityContextHolder.clearContext();
            }
        };
    }
}
