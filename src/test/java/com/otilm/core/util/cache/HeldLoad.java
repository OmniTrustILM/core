package com.otilm.core.util.cache;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A load held open on a thread of its own until the test releases it. It serves tests of what an eviction during a load
 * leaves in a cache.
 */
public final class HeldLoad {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final CountDownLatch started;
    private final CountDownLatch released = new CountDownLatch(1);

    public HeldLoad() {
        this(1);
    }

    /** Holds {@code loads} loads, which one release lets finish together. */
    public HeldLoad(int loads) {
        started = new CountDownLatch(loads);
    }

    /** The load, reporting its start and then waiting for the release. */
    public <T> Supplier<T> holding(Supplier<T> load) {
        return () -> {
            started.countDown();
            await(released, "held load released");
            return load.get();
        };
    }

    /** Runs the call on a thread of its own, returning once the call's held load has started. */
    public <T> CompletableFuture<T> start(Supplier<T> call) {
        CompletableFuture<T> result = CompletableFuture
                .supplyAsync(call, runnable -> Thread.ofPlatform().daemon().start(runnable));
        awaitStarted();
        return result;
    }

    /** Waits until every held load has started. */
    public void awaitStarted() {
        await(started, "held loads started");
    }

    /** Lets the held loads finish, returning the result of the given call. */
    public <T> T release(CompletableFuture<T> call) {
        released.countDown();
        return call.orTimeout(TIMEOUT.toSeconds(), TimeUnit.SECONDS).join();
    }

    private static void await(CountDownLatch latch, String description) {
        try {
            assertThat(latch.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS)).as(description).isTrue();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(description, e);
        }
    }
}
