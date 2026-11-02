package com.otilm.core.util.cache;

import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.awaitility.Awaitility;

import static org.assertj.core.api.Assertions.assertThat;

/** A cache call running on a thread of its own. The test can then see it parked on another caller's load. */
public record Caller<T>(Thread thread, CompletableFuture<T> result) {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    public static <T> Caller<T> start(Callable<T> call) {
        CompletableFuture<T> result = new CompletableFuture<>();
        Thread thread = Thread.ofPlatform().daemon().start(() -> {
            try {
                result.complete(call.call());
            } catch (Throwable t) {
                result.completeExceptionally(t);
            }
        });
        return new Caller<>(thread, result);
    }

    /** Waits until the caller is parked, joined on another caller's load. */
    public void awaitParked() {
        Awaitility
                .await("caller parked")
                .atMost(TIMEOUT)
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(1))
                .until(this::parked);
    }

    private boolean parked() {
        assertThat(result).as("caller still running").isNotDone();
        return thread.getState() == Thread.State.WAITING;
    }

    public T value() throws Exception {
        return result.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    }
}
