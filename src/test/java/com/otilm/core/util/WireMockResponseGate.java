package com.otilm.core.util;

import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ServeEventListener;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Holds the connector's answer until the test releases it, so a competing write provably commits while the operation
 * waits on the connector. Register it with {@code LoopbackWireMock.options().extensions(gate)}.
 */
public final class WireMockResponseGate implements ServeEventListener {

    private volatile CountDownLatch release;
    private final Semaphore held = new Semaphore(0);

    public CountDownLatch hold() {
        held.drainPermits();
        release = new CountDownLatch(1);
        return release;
    }

    /** Waits until a response has taken the gate in place, so a later {@link #hold()} no longer releases it. */
    public void awaitHeld() throws InterruptedException {
        if (!held.tryAcquire(10, TimeUnit.SECONDS)) {
            throw new IllegalStateException("No response reached the gate");
        }
    }

    @Override
    public void beforeResponseSent(ServeEvent serveEvent, Parameters parameters) {
        CountDownLatch gate = release;
        if (gate == null) {
            return;
        }
        held.release();
        try {
            gate.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public String getName() {
        return "responseGate";
    }
}
