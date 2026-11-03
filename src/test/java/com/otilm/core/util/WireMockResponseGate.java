package com.otilm.core.util;

import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ServeEventListener;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Holds the connector's answer until the test releases it, so a competing write provably commits while the operation
 * waits on the connector. Register it with {@code LoopbackWireMock.options().extensions(gate)}.
 */
public final class WireMockResponseGate implements ServeEventListener {

    private volatile CountDownLatch release;

    public CountDownLatch hold() {
        release = new CountDownLatch(1);
        return release;
    }

    @Override
    public void beforeResponseSent(ServeEvent serveEvent, Parameters parameters) {
        CountDownLatch gate = release;
        if (gate == null) {
            return;
        }
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
