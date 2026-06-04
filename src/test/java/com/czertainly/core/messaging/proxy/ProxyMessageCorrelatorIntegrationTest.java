package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.model.ConnectorResponse;
import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

/**
 * Integration tests for {@link ProxyMessageCorrelator}.
 * Tests real timeout behavior, threading, and capacity enforcement with Spring context.
 */
class ProxyMessageCorrelatorIntegrationTest extends BaseSpringBootTest {

    @Autowired
    private ProxyProperties proxyProperties;

    private ProxyMessageCorrelator correlator;

    @BeforeEach
    void setUpCorrelator() {
        // Create a fresh correlator for each test with shorter timeout for testing
        ProxyProperties testProps = new ProxyProperties(
                proxyProperties.exchange(),
                proxyProperties.responseQueue(),
                proxyProperties.instanceId(),
                Duration.ofMillis(500), // Short timeout for testing
                100, // Low capacity for testing
                null
        );
        correlator = new ProxyMessageCorrelator(testProps);
    }

    @AfterEach
    void tearDownCorrelator() {
        if (correlator != null) {
            correlator.shutdown();
        }
    }

    // ==================== End-to-End Tests ====================

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void registerAndComplete_endToEnd() throws Exception {
        String correlationId = "int-test-corr-1";

        CompletableFuture<ProxyMessage> future = correlator.registerRequest(correlationId, Duration.ofSeconds(5));
        assertThat(future.isDone()).isFalse();
        assertThat(correlator.getPendingCount()).isEqualTo(1);

        ProxyMessage message = createMessage(correlationId, 200, "success");

        correlator.completeRequest(message);

        assertThat(future.isDone()).isTrue();
        assertThat(correlator.getPendingCount()).isZero();

        ProxyMessage result = future.get();
        assertThat(result.getCorrelationId()).isEqualTo(correlationId);
        assertThat(result.getConnectorResponse().getStatusCode()).isEqualTo(200);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    @DisplayName("Timeout triggers after configured duration with retryable error response")
    void timeout_triggersAfterConfiguredDuration() throws Exception {
        String correlationId = "int-test-timeout";

        // Use short timeout
        CompletableFuture<ProxyMessage> future = correlator.registerRequest(correlationId, Duration.ofMillis(200));

        // Wait for timeout using Awaitility
        await().atMost(Duration.ofSeconds(2)).until(future::isDone);

        ProxyMessage message = future.get();
        assertThat(message).isNotNull();
        assertThat(message.getCorrelationId()).isEqualTo(correlationId);
        assertThat(message.getConnectorResponse().getStatusCode()).isZero();
        assertThat(message.getConnectorResponse().getErrorCategory()).isEqualTo("timeout");
        assertThat(message.getConnectorResponse().isRetryable()).isTrue();
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    @DisplayName("Shutdown gracefully completes all pending requests with non-retryable error")
    void shutdown_gracefullyHandlesPendingRequests() throws Exception {
        List<CompletableFuture<ProxyMessage>> futures = new ArrayList<>();

        // Register several requests
        for (int i = 0; i < 5; i++) {
            futures.add(correlator.registerRequest("shutdown-test-" + i, Duration.ofSeconds(30)));
        }

        assertThat(correlator.getPendingCount()).isEqualTo(5);

        // Shutdown
        correlator.shutdown();

        // All futures should be completed with shutdown error
        for (CompletableFuture<ProxyMessage> future : futures) {
            assertThat(future.isDone()).isTrue();
            ProxyMessage message = future.get();
            assertThat(message.getConnectorResponse().getErrorCategory()).isEqualTo("connection");
            assertThat(message.getConnectorResponse().isRetryable()).isFalse();
        }

        assertThat(correlator.getPendingCount()).isZero();
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    @DisplayName("Concurrent operations from multiple threads are thread-safe")
    void concurrentOperations_areThreadSafe() throws Exception {
        int numThreads = 10;
        int requestsPerThread = 20;
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(numThreads);
        CopyOnWriteArrayList<CompletableFuture<ProxyMessage>> allFutures = new CopyOnWriteArrayList<>();
        CopyOnWriteArrayList<String> allCorrelationIds = new CopyOnWriteArrayList<>();

        // Launch threads that register and complete requests
        for (int t = 0; t < numThreads; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int i = 0; i < requestsPerThread; i++) {
                        String correlationId = "thread-" + threadId + "-req-" + i;
                        allCorrelationIds.add(correlationId);

                        CompletableFuture<ProxyMessage> future = correlator.registerRequest(
                                correlationId, Duration.ofSeconds(10));
                        allFutures.add(future);

                        // Complete half immediately
                        if (i % 2 == 0) {
                            correlator.completeRequest(createMessage(correlationId, 200, null));
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        // Start all threads at once
        startLatch.countDown();
        doneLatch.await();
        executor.shutdown();

        // Verify no exceptions occurred
        assertThat(allFutures).hasSize(numThreads * requestsPerThread);

        // Complete remaining requests
        for (String correlationId : allCorrelationIds) {
            correlator.completeRequest(createMessage(correlationId, 200, null));
        }

        // All futures should be completed
        assertThat(allFutures).allMatch(CompletableFuture::isDone);
    }

    @Test
    @DisplayName("Capacity limit enforced - registration fails when at maximum capacity")
    void capacityLimit_enforcedCorrectly() {
        // Fill to capacity (100 set in setUp)
        for (int i = 0; i < 100; i++) {
            correlator.registerRequest("capacity-" + i, Duration.ofSeconds(30));
        }

        assertThat(correlator.getPendingCount()).isEqualTo(100);

        // Next registration should fail
        assertThatThrownBy(() -> correlator.registerRequest("overflow", Duration.ofSeconds(30)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void tryCompleteRequest_worksCorrectly() {
        String correlationId = "try-complete-test";
        CompletableFuture<ProxyMessage> future = correlator.registerRequest(correlationId, Duration.ofSeconds(5));

        // Try with wrong ID
        boolean wrongResult = correlator.tryCompleteRequest(createMessage("wrong-id", 200, null));
        assertThat(wrongResult).isFalse();
        assertThat(future.isDone()).isFalse();

        // Try with correct ID
        boolean correctResult = correlator.tryCompleteRequest(createMessage(correlationId, 200, null));
        assertThat(correctResult).isTrue();
        assertThat(future.isDone()).isTrue();
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void cancelRequest_worksCorrectly() {
        String correlationId = "cancel-test";
        CompletableFuture<ProxyMessage> future = correlator.registerRequest(correlationId, Duration.ofSeconds(5));

        assertThat(correlator.getPendingCount()).isEqualTo(1);

        boolean cancelled = correlator.cancelRequest(correlationId);
        assertThat(cancelled).isTrue();
        assertThat(future.isCancelled()).isTrue();
        assertThat(correlator.getPendingCount()).isZero();

        // Second cancel should return false
        assertThat(correlator.cancelRequest(correlationId)).isFalse();
    }

    // ==================== Helper Methods ====================

    private ProxyMessage createMessage(String correlationId, int statusCode, Object body) {
        return ProxyMessage.builder()
                .correlationId(correlationId)
                .proxyId("test-proxy")
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(statusCode)
                        .body(body)
                        .build())
                .build();
    }
}
