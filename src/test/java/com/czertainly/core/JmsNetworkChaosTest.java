package com.czertainly.core;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.core.messaging.jms.configuration.MessagingProperties;
import com.czertainly.core.messaging.jms.test.CountingRetryListener;
import com.czertainly.core.messaging.model.EventMessage;
import eu.rekawek.toxiproxy.model.ToxicDirection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.JmsException;
import org.springframework.retry.support.RetryTemplate;

import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Deterministic chaos engineering tests for JMS messaging resilience.

 * Key design principles:
 * 1. DETERMINISTIC: Uses CountingRetryListener to observe actual retry behavior
 * 2. NO RACE CONDITIONS: Toxics set BEFORE operations; synchronization via CountDownLatch
 * 3. RETRY COUNT ASSERTIONS: Verify number of retries, not timing
 * 4. CLEAR SEPARATION: Each test has a single responsibility
 */
public class JmsNetworkChaosTest extends JmsResilienceTests {

    @Autowired
    private MessagingProperties messagingProperties;

    @Autowired
    private RetryTemplate producerRetryTemplate;

    private CountingRetryListener countingRetryListener;
    private int maxAttempts;

    @BeforeEach
    void setUp() {
        maxAttempts = messagingProperties.producer().retry().maxAttempts();

        // Register listener once, reset on each test
        if (countingRetryListener == null) {
            countingRetryListener = new CountingRetryListener();
            producerRetryTemplate.registerListener(countingRetryListener);
        }
        countingRetryListener.reset();
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    void testConnectionIsUp_shouldSucceedWithoutRetry() throws Exception {
        // Given: Proxy is enabled (healthy connection)
        countingRetryListener.expectCompletion();

        // When: Send message
        eventProducer.produceMessage(createTestEventMessage());

        // Wait for completion
        assertTrue(countingRetryListener.awaitCompletion(5, TimeUnit.SECONDS), "Operation should complete within timeout");

        // Then: Should succeed on first attempt with no retries
        assertEquals(1, countingRetryListener.getAttemptsCount(), "Should succeed on first attempt");
        assertEquals(0, countingRetryListener.getErrorCount(), "Should have no retry errors");
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    void testConnectionDown_shouldExhaustRetriesAndFail() throws Exception {
        // Given: Connection is down
        proxy.disable();
        logger.info("Connection DOWN - expecting {} retry attempts", maxAttempts);

        countingRetryListener.expectCompletion();

        // When: Send message
        assertThrows(JmsException.class, () ->
            eventProducer.produceMessage(createTestEventMessage()), "Should throw JmsException after exhausting retries");

        // Wait for retry completion
        assertTrue(countingRetryListener.awaitCompletion(10, TimeUnit.SECONDS), "Retries should complete within timeout");

        // Then: Should have attempted maxAttempts times
        assertEquals(maxAttempts, countingRetryListener.getAttemptsCount(), "Should have attempted exactly maxAttempts times");
        assertEquals(maxAttempts, countingRetryListener.getErrorCount(), "All attempts should have failed");
        assertNotNull(countingRetryListener.getLastException(), "Should have captured the last exception");

        logger.info("Retry exhausted after {} attempts as expected", countingRetryListener.getAttemptsCount());
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    void testConnectionRestoredMidRetry_shouldEventuallySucceed() throws Exception {
        // Given: Connection starts down
        proxy.disable();
        logger.info("Connection DOWN initially");

        // Configure listener to notify after first retry error
        int retriesBeforeRestore = 1;
        countingRetryListener.expectRetryErrors(retriesBeforeRestore);
        countingRetryListener.expectCompletion();

        // Start send operation in background
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Void> sendFuture = executor.submit(() -> {
            eventProducer.produceMessage(createTestEventMessage());
            return null;
        });

        try {
            // Wait for first retry error to occur (DETERMINISTIC synchronization)
            boolean retryOccurred = countingRetryListener.awaitRetryErrors(5, TimeUnit.SECONDS);
            assertTrue(retryOccurred, "Should have experienced at least one retry error");

            // Restore connection AFTER first retry error (no race condition)
            proxy.enable();
            logger.info("Connection RESTORED after {} retry error(s)", retriesBeforeRestore);

            // Wait for completion (should succeed now)
            sendFuture.get(10, TimeUnit.SECONDS);

            // Then: Message should eventually succeed
            assertTrue(countingRetryListener.getAttemptsCount() > 1, "Should have retried at least once");
            assertTrue(countingRetryListener.getAttemptsCount() <= maxAttempts, "Should not exceed maxAttempts");
            assertTrue(countingRetryListener.getErrorCount() >= retriesBeforeRestore,
                    "Should have at least " + retriesBeforeRestore + " error(s)");

            logger.info("Message succeeded after {} attempts ({} errors)",
                    countingRetryListener.getAttemptsCount(),
                    countingRetryListener.getErrorCount());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    void testRecoveryAfterFailure_subsequentMessageSucceeds() throws Exception {
        // Given: First message fails due to connection outage
        proxy.disable();
        countingRetryListener.expectCompletion();

        assertThrows(JmsException.class, () -> eventProducer.produceMessage(createTestEventMessage()));

        assertTrue(countingRetryListener.awaitCompletion(10, TimeUnit.SECONDS), "First message retries should complete");

        int firstAttemptCount = countingRetryListener.getAttemptsCount();
        logger.info("First message failed after {} attempts", firstAttemptCount);

        // Reset counter for second message
        countingRetryListener.reset();

        // When: Connection restored and second message sent
        proxy.enable();
        logger.info("Connection RESTORED");

        countingRetryListener.expectCompletion();

        // Then: Second message should succeed immediately
        assertDoesNotThrow(() -> eventProducer.produceMessage(createTestEventMessage()));

        assertTrue(countingRetryListener.awaitCompletion(5, TimeUnit.SECONDS), "Second message should complete");

        assertEquals(1, countingRetryListener.getAttemptsCount(), "Second message should succeed on first attempt");
        assertEquals(0, countingRetryListener.getErrorCount(), "Second message should have no errors");

        logger.info("Second message succeeded on first attempt");
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testHighLatency_shouldSucceedWithPossibleRetries() throws Exception {
        // Given: High latency (500ms +/- 100ms jitter)
        int latencyMs = 500;
        int jitterMs = 100;
        proxy.toxics().latency("latency-toxic", ToxicDirection.UPSTREAM, latencyMs).setJitter(jitterMs);

        logger.info("Added latency: {}ms +/- {}ms", latencyMs, jitterMs);

        countingRetryListener.expectCompletion();

        // When: Send a message
        assertDoesNotThrow(() ->
            eventProducer.produceMessage(createTestEventMessage()), "Should eventually succeed despite latency");

        // Wait for completion
        assertTrue(countingRetryListener.awaitCompletion(10, TimeUnit.SECONDS), "Operation should complete within timeout");

        // Then: Verify behavior (may or may not retry depending on latency impact)
        assertTrue(countingRetryListener.getAttemptsCount() >= 1, "Should have at least one attempt");

        logger.info("Message sent successfully with {} attempt(s), {} error(s)",
                countingRetryListener.getAttemptsCount(),
                countingRetryListener.getErrorCount());
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void testConnectionTimeout_shouldExhaustRetries() throws Exception {
        // Given: Connection times out after a short duration to trigger retries
        int timeoutMs = 100;
        proxy.toxics().timeout("timeout-toxic", ToxicDirection.UPSTREAM, timeoutMs);

        logger.info("Added timeout: {}ms", timeoutMs);

        countingRetryListener.expectCompletion();

        // When: Send message - should fail after exhausting retries
        assertThrows(Exception.class, () -> eventProducer.produceMessage(createTestEventMessage()));

        // Wait for retry completion
        assertTrue(countingRetryListener.awaitCompletion(5, TimeUnit.SECONDS), "Retries should complete within timeout");

        // Then: Should have attempted maxAttempts times
        assertEquals(maxAttempts, countingRetryListener.getAttemptsCount(), "Should have attempted exactly maxAttempts times");

        logger.info("Timeout test completed: {} attempt(s), {} error(s)",
                countingRetryListener.getAttemptsCount(),
                countingRetryListener.getErrorCount());
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    void testTimeoutRecovery_shouldSucceedAfterToxicRemoved() throws Exception {
        // Given: First message fails due to timeout
        proxy.toxics().timeout("timeout-toxic", ToxicDirection.UPSTREAM, 500);
        countingRetryListener.expectCompletion();

        assertThrows(Exception.class, () -> eventProducer.produceMessage(createTestEventMessage()));
        assertTrue(countingRetryListener.awaitCompletion(10, TimeUnit.SECONDS), "First message retries should complete");

        countingRetryListener.reset();

        // When: Toxic removed and second message sent
        proxy.toxics().get("timeout-toxic").remove();
        logger.info("Timeout toxic removed");

        countingRetryListener.expectCompletion();

        // Then: Second message succeeds
        assertDoesNotThrow(() -> eventProducer.produceMessage(createTestEventMessage()));

        assertTrue(countingRetryListener.awaitCompletion(5, TimeUnit.SECONDS), "Second message should complete");

        assertEquals(1, countingRetryListener.getAttemptsCount(),
                "Should succeed on first attempt after toxic removal");
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testSlicedConnection_shouldSucceedWithLargePayload() throws Exception {
        // Given: Slicer toxic (1KB chunks with 20ms delay each)
        int averageSliceSize = 1024;
        int delayMicros = 20_000; // 20ms
        proxy.toxics().slicer("slicer-toxic", ToxicDirection.UPSTREAM, averageSliceSize, delayMicros)
                .setSizeVariation(256);

        logger.info("Added slicer: {}bytes with {}us delay", averageSliceSize, delayMicros);

        countingRetryListener.expectCompletion();

        // Large payload (~64KB = ~64 chunks = ~1.3s minimum)
        String largePayload = generateLargeRandomString(64 * 1024);

        // When: Send large message
        assertDoesNotThrow(() ->
            eventProducer.produceMessage(new EventMessage(
                    ResourceEvent.CERTIFICATE_DISCOVERED,
                    Resource.DISCOVERY,
                    UUID.randomUUID(),
                    largePayload
            )),
            "Should succeed despite sliced connection");

        // Wait for completion
        assertTrue(countingRetryListener.awaitCompletion(20, TimeUnit.SECONDS), "Operation should complete within timeout");

        // Then: Message should succeed (possibly with retries due to slow transfer)
        assertTrue(countingRetryListener.getAttemptsCount() >= 1, "Should have at least one attempt");

        logger.info("Slicer test completed: {} attempt(s), {} error(s)",
                countingRetryListener.getAttemptsCount(),
                countingRetryListener.getErrorCount());
    }

    private EventMessage createTestEventMessage() {
        return new EventMessage(
                ResourceEvent.CERTIFICATE_DISCOVERED,
                Resource.DISCOVERY,
                UUID.randomUUID(),
                "testData"
        );
    }

    private String generateLargeRandomString(int targetSizeInBytes) {
        int leftLimit = 48;  // '0'
        int rightLimit = 122; // 'z'
        java.util.Random random = new java.util.Random();

        return random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(targetSizeInBytes)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }
}