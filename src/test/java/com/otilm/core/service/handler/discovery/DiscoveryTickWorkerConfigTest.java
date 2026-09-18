package com.otilm.core.service.handler.discovery;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * The bounds a misconfigured deployment could set to nonsense. Each is checked where it is injected, so the context
 * refuses to start rather than the failure surfacing one tick at a time against live runs.
 */
class DiscoveryTickWorkerConfigTest {

    @Test
    void nonPositiveProcessingBatchSize_isRefusedAtStartup() {
        // Left to a tick, this throws inside PageRequest.of and reaches the listener's log-and-acknowledge
        // instead (see DiscoveryProcessTickWorker).
        assertThatIllegalArgumentException()
                .isThrownBy(() -> processWorkerWithBatchSize(0))
                .withMessageContaining("discovery.processing.batch-size");
        assertThatIllegalArgumentException().isThrownBy(() -> processWorkerWithBatchSize(-1));
    }

    @Test
    void nonPositiveDrainBounds_areRefusedAtStartup() {
        // Bounded, unlike the batch size -- the connector rejects the request and the budget eventually ends the
        // run -- but a typo that fails every healthy run is still a startup problem, not a runtime one.
        assertThatIllegalArgumentException()
                .isThrownBy(() -> drainWorkerWith(0, 1024))
                .withMessageContaining("discovery.drain.max-items");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> drainWorkerWith(500, 0))
                .withMessageContaining("discovery.drain.max-bytes");
    }

    @Test
    void nonPositiveContinuationBackstop_isRefusedAtStartup() {
        // Both workers park their backstop row and publish the continuation themselves; see DiscoveryWorkWriter
        // for why it must be due in the future.
        for (Duration notABackstop : List.of(Duration.ZERO, Duration.ofSeconds(-1))) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> processWorkerWith(200, notABackstop))
                    .withMessageContaining("discovery.work.continuation-backstop");
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> drainWorkerWith(500, 1024, notABackstop))
                    .withMessageContaining("discovery.work.continuation-backstop");
        }
    }

    private static DiscoveryProcessTickWorker processWorkerWithBatchSize(int batchSize) {
        return processWorkerWith(batchSize, Duration.ofMinutes(1));
    }

    private static DiscoveryProcessTickWorker processWorkerWith(int batchSize, Duration continuationBackstop) {
        return new DiscoveryProcessTickWorker(null, null, null, null, null, null, null, null, null, null, null, null,
                batchSize, continuationBackstop);
    }

    private static DiscoveryDrainTickWorker drainWorkerWith(int maxItems, long maxBytes) {
        return drainWorkerWith(maxItems, maxBytes, Duration.ofMinutes(1));
    }

    private static DiscoveryDrainTickWorker drainWorkerWith(int maxItems, long maxBytes,
            Duration continuationBackstop) {
        return new DiscoveryDrainTickWorker(null, null, null, null, null, null, null, null, null, maxItems, maxBytes,
                continuationBackstop);
    }
}
