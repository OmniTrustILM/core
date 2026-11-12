package com.otilm.core.service.handler.discovery;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The bounds a misconfigured deployment could set to nonsense. Each is checked where it is injected, so the context
 * refuses to start rather than the failure surfacing one tick at a time against live runs.
 */
class DiscoveryTickWorkerConfigTest {

    private static final String BUFFERED_ONLY = "buffered";
    private static final String CHECKPOINTED_AND_BUFFERED = "checkpointed,buffered";

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
                .isThrownBy(() -> drainWorkerOffering(BUFFERED_ONLY, 0, 1024))
                .withMessageContaining("discovery.drain.max-items");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> drainWorkerOffering(BUFFERED_ONLY, 500, 0))
                .withMessageContaining("discovery.drain.max-bytes");
    }

    @ParameterizedTest
    @CsvSource({"99, 1048576, discovery.drain.max-items", "100, 1048575, discovery.drain.max-bytes"})
    void refusesToStart_whenAPageLimitIsBelowTheFloor(int maxItems, long maxBytes, String settingBelowTheFloor) {
        // given — one page limit just below its floor

        // when
        ThrowingCallable construct = () -> drainWorkerWith(maxItems, maxBytes);

        // then
        assertThatThrownBy(construct)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(settingBelowTheFloor);
    }

    @Test
    void starts_whenBothPageLimitsSitOnTheFloor() {
        // given
        var floorItems = 100;
        var floorBytes = 1_048_576L;

        // when
        ThrowingCallable construct = () -> drainWorkerWith(floorItems, floorBytes);

        // then
        assertThatCode(construct).doesNotThrowAnyException();
    }

    @Test
    void starts_whenPageLimitsAreBelowTheFloorAndCheckpointedIsNotOffered() {
        // given
        var belowTheItemFloor = 50;
        var belowTheByteFloor = 262_144L;

        // when
        ThrowingCallable construct = () -> drainWorkerOffering(BUFFERED_ONLY, belowTheItemFloor, belowTheByteFloor);

        // then
        assertThatCode(construct).doesNotThrowAnyException();
    }

    private static DiscoveryProcessTickWorker processWorkerWithBatchSize(int batchSize) {
        return new DiscoveryProcessTickWorker(null, null, null, null, null, null, null, null, null, null, null, null,
                null, batchSize);
    }

    private static DiscoveryDrainTickWorker drainWorkerWith(int maxItems, long maxBytes) {
        return drainWorkerOffering(CHECKPOINTED_AND_BUFFERED, maxItems, maxBytes);
    }

    private static DiscoveryDrainTickWorker drainWorkerOffering(String modes, int maxItems, long maxBytes) {
        return new DiscoveryDrainTickWorker(null, null, null, null, null, null, null, null, null, null, null, null,
                new DiscoveryDeliveryModeOffer(modes), maxItems, maxBytes);
    }
}
