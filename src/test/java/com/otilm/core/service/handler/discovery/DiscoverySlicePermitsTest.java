package com.otilm.core.service.handler.discovery;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DiscoverySlicePermitsTest {

    private static final String SHIPPED_CONSUMERS = "1-12";

    @Test
    void refusesAPermit_whenTheCapIsTaken() {
        // given
        var twoSlots = 2;
        var permits = new DiscoverySlicePermits(twoSlots, SHIPPED_CONSUMERS);
        permits.tryAcquire();
        permits.tryAcquire();

        // when
        boolean granted = permits.tryAcquire();

        // then
        assertThat(granted).isFalse();
    }

    @Test
    void grantsAPermitAgain_whenOneIsReleased() {
        // given
        var singleSlot = 1;
        var permits = new DiscoverySlicePermits(singleSlot, SHIPPED_CONSUMERS);
        permits.tryAcquire();
        permits.release();

        // when
        boolean granted = permits.tryAcquire();

        // then
        assertThat(granted).isTrue();
    }

    @Test
    void refusesToStart_whenTheCapIsBelowOne() {
        // given
        var noSlicesAtAll = 0;

        // when
        ThrowingCallable createPermits = () -> new DiscoverySlicePermits(noSlicesAtAll, SHIPPED_CONSUMERS);

        // then
        assertThatThrownBy(createPermits)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("discovery.slice.max-concurrent-per-node");
    }

    @ParameterizedTest
    @CsvSource({"12, 1-12", "13, 1-12", "5, 5"})
    void refusesToStart_whenTheCapLeavesNoDiscoveryWorkConsumerFree(int cap, String consumers) {
        // given — a cap at or above the most consumers the discovery-work queue gets

        // when
        ThrowingCallable createPermits = () -> new DiscoverySlicePermits(cap, consumers);

        // then
        assertThatThrownBy(createPermits)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("discovery.slice.max-concurrent-per-node")
                .hasMessageContaining("messaging.concurrency.provider-discovery-work");
    }

    @Test
    void starts_whenTheCapLeavesOneDiscoveryWorkConsumerFree() {
        // given
        var oneBelowTheConsumerMaximum = 11;

        // when
        ThrowingCallable createPermits = () -> new DiscoverySlicePermits(oneBelowTheConsumerMaximum, SHIPPED_CONSUMERS);

        // then
        assertThatCode(createPermits).doesNotThrowAnyException();
    }
}
