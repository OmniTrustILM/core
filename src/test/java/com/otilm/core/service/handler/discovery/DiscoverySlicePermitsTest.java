package com.otilm.core.service.handler.discovery;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DiscoverySlicePermitsTest {

    @Test
    void refusesAPermit_whenTheCapIsTaken() {
        // given
        var cap = 2;
        var permits = new DiscoverySlicePermits(cap);
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
        var permits = new DiscoverySlicePermits(1);
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
        ThrowingCallable createPermits = () -> new DiscoverySlicePermits(noSlicesAtAll);

        // then
        assertThatThrownBy(createPermits)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("discovery.slice.max-concurrent-per-node");
    }
}
