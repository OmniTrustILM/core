package com.otilm.core.service.impl;

import java.time.Duration;
import java.util.Date;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The one piece of arithmetic the whole feed rests on: the {@code after} bound a run opens with. It is the start of the
 * last successful run, in whole seconds, less the overlap that covers clock skew between Core and the object store and
 * uploads still in flight when that run started. Pinned here rather than in an integration test because nothing about
 * it needs a database or a repository -- and because an overlap that silently came out as zero is exactly the defect
 * this guards.
 */
class CbomSyncWatermarkTest {

    /** An arbitrary run start with a sub-second remainder, so the truncation to whole seconds is exercised too. */
    private static final Date RUN_START = new Date(1_700_000_000_999L);

    private static final long RUN_START_SECOND = 1_700_000_000L;

    @Test
    void theDefaultOverlapMovesTheBoundASecondPerSecondBack() {
        assertThat(CbomServiceImpl.watermarkSeconds(RUN_START, Duration.ofSeconds(60)))
                .isEqualTo(RUN_START_SECOND - 60);
    }

    @Test
    void withoutAnOverlapTheBoundIsTheRunStartSecond() {
        assertThat(CbomServiceImpl.watermarkSeconds(RUN_START, Duration.ZERO)).isEqualTo(RUN_START_SECOND);
    }

    @Test
    void aLongOverlapIsSubtractedInFull() {
        assertThat(CbomServiceImpl.watermarkSeconds(RUN_START, Duration.ofMinutes(5)))
                .isEqualTo(RUN_START_SECOND - 300);
    }

    @Test
    void aRunStartEarlierThanTheOverlapClampsToTheEpoch() {
        assertThat(CbomServiceImpl.watermarkSeconds(new Date(30_000L), Duration.ofSeconds(60))).isZero();
    }
}
