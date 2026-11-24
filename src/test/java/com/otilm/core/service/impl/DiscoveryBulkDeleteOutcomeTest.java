package com.otilm.core.service.impl;

import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class DiscoveryBulkDeleteOutcomeTest {

    @ParameterizedTest
    @MethodSource("outcomes")
    void describesTheOutcome_whenTheBulkDeleteEnds(int stillRunning, int failed, String expected) {
        // given — the counts of runs the bulk delete refused and failed to delete

        // when
        String outcome = DiscoveryServiceImpl.bulkDeleteOutcome(stillRunning, failed);

        // then
        assertThat(outcome).isEqualTo(expected);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Arguments> outcomes() {
        return Stream
                .of(arguments(named("every run deleted", 0), 0, "Discovery histories have been deleted."),
                        arguments(named("some still running", 2), 0,
                                "Discovery histories have been deleted, except 2 that are still running."
                                        + " Cancel those first."),
                        arguments(named("some failed", 0), 3,
                                "Discovery histories have been deleted, except 3 that could not be deleted."),
                        arguments(named("some still running and some failed", 2), 3,
                                "Discovery histories have been deleted, except 2 that are still running and 3 that"
                                        + " could not be deleted. Cancel the running ones first."));
    }
}
