package com.otilm.core.architecture;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the number of distinct Spring test-context signatures to an exact committed {@link #BASELINE}.
 */
class ContextSignatureGuardTest {

    /** Committed baseline: the exact current distinct count. Update in lock-step with any change. */
    static final int BASELINE = 57;

    private static final Path TEST_ROOT = Path.of("src/test/java");

    @Test
    void distinctContextSignaturesMatchBaseline() {
        int actual = ContextSignature.distinctCount(TEST_ROOT);
        assertThat(actual)
                .describedAs("Distinct context-signature count changed from the committed BASELINE (%d). "
                        + "If it ROSE, either reuse an existing mock-module combination, or — if a new "
                        + "combination is genuinely needed — raise BASELINE in this PR (the reviewed record of "
                        + "a new ~15s context boot). If it FELL, a combination was removed: lower BASELINE to "
                        + "match, so no silent slack accumulates.", BASELINE)
                .isEqualTo(BASELINE);
    }

    @Test
    void census() {
        int count = ContextSignature.distinctCount(TEST_ROOT);
        System.out.println("[CENSUS] distinct context signatures = " + count);
        assertThat(count).describedAs("there must be at least one context-loading test").isPositive();
    }
}
