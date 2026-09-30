package com.otilm.core.config;

import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyImportPropertiesTest {

    @Test
    void theDefaultsApplyWhenNothingIsConfigured() {
        // when
        KeyImportProperties properties = new KeyImportProperties(null, null, null, null, null, null);

        // then
        assertThat(properties.requestTimeout()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.pollInterval()).isEqualTo(Duration.ofSeconds(2));
        assertThat(properties.unresolvedAfter()).isEqualTo(Duration.ofHours(20));
        assertThat(properties.retryWindow()).isEqualTo(Duration.ofMinutes(15));
        assertThat(properties.sweepInterval()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.retention()).isEqualTo(Duration.ofDays(7));
    }

    @Test
    void aDurationThatIsNotPositiveIsRefused() {
        // given
        Duration zero = Duration.ZERO;
        Duration negative = Duration.ofSeconds(-1);

        // when
        // then
        assertThatThrownBy(() -> new KeyImportProperties(zero, null, null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("key-import.request-timeout");
        assertThatThrownBy(() -> new KeyImportProperties(null, negative, null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("key-import.poll-interval");
        assertThatThrownBy(() -> new KeyImportProperties(null, null, zero, null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("key-import.unresolved-after");
        assertThatThrownBy(() -> new KeyImportProperties(null, null, null, negative, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("key-import.retry-window");
        assertThatThrownBy(() -> new KeyImportProperties(null, null, null, null, zero, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("key-import.sweep-interval");
    }

    /** The request sleeps in whole milliseconds, so a shorter poll interval would ask the connector without a pause. */
    @Test
    void aPollIntervalShorterThanAMillisecondIsRefused() {
        // given
        Duration microsecond = Duration.ofNanos(1_000);

        // when
        // then
        assertThatThrownBy(() -> new KeyImportProperties(null, microsecond, null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("key-import.poll-interval must be at least a millisecond, was PT0.000001S");
    }

    /** A connector keeps its record of an import for at least 24 hours; past that, a missing record proves nothing. */
    @Test
    void anUnresolvedAfterOfADayOrMoreIsRefused() {
        // given
        Duration day = Duration.ofHours(24);

        // when
        // then
        assertThatThrownBy(() -> new KeyImportProperties(null, null, day, null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("key-import.unresolved-after must be shorter than 24 hours, was PT24H");
    }

    /**
     * The last look comes up to a retry window and a sweep after the cutoff, and must come while the record is kept.
     */
    @Test
    void aLastLookThatCouldComeAfterTheConnectorForgetsIsRefused() {
        // given
        Duration twentyThreeHours = Duration.ofHours(23);
        Duration twoHours = Duration.ofHours(2);

        // when
        // then
        assertThatThrownBy(() -> new KeyImportProperties(null, null, twentyThreeHours, twoHours, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("key-import.unresolved-after, key-import.retry-window and key-import.sweep-interval "
                        + "together must be shorter than 24 hours, were PT23H, PT2H and PT1M");
    }

    /** The first look at an import comes up to a sweep after its retry window, and must come before it is given up. */
    @Test
    void aSweepThatCouldComeOnlyAfterUnresolvedAfterIsRefused() {
        // given
        Duration hour = Duration.ofHours(1);
        Duration day = Duration.ofHours(24);

        // when
        // then
        assertThatThrownBy(() -> new KeyImportProperties(null, null, hour, hour, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("key-import.retry-window and key-import.sweep-interval together must be shorter than "
                        + "key-import.unresolved-after, were PT1H and PT1M");
        assertThatThrownBy(() -> new KeyImportProperties(null, null, null, null, day, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("key-import.retry-window and key-import.sweep-interval together must be shorter than "
                        + "key-import.unresolved-after, were PT15M and PT24H");
    }

    /** A finished import is kept longer than an import can stay open, which is until its last look. */
    @Test
    void aRetentionNoLongerThanAnImportCanStayOpenIsRefused() {
        // given
        Duration longestOpen = Duration.ofHours(20).plusMinutes(16);
        Duration longer = longestOpen.plusSeconds(1);

        // when
        // then
        assertThatThrownBy(() -> new KeyImportProperties(null, null, null, null, null, longestOpen))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("key-import.retention must be longer than key-import.unresolved-after, "
                        + "key-import.retry-window and key-import.sweep-interval together (PT20H16M), was PT20H16M");
        assertThat(new KeyImportProperties(null, null, null, null, null, longer).retention()).isEqualTo(longer);
    }
}
