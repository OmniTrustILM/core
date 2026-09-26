package com.otilm.core.config;

import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyImportPropertiesTest {

    @Test
    void theDefaultsApplyWhenNothingIsConfigured() {
        // when
        KeyImportProperties properties = new KeyImportProperties(null, null, null);

        // then
        assertThat(properties.requestTimeout()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.pollInterval()).isEqualTo(Duration.ofSeconds(2));
        assertThat(properties.unresolvedAfter()).isEqualTo(Duration.ofHours(20));
    }

    @Test
    void aDurationThatIsNotPositiveIsRefused() {
        // given
        Duration zero = Duration.ZERO;
        Duration negative = Duration.ofSeconds(-1);

        // when
        // then
        assertThatThrownBy(() -> new KeyImportProperties(zero, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("key-import.request-timeout");
        assertThatThrownBy(() -> new KeyImportProperties(null, negative, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("key-import.poll-interval");
        assertThatThrownBy(() -> new KeyImportProperties(null, null, zero))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("key-import.unresolved-after");
    }

    /** A connector keeps its record of an import for at least 24 hours; past that, a missing record proves nothing. */
    @Test
    void anUnresolvedAfterOfADayOrMoreIsRefused() {
        // given
        Duration day = Duration.ofHours(24);

        // when
        // then
        assertThatThrownBy(() -> new KeyImportProperties(null, null, day))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("key-import.unresolved-after must be shorter than 24 hours, was PT24H");
    }
}
