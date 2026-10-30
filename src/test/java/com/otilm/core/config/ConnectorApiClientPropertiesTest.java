package com.otilm.core.config;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.util.unit.DataSize;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

class ConnectorApiClientPropertiesTest {

    private static ConnectorApiClientProperties withMaxInMemorySize(DataSize size) {
        return new ConnectorApiClientProperties(Duration.ofSeconds(3), Duration.ofSeconds(35), 20,
                Duration.ofSeconds(10), size);
    }

    @Test
    void acceptsAPositiveInMemoryCap() {
        assertThatNoException().isThrownBy(() -> withMaxInMemorySize(DataSize.ofMegabytes(16)));
    }

    @Test
    void rejectsAMissingZeroOrOversizedInMemoryCap() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> withMaxInMemorySize(null))
                .withMessageContaining("max-in-memory-size");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> withMaxInMemorySize(DataSize.ofBytes(0)))
                .withMessageContaining("max-in-memory-size");
        // ClientTuning takes an int of bytes, so anything above Integer.MAX_VALUE cannot be represented.
        assertThatIllegalArgumentException()
                .isThrownBy(() -> withMaxInMemorySize(DataSize.ofGigabytes(3)))
                .withMessageContaining("max-in-memory-size");
    }
}
