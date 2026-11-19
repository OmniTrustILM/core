package com.otilm.core.dao.converter;

import com.otilm.api.model.client.discovery.DiscoveryWindowMode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryWindowModeConverterTest {

    private final DiscoveryWindowModeConverter converter = new DiscoveryWindowModeConverter();

    @Test
    void roundTripsTheWireCode_whenStoredAndRead() {
        // given
        var mode = DiscoveryWindowMode.SINCE_LAST_SUCCESSFUL_RUN;

        // when
        String stored = converter.convertToDatabaseColumn(mode);
        DiscoveryWindowMode back = converter.convertToEntityAttribute(stored);

        // then
        assertThat(stored).isEqualTo("sinceLastSuccessfulRun");
        assertThat(back).isEqualTo(mode);
    }

    @Test
    void storesNull_whenNothingIsStored() {
        // given
        DiscoveryWindowMode absent = null;

        // when
        String stored = converter.convertToDatabaseColumn(absent);

        // then
        assertThat(stored).isNull();
    }

    @Test
    void readsNull_whenColumnIsNull() {
        // given — the column holds no value

        // when
        DiscoveryWindowMode read = converter.convertToEntityAttribute(null);

        // then
        assertThat(read).isNull();
    }
}
