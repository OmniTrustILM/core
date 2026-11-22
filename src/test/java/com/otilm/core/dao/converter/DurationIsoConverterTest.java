package com.otilm.core.dao.converter;

import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DurationIsoConverterTest {

    private final DurationIsoConverter converter = new DurationIsoConverter();

    @Test
    void roundTripsTheDuration_whenStoredAndRead() {
        // given
        var thirtySixHours = Duration.ofHours(36);

        // when
        Duration back = converter.convertToEntityAttribute(converter.convertToDatabaseColumn(thirtySixHours));

        // then
        assertThat(back).isEqualTo(thirtySixHours);
    }

    @Test
    void storesIsoText_whenDurationGiven() {
        // given
        var oneDay = Duration.ofDays(1);

        // when
        String stored = converter.convertToDatabaseColumn(oneDay);

        // then
        assertThat(Duration.parse(stored)).isEqualTo(oneDay);
    }

    @Test
    void storesNull_whenNothingIsStored() {
        // given
        Duration absent = null;

        // when
        String stored = converter.convertToDatabaseColumn(absent);

        // then
        assertThat(stored).isNull();
    }

    @Test
    void readsNull_whenColumnIsNull() {
        // given — the column holds no value

        // when
        Duration read = converter.convertToEntityAttribute(null);

        // then
        assertThat(read).isNull();
    }
}
