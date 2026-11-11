package com.otilm.core.certificate.type;

import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ValidityTest {

    private static final Instant NOT_BEFORE = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant NOT_AFTER = Instant.parse("2026-12-31T00:00:00Z");

    @Test
    void reportsNotYetValid_whenTheMomentIsBeforeTheStart() {
        // given
        var validity = new Validity(NOT_BEFORE, NOT_AFTER, ValidityPrecision.DATE_TIME);

        // when
        ValidityStatus status = validity.statusAt(NOT_BEFORE.minusSeconds(1));

        // then
        assertThat(status).isEqualTo(ValidityStatus.NOT_YET_VALID);
    }

    @Test
    void reportsValid_whenTheMomentIsWithinTheDateTimePeriod() {
        // given
        var validity = new Validity(NOT_BEFORE, NOT_AFTER, ValidityPrecision.DATE_TIME);

        // when
        ValidityStatus status = validity.statusAt(Instant.parse("2026-06-01T12:00:00Z"));

        // then
        assertThat(status).isEqualTo(ValidityStatus.VALID);
    }

    @Test
    void reportsExpired_whenTheMomentIsAfterTheEndOfADateTimePeriod() {
        // given
        var validity = new Validity(NOT_BEFORE, NOT_AFTER, ValidityPrecision.DATE_TIME);

        // when
        ValidityStatus status = validity.statusAt(NOT_AFTER.plusSeconds(1));

        // then
        assertThat(status).isEqualTo(ValidityStatus.EXPIRED);
    }

    @Test
    void reportsValid_whenTheMomentIsLaterOnTheLastDayOfADatePeriod() {
        // given
        var validity = new Validity(NOT_BEFORE, NOT_AFTER, ValidityPrecision.DATE);

        // when
        ValidityStatus status = validity.statusAt(Instant.parse("2026-12-31T23:59:59Z"));

        // then
        assertThat(status).isEqualTo(ValidityStatus.VALID);
    }

    @Test
    void reportsExpired_whenTheMomentIsOnTheDayAfterADatePeriod() {
        // given
        var validity = new Validity(NOT_BEFORE, NOT_AFTER, ValidityPrecision.DATE);

        // when
        ValidityStatus status = validity.statusAt(Instant.parse("2027-01-01T00:00:01Z"));

        // then
        assertThat(status).isEqualTo(ValidityStatus.EXPIRED);
    }
}
