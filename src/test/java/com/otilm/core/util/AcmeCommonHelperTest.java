package com.otilm.core.util;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

class AcmeCommonHelperTest {

    @ParameterizedTest
    @MethodSource("rfc3339TimestampsOfOneInstant")
    void returnsTheInstantNamed_whenTimestampIsRfc3339(String timestamp) {
        // given
        Instant namedInstant = OffsetDateTime.of(2026, 11, 5, 10, 0, 0, 0, ZoneOffset.UTC).toInstant();

        // when
        Date date = AcmeCommonHelper.getDateFromString(timestamp);

        // then
        assertThat(date.toInstant()).isEqualTo(namedInstant);
    }

    @Test
    void returnsLastSecondOfTheDay_whenTimestampIsLeapSecond() {
        // given
        var leapSecond = "2016-12-31T23:59:60Z";
        Instant lastSecondOfTheDay = OffsetDateTime.of(2016, 12, 31, 23, 59, 59, 0, ZoneOffset.UTC).toInstant();

        // when
        Date date = AcmeCommonHelper.getDateFromString(leapSecond);

        // then
        assertThat(date.toInstant()).isEqualTo(lastSecondOfTheDay);
    }

    @ParameterizedTest
    @MethodSource("textsThatAreNotTimestampsInRange")
    void throwsDateTimeException_whenTextIsNotTimestampInRange(String text) {
        // given — a text that is not an RFC 3339 timestamp from 1970 to 9999

        // when
        ThrowingCallable read = () -> AcmeCommonHelper.getDateFromString(text);

        // then
        assertThatThrownBy(read).isInstanceOf(DateTimeException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<String>> rfc3339TimestampsOfOneInstant() {
        return Stream
                .of(named("UTC without a fraction", "2026-11-05T10:00:00Z"),
                        named("UTC with two fraction digits, as Core writes it", "2026-11-05T10:00:00.00Z"),
                        named("UTC with three fraction digits", "2026-11-05T10:00:00.000Z"),
                        named("an offset east of UTC", "2026-11-05T12:00:00+02:00"),
                        named("lower-case separators", "2026-11-05t10:00:00z"));
    }

    private static Stream<Named<String>> textsThatAreNotTimestampsInRange() {
        return Stream
                .of(named("an empty string", ""), named("text that is not a timestamp", "not-a-date"),
                        named("a date without a time", "2026-11-05"),
                        named("a time without an offset", "2026-11-05T10:00:00"),
                        named("a time without seconds", "2026-11-05T10:00Z"),
                        named("a year of more than four digits", "+10000-01-01T00:00:00Z"),
                        named("an instant before 1970", "1969-12-31T23:59:59Z"),
                        named("an instant after 9999 in UTC", "9999-12-31T23:30:00-01:00"),
                        named("a fraction finer than nanoseconds", "2026-11-05T10:00:00.0000000000Z"),
                        named("an offset beyond 18 hours", "2026-11-05T10:00:00+19:00"));
    }
}
