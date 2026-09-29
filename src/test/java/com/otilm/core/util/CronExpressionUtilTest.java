package com.otilm.core.util;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit test for {@link CronExpressionUtil}, the pure kernel behind {@code ScheduledJobDto.nextFireTime}. Quartz
 * evaluates in the JVM default zone and the build pins none, so exact-value cases use an every-minute expression, whose
 * fire instants are the same in every zone; the hourly case asserts zone-relative properties instead.
 */
class CronExpressionUtilTest {

    private static final String JOB_NAME = "hourly-sweep";
    private static final String EVERY_MINUTE = "0 * * ? * *";
    private static final String HALF_PAST_EVERY_HOUR = "0 30 * ? * *";
    private static final Instant AFTER = Instant.parse("2026-09-24T10:15:20Z");

    @Test
    void nextFireTime_returnsTheNextFireInstantStrictlyAfterTheGivenOne() {
        // when
        Instant next = CronExpressionUtil.nextFireTime(JOB_NAME, EVERY_MINUTE, AFTER);

        // then
        assertEquals(Instant.parse("2026-09-24T10:16:00Z"), next);
    }

    @Test
    void nextFireTime_skipsTheGivenInstant_whenItIsItselfAFireTime() {
        // given an instant exactly on a fire time
        Instant onTheMinute = Instant.parse("2026-09-24T10:16:00Z");

        // when
        Instant next = CronExpressionUtil.nextFireTime(JOB_NAME, EVERY_MINUTE, onTheMinute);

        // then the trigger is due at the following one, not "now"
        assertEquals(Instant.parse("2026-09-24T10:17:00Z"), next);
    }

    @Test
    void nextFireTime_evaluatesAStoredHourlyExpressionInTheJvmZone() {
        // given the PQC sweep's own expression
        // when
        Instant next = CronExpressionUtil.nextFireTime(JOB_NAME, HALF_PAST_EVERY_HOUR, AFTER);

        // then it lands on the next local half hour, within the hour
        ZonedDateTime local = next.atZone(ZoneId.systemDefault());
        assertEquals(30, local.getMinute());
        assertEquals(0, local.getSecond());
        assertTrue(next.isAfter(AFTER));
        assertTrue(Duration.between(AFTER, next).compareTo(Duration.ofHours(1)) <= 0);
    }

    @Test
    void nextFireTime_isNull_whenNoExpressionIsStored() {
        assertNull(CronExpressionUtil.nextFireTime(JOB_NAME, null, AFTER));
        assertNull(CronExpressionUtil.nextFireTime(JOB_NAME, "   ", AFTER));
    }

    @Test
    void nextFireTime_isNull_whenTheStoredExpressionDoesNotParse() {
        assertNull(CronExpressionUtil.nextFireTime(JOB_NAME, "every hour on the half hour", AFTER));
    }

    @Test
    void nextFireTime_isNull_forAFiveFieldUnixCrontabExpression() {
        // given the Unix crontab shape (no seconds field) the scheduler would never have stored -- Spring's own
        // parser rejects it too, since Spring's CronExpression requires six fields
        assertNull(CronExpressionUtil.nextFireTime(JOB_NAME, "30 * * * *", AFTER));
    }

    @Test
    void nextFireTime_isNull_whenTheExpressionHasNoFireTimeLeft() {
        // given a seventh, year field that already lies in the past
        assertNull(CronExpressionUtil.nextFireTime(JOB_NAME, "0 0 0 1 1 ? 2020", AFTER));
    }
}
