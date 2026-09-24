package com.otilm.core.util;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import org.quartz.CronExpression;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cron arithmetic over the dialect the scheduler stores: Quartz's six or seven fields, seconds first, with the
 * {@code ?} wildcard. Spring's {@code CronExpression} rejects the 7-field year form some stored expressions use, and
 * gives numeric day-of-week a different meaning than Quartz does (1 = Sunday in Quartz, Monday in Spring; Quartz
 * rejects 0 outright, where Spring accepts it as Sunday too), so Quartz's own parser is used -- as a parser only --
 * rather than silently misreading a Quartz-authored expression. Core runs no Quartz scheduler ({@code
 * QuartzAutoConfiguration} is excluded in {@code Application}).
 */
public final class CronExpressionUtil {

    private static final Logger logger = LoggerFactory.getLogger(CronExpressionUtil.class);

    private CronExpressionUtil() {
    }

    /**
     * The first moment strictly after {@code after} at which a job on {@code cronExpression} fires, evaluated in the
     * JVM default time zone: the scheduler builds its trigger with {@code CronScheduleBuilder.cronSchedule} and no
     * explicit zone, and that zone is captured once, into the JDBC-backed job store, at trigger creation time rather
     * than read fresh on every fire. This agrees with core's computation only when core's current zone matches the zone
     * the scheduler process had at the time each trigger was created, not simply whenever both services happen to run
     * under one zone today.
     *
     * @param jobName names the job in the log line when its stored expression is missing or does not parse; it takes no
     * part in the computation
     * @return {@code null} when the job is disabled, when no expression is stored, when the expression does not parse,
     * or when it has no fire time left (a seventh, year field already in the past). A missing or unparseable stored
     * expression is a data problem and is logged; none of these may fail the request that lists the job.
     */
    public static Instant nextFireTime(final String jobName, final String cronExpression, final boolean enabled,
            final Instant after) {
        if (!enabled) {
            return null;
        }
        if (cronExpression == null || cronExpression.isBlank()) {
            logger
                    .warn("Scheduled job '{}' has no cron expression stored; its next fire time cannot be computed",
                            jobName);
            return null;
        }
        final CronExpression parsed;
        try {
            parsed = new CronExpression(cronExpression);
        } catch (ParseException e) {
            logger
                    .warn("Scheduled job '{}' stores cron expression '{}' that does not parse; "
                            + "its next fire time cannot be computed", jobName, cronExpression, e);
            return null;
        }
        final Date next = parsed.getNextValidTimeAfter(Date.from(after));
        return next == null ? null : next.toInstant();
    }
}
