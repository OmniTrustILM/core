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
 * rather than silently misreading a Quartz-authored expression. Core runs no Quartz scheduler; see
 * {@link com.otilm.core.Application}.
 */
public final class CronExpressionUtil {

    private static final Logger logger = LoggerFactory.getLogger(CronExpressionUtil.class);

    private CronExpressionUtil() {
    }

    /**
     * Returns the first fire time strictly after {@code after}, or {@code null} when none can be served.
     *
     * <p>
     * <b>Time zone:</b> evaluated in the JVM default zone. The scheduler fixes each trigger's zone once, when it
     * creates the trigger, so the result drifts if either JVM's zone has changed since then.
     *
     * <p>
     * <b>Never throws:</b> a missing or unparseable expression is logged and yields {@code null}, as does an expression
     * with no fire time left (a seventh, year field already in the past). None of these may fail the request that lists
     * the job.
     *
     * @param jobName names the job in the log line when its stored expression is missing or does not parse; it takes no
     * part in the computation
     */
    public static Instant nextFireTime(final String jobName, final String cronExpression, final Instant after) {
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
