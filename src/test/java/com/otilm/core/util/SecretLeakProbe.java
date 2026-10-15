package com.otilm.core.util;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/** Captures what the platform logs at DEBUG while a test runs, so the test can show a secret reached none of it. */
public final class SecretLeakProbe implements AutoCloseable {

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    private final Logger platform = (Logger) LoggerFactory.getLogger("com.otilm");
    private final Level platformLevel = platform.getLevel();

    private SecretLeakProbe() {
        logs.start();
        root.addAppender(logs);
        platform.setLevel(Level.DEBUG);
    }

    /** Starts capturing; closing the probe restores the loggers. */
    public static SecretLeakProbe capture() {
        return new SecretLeakProbe();
    }

    /** Every captured line, with the stack trace of any throwable it carried. */
    public List<String> logged() {
        List<String> lines = new ArrayList<>();
        for (ILoggingEvent event : logs.list) {
            lines.add(event.getFormattedMessage());
            if (event.getThrowableProxy() != null) {
                lines.add(ThrowableProxyUtil.asString(event.getThrowableProxy()));
            }
        }
        return lines;
    }

    @Override
    public void close() {
        platform.setLevel(platformLevel);
        root.detachAppender(logs);
    }

    /** Every audit record as its JSON row. */
    public static List<String> auditRecords(JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForList("SELECT row_to_json(audit_log)::text FROM audit_log", String.class);
    }

    /** Asserts that some text was collected and that none of it, nulls aside, contains any of the secrets. */
    public static void assertNoneReveals(Collection<String> texts, String... secrets) {
        assertThat(texts)
                .filteredOn(Objects::nonNull)
                .isNotEmpty()
                .allSatisfy(text -> assertThat(text).doesNotContain(secrets));
    }
}
