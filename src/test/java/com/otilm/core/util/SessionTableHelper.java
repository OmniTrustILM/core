package com.otilm.core.util;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The session tables come from {@code schema.sql} and every test context shares them, so a test only empties them.
 */
public class SessionTableHelper {

    public static void deleteAllSessions(JdbcTemplate jdbcTemplate) {
        jdbcTemplate.update("DELETE FROM spring_session");
    }
}
