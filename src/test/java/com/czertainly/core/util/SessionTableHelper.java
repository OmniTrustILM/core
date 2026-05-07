package com.czertainly.core.util;

import org.springframework.jdbc.core.JdbcTemplate;

public class SessionTableHelper {

    public static void createSessionTables(JdbcTemplate jdbcTemplate) {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS spring_session (
                    PRIMARY_ID CHAR(36) NOT NULL,
                    SESSION_ID CHAR(36) NOT NULL,
                    CREATION_TIME BIGINT NOT NULL,
                    LAST_ACCESS_TIME BIGINT NOT NULL,
                    MAX_INACTIVE_INTERVAL INT NOT NULL,
                    EXPIRY_TIME BIGINT NOT NULL,
                    PRINCIPAL_NAME VARCHAR(100),
                    CONSTRAINT spring_session_pkey PRIMARY KEY(PRIMARY_ID)
                );
                """);

        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS spring_session_attributes (
                    SESSION_PRIMARY_ID CHAR(36) NOT NULL,
                    ATTRIBUTE_NAME VARCHAR(200) NOT NULL,
                    ATTRIBUTE_BYTES TEXT,
                    CONSTRAINT spring_session_attributes_pkey PRIMARY KEY(SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
                    CONSTRAINT fk_session FOREIGN KEY(SESSION_PRIMARY_ID) REFERENCES spring_session(PRIMARY_ID) ON DELETE CASCADE
                );
                """);
    }
}
