package com.otilm.core.util;

import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Makes the database refuse to delete one discovery, so a test can fail a delete after its other writes went through,
 * as a database fault would. Remove it in {@code @AfterEach}: the trigger outlives the test's own data.
 */
public final class RefusedDiscoveryDeletes {

    public static final String REASON = "discovery delete refused by the test";

    private RefusedDiscoveryDeletes() {
    }

    public static void install(JdbcTemplate jdbc, UUID discoveryUuid) {
        jdbc.execute("""
                CREATE OR REPLACE FUNCTION refuse_discovery_delete() RETURNS TRIGGER AS $$
                BEGIN
                    IF OLD.uuid = '%s' THEN
                        RAISE EXCEPTION '%s';
                    END IF;
                    RETURN OLD;
                END
                $$ LANGUAGE plpgsql""".formatted(discoveryUuid, REASON));
        jdbc.execute("""
                CREATE TRIGGER refuse_discovery_delete BEFORE DELETE ON discovery
                FOR EACH ROW EXECUTE FUNCTION refuse_discovery_delete()""");
    }

    public static void remove(JdbcTemplate jdbc) {
        jdbc.execute("DROP TRIGGER IF EXISTS refuse_discovery_delete ON discovery");
        jdbc.execute("DROP FUNCTION IF EXISTS refuse_discovery_delete()");
    }
}
