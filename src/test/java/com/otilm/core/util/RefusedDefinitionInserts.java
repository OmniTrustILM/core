package com.otilm.core.util;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Makes the database refuse to store an attribute definition of one name, so a test can drive the attribute engine into
 * a failure that is not an {@code AttributeException}, as a database fault would. Remove it in {@code @AfterEach}: the
 * trigger outlives the test's own data.
 */
public final class RefusedDefinitionInserts {

    public static final String REFUSED_NAME = "refusedByTheDatabase";

    private RefusedDefinitionInserts() {
    }

    public static void install(JdbcTemplate jdbc) {
        jdbc.execute("""
                CREATE OR REPLACE FUNCTION refuse_attribute_definition_insert() RETURNS TRIGGER AS $$
                BEGIN
                    IF NEW.name = 'refusedByTheDatabase' THEN
                        RAISE EXCEPTION 'attribute definition refused by the test';
                    END IF;
                    RETURN NEW;
                END
                $$ LANGUAGE plpgsql""");
        jdbc.execute("""
                CREATE TRIGGER refuse_attribute_definition_insert BEFORE INSERT ON attribute_definition
                FOR EACH ROW EXECUTE FUNCTION refuse_attribute_definition_insert()""");
    }

    public static void remove(JdbcTemplate jdbc) {
        jdbc.execute("DROP TRIGGER IF EXISTS refuse_attribute_definition_insert ON attribute_definition");
        jdbc.execute("DROP FUNCTION IF EXISTS refuse_attribute_definition_insert()");
    }
}
