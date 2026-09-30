package com.otilm.core.util;

import java.sql.SQLException;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DuplicateKeyException;

/** Recognises a violated unique constraint in an exception, however the persistence stack wrapped it. */
public final class UniqueViolations {

    private static final int MAX_CAUSE_DEPTH = 10;

    /** SQLSTATE 23505, unique_violation. */
    private static final String UNIQUE_VIOLATION_SQL_STATE = "23505";

    private UniqueViolations() {
    }

    /**
     * Kind and SQL state rather than constraint name: the production schema is built by Flyway and the test schema by
     * the entity annotations, so generated names differ and matching on them would classify correctly in only one of
     * the two.
     *
     * <p>
     * Hibernate's PostgreSQL dialect reports every constraint violation as kind OTHER, batched or not, so SQL state
     * 23505 is the signal on the supported database; {@link DuplicateKeyException} and the UNIQUE kind cover
     * translators that do classify it.
     */
    public static boolean isUniqueViolation(Throwable throwable) {
        Throwable cause = throwable;
        for (int depth = 0; cause != null && depth < MAX_CAUSE_DEPTH; cause = cause.getCause(), depth++) {
            if (cause instanceof DuplicateKeyException) {
                return true;
            }
            if (cause instanceof ConstraintViolationException constraintViolation
                    && constraintViolation.getKind() == ConstraintViolationException.ConstraintKind.UNIQUE) {
                return true;
            }
            if (cause instanceof SQLException sqlException
                    && UNIQUE_VIOLATION_SQL_STATE.equals(sqlException.getSQLState())) {
                return true;
            }
        }
        return false;
    }
}
