package com.otilm.core.dao.repository.signing;

/**
 * The SQL fragments every statement that removes signing records is wrapped in, so that deleting a record never deletes
 * the fact that the signing happened.
 *
 * <p>
 * A statement is assembled as {@link #OPEN_VICTIM_CTE}, the caller's SELECT naming the rows to delete,
 * {@link #WAIT_FOR_CONTENDED_ROWS} or {@link #SKIP_CONTENDED_ROWS}, and {@link #ROLL_UP_THEN_DELETE}. Each fragment
 * that follows the SELECT opens with its own newline, so the joins never depend on how the caller ended it.
 *
 * <p>
 * PostgreSQL runs a data-modifying CTE exactly once and to completion, and every part of the statement reads the same
 * snapshot of the materialized {@code victim} rows, so the roll-up and the delete cover the identical set and commit
 * together. The statement's own result is the DELETE's row count, so callers still learn how many records were removed.
 */
final class SigningRecordRollupSql {

    /**
     * Opens the {@code victim} CTE; the caller appends the SELECT naming the rows to delete, which must alias
     * {@code signing_record} as {@code sr} and project {@code uuid}, {@code signing_profile_uuid} and
     * {@code signing_time}. Materialized because both halves of the statement read it and must see the same rows — a
     * re-evaluated {@code LIMIT} could pick a different set.
     */
    static final String OPEN_VICTIM_CTE = "WITH victim AS MATERIALIZED (";

    /**
     * Waits for a row another statement holds, then re-reads it: one the winner deleted is not returned. For the keyed
     * delete, whose caller is told the record is gone — skipping a contended row would report success for a record the
     * winner might yet roll back. It locks a single row, so it can wait for a cycle but never form one.
     */
    static final String WAIT_FOR_CONTENDED_ROWS = "\nFOR UPDATE OF sr\n";

    /**
     * Leaves a row another statement holds where it is. For the batch sweeps, which have no per-record contract —
     * whatever a sweep passes over is taken by the statement holding it or by the next sweep. Waiting instead would let
     * two sweeps that pick overlapping victims in different index orders deadlock, or let one open transaction stall a
     * sweep while it holds the cluster-wide sweep lock.
     */
    static final String SKIP_CONTENDED_ROWS = "\nFOR UPDATE OF sr SKIP LOCKED\n";

    /**
     * Rolls the claimed rows into their UTC hourly buckets and deletes them. Only {@code signing_record} rows are
     * locked, so a claim never holds up the signing profile version the batch selectors join.
     *
     * <p>
     * The buckets are inserted in key order. Two sweeps running at once can each carry rows for the same profile and
     * hour, and an unordered grouped upsert would let them take those bucket locks in opposite orders and deadlock.
     */
    static final String ROLL_UP_THEN_DELETE = """
            )
            , bucket AS (
                SELECT victim.signing_profile_uuid AS signing_profile_uuid,
                       date_trunc('hour', victim.signing_time AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket_start,
                       count(*) AS signing_count
                FROM victim
                GROUP BY 1, 2
            )
            , rolled AS (
                INSERT INTO {h-schema}signing_record_volume AS srv
                    (uuid, signing_profile_uuid, bucket_start, signing_count)
                SELECT gen_random_uuid(), bucket.signing_profile_uuid, bucket.bucket_start, bucket.signing_count
                FROM bucket
                ORDER BY bucket.signing_profile_uuid, bucket.bucket_start
                ON CONFLICT (signing_profile_uuid, bucket_start)
                DO UPDATE SET signing_count = srv.signing_count + EXCLUDED.signing_count
            )
            DELETE FROM {h-schema}signing_record WHERE uuid IN (SELECT uuid FROM victim)
            """;

    private SigningRecordRollupSql() {
    }
}
