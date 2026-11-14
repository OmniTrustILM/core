package com.otilm.core.dao.repository.ai;

/** Atomic local completion after a trusted caller independently proves the exact workload footprint absent. */
public final class AiRuntimeCleanupSql {
    private AiRuntimeCleanupSql() {
    }

    static final String LOCK_ATTEMPT = """
            SELECT a.uuid FROM {h-schema}ai_runtime_run r
            JOIN {h-schema}ai_runtime_attempt a ON a.uuid=r.current_attempt_uuid AND a.run_uuid=r.uuid
            WHERE r.uuid=:#{#e.runId()} AND a.uuid=:#{#e.attemptId()}
                AND r.revision=:#{#e.runRevision()} AND r.fence=:#{#e.fence()}
            FOR UPDATE OF a
            """;
    static final String LOCK_LAUNCH = """
            SELECT attempt_uuid FROM {h-schema}ai_runtime_launch WHERE attempt_uuid=:attemptId FOR UPDATE
            """;
    private static final String SUPPLIED = """
            WITH supplied AS MATERIALIZED (
                SELECT x.cluster,x."podUid" AS pod_uid
                FROM jsonb_to_recordset(CAST(:workloads AS jsonb)) AS x(cluster TEXT,"podUid" TEXT)
            )
            """;
    private static final String PARENTS = """
            FROM {h-schema}ai_runtime_run r
            JOIN {h-schema}ai_runtime_attempt a ON a.uuid=r.current_attempt_uuid AND a.run_uuid=r.uuid
            JOIN {h-schema}ai_runtime_launch l ON l.attempt_uuid=a.uuid
            """;
    private static final String EXACT = """
            r.uuid=:#{#e.runId()} AND a.uuid=:#{#e.attemptId()}
            AND r.revision=:#{#e.runRevision()} AND r.fence=:#{#e.fence()}
            AND a.state='FENCED' AND l.job_uid=:jobUid
            AND (SELECT count(*) FROM supplied)<=16
            AND NOT EXISTS (
                SELECT w.cluster,w.pod_uid FROM {h-schema}ai_runtime_workload w WHERE w.attempt_uuid=a.uuid
                EXCEPT SELECT cluster,pod_uid FROM supplied
            )
            AND NOT EXISTS (
                SELECT cluster,pod_uid FROM supplied
                EXCEPT SELECT w.cluster,w.pod_uid FROM {h-schema}ai_runtime_workload w WHERE w.attempt_uuid=a.uuid
            )
            AND NOT EXISTS (SELECT 1 FROM {h-schema}ai_runtime_workload w WHERE w.attempt_uuid=a.uuid
                AND (w.cluster<>l.cluster OR w.job_uid<>l.job_uid))
            AND clock_timestamp()<:operationDeadline
            """;
    static final String CURRENT = SUPPLIED + "SELECT l.cleanup_state " + PARENTS + " WHERE " + EXACT + """
            AND (l.cleanup_state='DUE' OR (l.cleanup_state='DONE' AND NOT EXISTS (
                SELECT 1 FROM {h-schema}ai_runtime_workload w WHERE w.attempt_uuid=a.uuid AND w.state<>'CLOSED'
            )))
            """;
    static final String COMPLETE = SUPPLIED + ", valid AS MATERIALIZED (SELECT a.uuid " + PARENTS + " WHERE " + EXACT
            + " AND l.cleanup_state='DUE'), closed AS (" + """
                        UPDATE {h-schema}ai_runtime_workload w SET state='CLOSED',updated_at=:at
                        FROM valid v WHERE w.attempt_uuid=v.uuid RETURNING w.pod_uid
                    )
                    UPDATE {h-schema}ai_runtime_launch l SET cleanup_state='DONE',updated_at=:at
                    FROM valid v WHERE l.attempt_uuid=v.uuid AND l.cleanup_state='DUE'
                        AND (SELECT count(*) FROM closed)=(SELECT count(*) FROM supplied)
                        AND clock_timestamp()<:operationDeadline
                    """;
}
