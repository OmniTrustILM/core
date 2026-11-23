package com.otilm.core.dao.repository.ai;

final class AiRuntimeTransitionSql {
    static final String OPERATION_CUTOFF = " AND clock_timestamp() < :operationDeadline";

    static final String ADMISSION_CURRENT = """
            SELECT EXISTS (
                SELECT 1 FROM {h-schema}ai_runtime_run r
                JOIN {h-schema}ai_runtime_attempt a ON a.uuid = r.current_attempt_uuid AND a.run_uuid = r.uuid
                JOIN {h-schema}ai_runtime_launch l ON l.attempt_uuid = a.uuid
                JOIN {h-schema}ai_runtime_control c ON c.id = 1
                LEFT JOIN {h-schema}ai_runtime_workload w ON w.attempt_uuid = a.uuid
                    AND w.cluster = a.winner_cluster AND w.pod_uid = a.winner_pod_uid
                WHERE r.uuid = :#{#e.runId()} AND a.uuid = :#{#e.attemptId()}
                    AND r.revision = :#{#e.runRevision()} AND r.fence = :#{#e.fence()} AND a.fence = r.fence
                    AND l.cleanup_state = 'NONE' AND clock_timestamp() < LEAST(r.run_deadline, a.max_deadline)
                    AND ((r.state = 'QUEUED' AND a.state = 'LAUNCHING' AND clock_timestamp() < a.launch_deadline)
                        OR (r.state = 'RUNNING' AND a.state = 'CLAIMED' AND w.state = 'REGISTERED'
                            AND a.lease_until <= c.valid_until
                            AND clock_timestamp() < LEAST(a.lease_until, w.observation_valid_until))) AND
            """ + AiRuntimeControlSql.ADMISSION + ")";

    static final String CREATE = """
            WITH decision AS MATERIALIZED (SELECT clock_timestamp() AS at),
            authorized AS MATERIALIZED (
                SELECT c.generation, c.valid_until FROM {h-schema}ai_runtime_control c
                WHERE c.id = 1 AND c.generation = :#{#expected.generation()} AND c.enabled
                    AND c.image_digest = :#{#attempt.imageDigest()} AND c.profile_revision = :#{#attempt.profileRevision()}
                    AND c.security_revision = :#{#attempt.securityRevision()} AND c.trust_revision = :#{#attempt.trustRevision()}
                    AND c.protocol = :#{#attempt.protocol()} AND c.cluster = :#{#attempt.launch().cluster()}
                    AND c.namespace_name = :#{#attempt.launch().namespaceName()}
                    AND c.namespace_uid = :#{#attempt.launch().namespaceUid()}
                    AND c.service_account_name = :#{#attempt.launch().serviceAccountName()}
                    AND c.service_account_uid = :#{#attempt.launch().serviceAccountUid()}
                    AND c.template_digest = :#{#attempt.launch().templateDigest()}
                    AND c.runtime_class = :#{#attempt.launch().runtimeClass()} AND
            """
            + AiRuntimeControlSql.FRESH
            + """
                    ), inserted_run AS (
                        INSERT INTO {h-schema}ai_runtime_run
                            (uuid, conversation_ref, actor_uuid, scope_marker, state, revision, fence, attempts_used,
                             attempt_limit, current_attempt_uuid, run_deadline, lease_seconds, pod_limit,
                             control_generation, created_at, updated_at)
                        SELECT :#{#run.runId()}, CAST(:#{#run.conversationRef().orElse(null)} AS UUID), :#{#run.actorId()},
                            :#{#run.scopeMarker()}, 'QUEUED', 1, 1, 1, :#{#run.attemptLimit()}, :#{#attempt.attemptId()},
                            :#{#run.runDeadline()}, :#{#run.leaseSeconds()}, :#{#run.podLimit()}, control.generation,
                            decision.at, decision.at
                        FROM decision CROSS JOIN authorized control
                        WHERE :#{#run.runDeadline()} > decision.at AND :#{#attempt.launchDeadline()} > decision.at
                            AND :#{#attempt.maxDeadline()} <= :#{#run.runDeadline()}
                            AND :#{#attempt.launchDeadline()} <= :#{#attempt.maxDeadline()}
                            AND clock_timestamp() < control.valid_until
                        RETURNING uuid, control_generation
                    ), inserted_attempt AS (
                        INSERT INTO {h-schema}ai_runtime_attempt
                            (uuid, run_uuid, attempt_no, state, fence, image_digest, profile_revision, security_revision,
                             trust_revision, protocol, launch_deadline, max_deadline, control_generation, created_at, updated_at)
                        SELECT :#{#attempt.attemptId()}, inserted_run.uuid, 1, 'LAUNCHING', 1, :#{#attempt.imageDigest()},
                            :#{#attempt.profileRevision()}, :#{#attempt.securityRevision()}, :#{#attempt.trustRevision()},
                            :#{#attempt.protocol()}, :#{#attempt.launchDeadline()}, :#{#attempt.maxDeadline()},
                            inserted_run.control_generation, decision.at, decision.at
                        FROM inserted_run CROSS JOIN decision CROSS JOIN authorized control
                        WHERE clock_timestamp() < control.valid_until
                        RETURNING uuid
                    )
                    INSERT INTO {h-schema}ai_runtime_launch
                        (attempt_uuid, cluster, namespace_name, namespace_uid, service_account_name, service_account_uid,
                         job_name, template_digest, runtime_class, observation_sequence, cleanup_state, created_at, updated_at)
                    SELECT inserted_attempt.uuid, :#{#attempt.launch().cluster()}, :#{#attempt.launch().namespaceName()},
                        :#{#attempt.launch().namespaceUid()}, :#{#attempt.launch().serviceAccountName()},
                        :#{#attempt.launch().serviceAccountUid()}, 'ilm-ai-' || replace(CAST(inserted_attempt.uuid AS text), '-', ''),
                        :#{#attempt.launch().templateDigest()}, :#{#attempt.launch().runtimeClass()}, 0, 'NONE',
                        decision.at, decision.at
                    FROM inserted_attempt CROSS JOIN decision CROSS JOIN authorized control
                    WHERE clock_timestamp() < LEAST(:#{#run.runDeadline()}, :#{#attempt.launchDeadline()},
                        :#{#attempt.maxDeadline()}, control.valid_until)
                    """;

    static final String OBSERVE = """
            WITH updated_run AS (
                UPDATE {h-schema}ai_runtime_run r
                SET revision = r.revision + 1, updated_at = :at
                FROM {h-schema}ai_runtime_attempt a
                JOIN {h-schema}ai_runtime_launch l ON l.attempt_uuid = a.uuid
                JOIN {h-schema}ai_runtime_control c ON c.id = 1
                LEFT JOIN {h-schema}ai_runtime_workload existing
                    ON existing.cluster = :#{#o.cluster()} AND existing.pod_uid = :#{#o.podUid()}
                WHERE
            """ + AiRuntimeControlSql.ADMISSION + """
                    AND r.uuid = :#{#o.expected().runId()}
                    AND r.current_attempt_uuid = :#{#o.expected().attemptId()}
                    AND r.revision = :#{#o.expected().runRevision()} AND r.fence = :#{#o.expected().fence()}
                    AND a.uuid = r.current_attempt_uuid AND a.run_uuid = r.uuid AND a.fence = r.fence
                    AND ((r.state = 'QUEUED' AND a.state = 'LAUNCHING')
                        OR (r.state = 'RUNNING' AND a.state = 'CLAIMED'))
                    AND a.image_digest = :#{#o.imageDigest()} AND a.profile_revision = :#{#o.profileRevision()}
                    AND a.security_revision = :#{#o.securityRevision()} AND a.trust_revision = :#{#o.trustRevision()}
                    AND a.protocol = :#{#o.protocol()} AND l.cluster = :#{#o.cluster()}
                    AND l.namespace_name = :#{#o.namespaceName()} AND l.namespace_uid = :#{#o.namespaceUid()}
                    AND l.service_account_name = :#{#o.serviceAccountName()}
                    AND l.service_account_uid = :#{#o.serviceAccountUid()} AND l.job_name = :#{#o.jobName()}
                    AND l.template_digest = :#{#o.templateDigest()} AND l.runtime_class = :#{#o.runtimeClass()}
                    AND l.cleanup_state = 'NONE' AND (l.job_uid IS NULL OR l.job_uid = :#{#o.jobUid()})
                    AND :#{#o.validUntil()} <= a.max_deadline AND :#{#o.validUntil()} <= r.run_deadline
                    AND clock_timestamp() < LEAST(r.run_deadline, a.max_deadline, :#{#o.validUntil()},
                        CASE WHEN a.state = 'LAUNCHING' THEN a.launch_deadline ELSE a.lease_until END,
                        CASE WHEN existing.state = 'REGISTERED' THEN a.max_deadline ELSE a.launch_deadline END)
                    AND ((existing.pod_uid IS NOT NULL AND existing.attempt_uuid = a.uuid
                            AND existing.pod_name = :#{#o.podName()} AND existing.job_uid = :#{#o.jobUid()}
                            AND existing.state IN ('ELIGIBLE', 'REGISTERED')
                            AND (existing.state <> 'REGISTERED' OR :#{#o.registered()})
                            AND existing.observation_sequence < :#{#o.sequence()})
                        OR (existing.pod_uid IS NULL AND (
                            SELECT count(*) FROM {h-schema}ai_runtime_workload reserved
                            JOIN {h-schema}ai_runtime_attempt reserved_attempt
                                ON reserved_attempt.uuid = reserved.attempt_uuid
                            JOIN {h-schema}ai_runtime_launch reserved_launch
                                ON reserved_launch.attempt_uuid = reserved_attempt.uuid
                            WHERE reserved_attempt.run_uuid = r.uuid AND reserved_launch.cleanup_state <> 'DONE'
                        ) < r.pod_limit))
                RETURNING r.current_attempt_uuid,
                    LEAST(c.valid_until, r.run_deadline, a.max_deadline, :#{#o.validUntil()},
                        CASE WHEN a.state = 'LAUNCHING' THEN a.launch_deadline ELSE a.lease_until END,
                        CASE WHEN existing.state = 'REGISTERED' THEN a.max_deadline ELSE a.launch_deadline END)
                        AS authority_deadline
            ), updated_launch AS (
                UPDATE {h-schema}ai_runtime_launch l
                SET job_uid = COALESCE(l.job_uid, :#{#o.jobUid()}),
                    observation_sequence = GREATEST(l.observation_sequence, :#{#o.sequence()}), updated_at = :at
                FROM updated_run parent
                WHERE l.attempt_uuid = parent.current_attempt_uuid
                    AND (l.job_uid IS NULL OR l.job_uid = :#{#o.jobUid()})
                    AND clock_timestamp() < parent.authority_deadline
                RETURNING l.attempt_uuid, parent.authority_deadline
            )
            INSERT INTO {h-schema}ai_runtime_workload AS stored
                (cluster, pod_uid, attempt_uuid, pod_name, job_uid, state, observation_sequence,
                 observation_valid_until, pending_returns, created_at, updated_at)
            SELECT :#{#o.cluster()}, :#{#o.podUid()}, parent.attempt_uuid, :#{#o.podName()}, :#{#o.jobUid()},
                CASE WHEN :#{#o.registered()} THEN 'REGISTERED' ELSE 'ELIGIBLE' END,
                :#{#o.sequence()}, :#{#o.validUntil()}, 0, :at, :at
            FROM updated_launch parent
            WHERE clock_timestamp() < parent.authority_deadline
            ON CONFLICT (cluster, pod_uid) DO UPDATE
            SET state = CASE WHEN stored.state = 'REGISTERED' OR excluded.state = 'REGISTERED'
                    THEN 'REGISTERED' ELSE 'ELIGIBLE' END,
                observation_sequence = excluded.observation_sequence,
                observation_valid_until = excluded.observation_valid_until, updated_at = excluded.updated_at
            WHERE stored.attempt_uuid = excluded.attempt_uuid AND stored.pod_name = excluded.pod_name
                AND stored.job_uid = excluded.job_uid AND stored.state IN ('ELIGIBLE', 'REGISTERED')
                AND (stored.state <> 'REGISTERED' OR excluded.state = 'REGISTERED')
                AND stored.observation_sequence < excluded.observation_sequence
                AND clock_timestamp() < (SELECT authority_deadline FROM updated_launch)
            """;

    static final String CLAIM = """
            WITH updated_run AS (
                UPDATE {h-schema}ai_runtime_run r
                SET state = 'RUNNING', revision = r.revision + 1, updated_at = :at
                FROM {h-schema}ai_runtime_attempt a
                JOIN {h-schema}ai_runtime_launch l ON l.attempt_uuid = a.uuid
                JOIN {h-schema}ai_runtime_control c ON c.id = 1
                JOIN {h-schema}ai_runtime_workload w ON w.attempt_uuid = a.uuid
                    AND w.cluster = l.cluster AND w.job_uid = l.job_uid
                WHERE
            """ + AiRuntimeControlSql.ADMISSION + """
                    AND r.uuid = :#{#e.runId()} AND r.current_attempt_uuid = :#{#e.attemptId()}
                    AND r.revision = :#{#e.runRevision()} AND r.fence = :#{#e.fence()}
                    AND r.state = 'QUEUED' AND a.uuid = r.current_attempt_uuid AND a.run_uuid = r.uuid
                    AND a.state = 'LAUNCHING' AND a.fence = r.fence AND a.claim_uuid IS NULL
                    AND l.cleanup_state = 'NONE' AND w.cluster = :#{#w.cluster()} AND w.pod_uid = :#{#w.podUid()}
                    AND w.state = 'REGISTERED' AND w.bootstrap_consumed_at IS NULL
                    AND clock_timestamp() < LEAST(r.run_deadline, a.max_deadline, a.launch_deadline,
                        w.observation_valid_until, COALESCE(w.pending_deadline, a.launch_deadline))
                    AND :leaseUntil <= LEAST(c.valid_until, r.run_deadline, a.max_deadline,
                        CAST(:at AS timestamptz) + r.lease_seconds * interval '1 second')
                    AND clock_timestamp() < :leaseUntil
                RETURNING r.uuid, r.current_attempt_uuid, r.fence,
                    LEAST(c.valid_until, r.run_deadline, a.max_deadline, a.launch_deadline, w.observation_valid_until,
                        COALESCE(w.pending_deadline, a.launch_deadline)) AS authority_deadline
            ), claimed_attempt AS (
                UPDATE {h-schema}ai_runtime_attempt a
                SET state = 'CLAIMED', winner_cluster = :#{#w.cluster()}, winner_pod_uid = :#{#w.podUid()},
                    claim_uuid = :claimId, lease_until = :leaseUntil, last_heartbeat_sequence = 0,
                    last_heartbeat_lease = :leaseUntil, updated_at = :at
                FROM updated_run parent
                WHERE a.uuid = parent.current_attempt_uuid AND a.run_uuid = parent.uuid
                    AND a.fence = parent.fence AND a.state = 'LAUNCHING' AND a.claim_uuid IS NULL
                    AND clock_timestamp() < parent.authority_deadline AND clock_timestamp() < :leaseUntil
                RETURNING a.uuid, parent.authority_deadline
            )
            UPDATE {h-schema}ai_runtime_workload w
            SET bootstrap_consumed_at = :at, updated_at = :at
            FROM claimed_attempt parent
            WHERE w.attempt_uuid = parent.uuid AND w.cluster = :#{#w.cluster()} AND w.pod_uid = :#{#w.podUid()}
                AND w.state = 'REGISTERED' AND w.bootstrap_consumed_at IS NULL
                AND clock_timestamp() < parent.authority_deadline AND clock_timestamp() < :leaseUntil
            """;

    static final String PENDING = """
            WITH updated_run AS (
                UPDATE {h-schema}ai_runtime_run r
                SET revision = r.revision + 1, updated_at = :at
                FROM {h-schema}ai_runtime_attempt a
                JOIN {h-schema}ai_runtime_launch l ON l.attempt_uuid = a.uuid
                JOIN {h-schema}ai_runtime_control c ON c.id = 1
                JOIN {h-schema}ai_runtime_workload w ON w.attempt_uuid = a.uuid
                    AND w.cluster = l.cluster AND w.job_uid = l.job_uid
                WHERE
            """ + AiRuntimeControlSql.ADMISSION
            + """
                            AND r.uuid = :#{#e.runId()} AND r.current_attempt_uuid = :#{#e.attemptId()}
                            AND r.revision = :#{#e.runRevision()} AND r.fence = :#{#e.fence()}
                            AND r.state = 'QUEUED' AND a.uuid = r.current_attempt_uuid AND a.run_uuid = r.uuid
                            AND a.state = 'LAUNCHING' AND a.fence = r.fence AND a.claim_uuid IS NULL
                            AND l.cleanup_state = 'NONE' AND w.cluster = :#{#w.cluster()} AND w.pod_uid = :#{#w.podUid()}
                            AND w.state = 'ELIGIBLE' AND w.bootstrap_consumed_at IS NULL AND w.pending_returns < 11
                            AND COALESCE(w.pending_deadline, :pendingDeadline)
                                <= LEAST(a.launch_deadline, a.max_deadline, r.run_deadline)
                            AND ((w.pending_returns = 0 AND :pendingDeadline <= CAST(:at AS timestamptz) + interval '30 seconds')
                                OR (w.pending_returns > 0 AND w.pending_deadline <= w.first_pending_at + interval '30 seconds'))
                            AND clock_timestamp() < LEAST(r.run_deadline, a.max_deadline, a.launch_deadline,
                                w.observation_valid_until, COALESCE(w.pending_deadline, :pendingDeadline))
                        RETURNING r.current_attempt_uuid, w.pending_returns,
                            COALESCE(w.first_pending_at, :at) AS first_pending_at,
                            COALESCE(w.pending_deadline, :pendingDeadline) AS pending_deadline,
                            LEAST(c.valid_until, r.run_deadline, a.max_deadline, a.launch_deadline, w.observation_valid_until,
                                COALESCE(w.pending_deadline, :pendingDeadline)) AS authority_deadline
                    )
                    UPDATE {h-schema}ai_runtime_workload w
                    SET first_pending_at = parent.first_pending_at, pending_deadline = parent.pending_deadline,
                        pending_returns = w.pending_returns + 1, updated_at = :at
                    FROM updated_run parent
                    WHERE w.attempt_uuid = parent.current_attempt_uuid
                        AND w.cluster = :#{#w.cluster()} AND w.pod_uid = :#{#w.podUid()}
                        AND w.state = 'ELIGIBLE' AND w.bootstrap_consumed_at IS NULL
                        AND w.pending_returns = parent.pending_returns AND w.pending_returns < 11
                        AND clock_timestamp() < parent.authority_deadline
                    """;

    static final String HEARTBEAT = """
            WITH updated_run AS (
                UPDATE {h-schema}ai_runtime_run r
                SET revision = r.revision + 1, updated_at = :at
                FROM {h-schema}ai_runtime_attempt a
                JOIN {h-schema}ai_runtime_launch l ON l.attempt_uuid = a.uuid
                JOIN {h-schema}ai_runtime_control c ON c.id = 1
                JOIN {h-schema}ai_runtime_workload w ON w.attempt_uuid = a.uuid
                    AND w.cluster = l.cluster AND w.job_uid = l.job_uid
                WHERE
            """ + AiRuntimeControlSql.ADMISSION
            + """
                            AND r.uuid = :#{#e.runId()} AND r.uuid = :#{#b.runId()}
                            AND r.current_attempt_uuid = :#{#e.attemptId()} AND r.current_attempt_uuid = :#{#b.attemptId()}
                            AND r.revision = :#{#e.runRevision()} AND r.fence = :#{#e.fence()} AND r.fence = :#{#b.fence()}
                            AND r.state = 'RUNNING' AND a.uuid = r.current_attempt_uuid AND a.run_uuid = r.uuid
                            AND a.state = 'CLAIMED' AND a.fence = r.fence AND a.claim_uuid = :#{#b.claimId()}
                            AND a.winner_cluster = :#{#b.workload().cluster()} AND a.winner_pod_uid = :#{#b.workload().podUid()}
                            AND w.cluster = a.winner_cluster AND w.pod_uid = a.winner_pod_uid
                            AND w.state = 'REGISTERED' AND w.bootstrap_consumed_at IS NOT NULL AND l.cleanup_state = 'NONE'
                            AND :sequence > a.last_heartbeat_sequence
                            AND clock_timestamp() < LEAST(r.run_deadline, a.max_deadline, a.lease_until, w.observation_valid_until)
                            AND :leaseUntil >= a.lease_until
                            AND :leaseUntil <= LEAST(c.valid_until, r.run_deadline, a.max_deadline,
                                CAST(:at AS timestamptz) + r.lease_seconds * interval '1 second')
                            AND clock_timestamp() < :leaseUntil
                        RETURNING r.uuid, r.current_attempt_uuid, r.fence,
                            LEAST(c.valid_until, r.run_deadline, a.max_deadline, a.lease_until,
                                w.observation_valid_until) AS authority_deadline
                    )
                    UPDATE {h-schema}ai_runtime_attempt a
                    SET lease_until = :leaseUntil, last_heartbeat_sequence = :sequence,
                        last_heartbeat_lease = :leaseUntil, updated_at = :at
                    FROM updated_run parent
                    WHERE a.uuid = parent.current_attempt_uuid AND a.run_uuid = parent.uuid AND a.fence = parent.fence
                        AND a.state = 'CLAIMED' AND a.claim_uuid = :#{#b.claimId()}
                        AND a.winner_cluster = :#{#b.workload().cluster()} AND a.winner_pod_uid = :#{#b.workload().podUid()}
                        AND :sequence > a.last_heartbeat_sequence
                        AND clock_timestamp() < parent.authority_deadline AND clock_timestamp() < :leaseUntil
                    """;

    static final String FENCE = """
            WITH updated_run AS (
                UPDATE {h-schema}ai_runtime_run r
                SET state = :#{#state.name()}, revision = r.revision + 1, fence = r.fence + 1, updated_at = :at
                FROM {h-schema}ai_runtime_attempt a
                WHERE r.uuid = :#{#e.runId()} AND r.current_attempt_uuid = :#{#e.attemptId()}
                    AND r.revision = :#{#e.runRevision()} AND r.fence = :#{#e.fence()}
                    AND r.state IN ('QUEUED', 'RUNNING') AND a.uuid = r.current_attempt_uuid AND a.run_uuid = r.uuid
                    AND :#{#state.name()} IN ('QUEUED', 'FAILED', 'CANCELLED', 'LIMIT_REACHED')
                    AND a.state IN ('LAUNCHING', 'CLAIMED') AND a.fence = r.fence
                RETURNING r.uuid, r.current_attempt_uuid
            ), fenced_attempt AS (
                UPDATE {h-schema}ai_runtime_attempt a
                SET state = 'FENCED', failure_reason = :#{#reason.name()}, updated_at = :at
                FROM updated_run parent
                WHERE a.uuid = parent.current_attempt_uuid AND a.run_uuid = parent.uuid
                RETURNING a.uuid
            ), closed_workloads AS (
                UPDATE {h-schema}ai_runtime_workload w
                SET state = 'CLOSED', updated_at = :at
                FROM fenced_attempt parent
                WHERE w.attempt_uuid = parent.uuid
                RETURNING w.attempt_uuid
            )
            UPDATE {h-schema}ai_runtime_launch l
            SET cleanup_state = 'DUE', updated_at = :at
            FROM fenced_attempt parent
            WHERE l.attempt_uuid = parent.uuid
            """;

    static final String TERMINATE_FENCED = """
            UPDATE {h-schema}ai_runtime_run r
            SET state = :#{#state.name()}, revision = r.revision + 1, fence = r.fence + 1, updated_at = :at
            FROM {h-schema}ai_runtime_attempt a
            WHERE r.uuid = :#{#e.runId()} AND r.current_attempt_uuid = :#{#e.attemptId()}
                AND r.revision = :#{#e.runRevision()} AND r.fence = :#{#e.fence()} AND r.state = 'QUEUED'
                AND a.uuid = r.current_attempt_uuid AND a.run_uuid = r.uuid AND a.state = 'FENCED'
                AND (:#{#state.name()} IN ('CANCELLED', 'FAILED')
                    OR (:#{#state.name()} = 'LIMIT_REACHED'
                        AND (r.attempts_used >= r.attempt_limit OR r.run_deadline <= clock_timestamp())))
            """;

    static final String REPLACE = """
            WITH updated_run AS (
                UPDATE {h-schema}ai_runtime_run r
                SET current_attempt_uuid = :#{#next.attemptId()}, attempts_used = r.attempts_used + 1,
                    revision = r.revision + 1, fence = r.fence + 1, updated_at = :at
                FROM {h-schema}ai_runtime_attempt a
                JOIN {h-schema}ai_runtime_launch l ON l.attempt_uuid = a.uuid
                JOIN {h-schema}ai_runtime_control c ON c.id = 1
                WHERE
            """ + AiRuntimeControlSql.ADMISSION
            + """
                            AND r.uuid = :#{#e.runId()} AND r.current_attempt_uuid = :#{#e.attemptId()}
                            AND r.revision = :#{#e.runRevision()} AND r.fence = :#{#e.fence()} AND r.state = 'QUEUED'
                            AND a.uuid = r.current_attempt_uuid AND a.run_uuid = r.uuid
                            AND a.state = 'FENCED' AND a.attempt_no = r.attempts_used
                            AND a.failure_reason IN ('LAUNCH_EXPIRED', 'LEASE_EXPIRED',
                                'PENDING_EXHAUSTED', 'OBSERVATION_EXPIRED')
                            AND r.attempts_used < r.attempt_limit AND :#{#next.attemptId()} <> a.uuid
                            AND (SELECT count(*) FROM {h-schema}ai_runtime_workload reserved
                                JOIN {h-schema}ai_runtime_attempt reserved_attempt ON reserved_attempt.uuid = reserved.attempt_uuid
                                JOIN {h-schema}ai_runtime_launch reserved_launch ON reserved_launch.attempt_uuid = reserved_attempt.uuid
                                WHERE reserved_attempt.run_uuid = r.uuid AND reserved_launch.cleanup_state <> 'DONE') < r.pod_limit
                            AND NOT EXISTS (SELECT 1 FROM {h-schema}ai_runtime_attempt recorded
                                WHERE recorded.uuid = :#{#next.attemptId()})
                            AND a.image_digest = :#{#next.imageDigest()}
                            AND a.profile_revision = :#{#next.profileRevision()}
                            AND a.security_revision = :#{#next.securityRevision()}
                            AND a.trust_revision = :#{#next.trustRevision()} AND a.protocol = :#{#next.protocol()}
                            AND l.cluster = :#{#next.launch().cluster()}
                            AND l.namespace_name = :#{#next.launch().namespaceName()}
                            AND l.namespace_uid = :#{#next.launch().namespaceUid()}
                            AND l.service_account_name = :#{#next.launch().serviceAccountName()}
                            AND l.service_account_uid = :#{#next.launch().serviceAccountUid()}
                            AND l.template_digest = :#{#next.launch().templateDigest()}
                            AND l.runtime_class = :#{#next.launch().runtimeClass()}
                            AND :#{#next.launchDeadline()} <= :#{#next.maxDeadline()}
                            AND :#{#next.maxDeadline()} <= r.run_deadline
                            AND clock_timestamp() < LEAST(r.run_deadline,
                                :#{#next.launchDeadline()}, :#{#next.maxDeadline()})
                        RETURNING r.uuid, r.current_attempt_uuid, r.fence, r.attempts_used, r.run_deadline,
                            r.control_generation, c.valid_until AS control_deadline,
                            a.image_digest, a.profile_revision, a.security_revision,
                            a.trust_revision, a.protocol, l.cluster, l.namespace_name,
                            l.namespace_uid, l.service_account_name, l.service_account_uid,
                            l.template_digest, l.runtime_class
                    ), inserted_attempt AS (
                        INSERT INTO {h-schema}ai_runtime_attempt
                            (uuid, run_uuid, attempt_no, state, fence, image_digest, profile_revision,
                             security_revision, trust_revision, protocol, launch_deadline, max_deadline,
                             control_generation, created_at, updated_at)
                        SELECT parent.current_attempt_uuid, parent.uuid, parent.attempts_used, 'LAUNCHING', parent.fence,
                            parent.image_digest, parent.profile_revision, parent.security_revision, parent.trust_revision,
                            parent.protocol, :#{#next.launchDeadline()}, :#{#next.maxDeadline()}, parent.control_generation, :at, :at
                        FROM updated_run parent
                        WHERE clock_timestamp() < LEAST(parent.control_deadline, parent.run_deadline,
                            :#{#next.launchDeadline()}, :#{#next.maxDeadline()})
                        RETURNING uuid, run_uuid, launch_deadline, max_deadline
                    )
                    INSERT INTO {h-schema}ai_runtime_launch
                        (attempt_uuid, cluster, namespace_name, namespace_uid, service_account_name, service_account_uid,
                         job_name, template_digest, runtime_class, observation_sequence, cleanup_state, created_at, updated_at)
                    SELECT attempt.uuid, parent.cluster, parent.namespace_name, parent.namespace_uid,
                        parent.service_account_name, parent.service_account_uid,
                        'ilm-ai-' || replace(CAST(attempt.uuid AS text), '-', ''), parent.template_digest,
                        parent.runtime_class, 0, 'NONE', :at, :at
                    FROM inserted_attempt attempt
                    JOIN updated_run parent ON parent.uuid = attempt.run_uuid
                        AND parent.current_attempt_uuid = attempt.uuid
                    WHERE clock_timestamp() < LEAST(parent.control_deadline, parent.run_deadline,
                        attempt.launch_deadline, attempt.max_deadline)
                    """;

    private AiRuntimeTransitionSql() {
    }
}
