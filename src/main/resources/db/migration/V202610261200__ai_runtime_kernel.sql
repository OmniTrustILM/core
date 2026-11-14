CREATE TABLE ai_runtime_run
(
    uuid                 UUID        NOT NULL PRIMARY KEY,
    conversation_ref     UUID,
    actor_uuid           UUID        NOT NULL,
    scope_marker         VARCHAR(64) NOT NULL CHECK (btrim(scope_marker) <> ''),
    state                VARCHAR(24) NOT NULL CHECK (state IN ('QUEUED', 'RUNNING', 'FAILED', 'CANCELLED', 'LIMIT_REACHED')),
    revision             BIGINT      NOT NULL CHECK (revision >= 1),
    fence                BIGINT      NOT NULL CHECK (fence >= 1),
    attempts_used        INTEGER     NOT NULL CHECK (attempts_used >= 1),
    attempt_limit        INTEGER     NOT NULL CHECK (attempt_limit BETWEEN 1 AND 10 AND attempts_used <= attempt_limit),
    current_attempt_uuid UUID        NOT NULL,
    run_deadline         TIMESTAMPTZ NOT NULL,
    lease_seconds        INTEGER     NOT NULL CHECK (lease_seconds BETWEEN 1 AND 60),
    pod_limit            INTEGER     NOT NULL CHECK (pod_limit BETWEEN 2 AND 16),
    created_at           TIMESTAMPTZ NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX uq_ai_runtime_live_conversation ON ai_runtime_run (conversation_ref)
    WHERE conversation_ref IS NOT NULL AND state IN ('QUEUED', 'RUNNING');

CREATE TABLE ai_runtime_attempt
(
    uuid                    UUID         NOT NULL PRIMARY KEY,
    run_uuid                UUID         NOT NULL REFERENCES ai_runtime_run (uuid),
    attempt_no              INTEGER      NOT NULL CHECK (attempt_no BETWEEN 1 AND 10),
    state                   VARCHAR(24)  NOT NULL CHECK (state IN ('LAUNCHING', 'CLAIMED', 'FENCED')),
    failure_reason          VARCHAR(32)  CHECK (failure_reason IN ('LAUNCH_EXPIRED', 'LEASE_EXPIRED', 'PENDING_EXHAUSTED',
                                            'OBSERVATION_EXPIRED', 'JOB_CONFLICT', 'CANCELLED', 'INVALIDATED')),
    fence                   BIGINT       NOT NULL CHECK (fence >= 1),
    image_digest            VARCHAR(71)  NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    profile_revision        BIGINT       NOT NULL CHECK (profile_revision >= 1),
    security_revision       BIGINT       NOT NULL CHECK (security_revision >= 1),
    trust_revision          BIGINT       NOT NULL CHECK (trust_revision >= 1),
    protocol                VARCHAR(16)  NOT NULL CHECK (protocol = 'v1'),
    launch_deadline         TIMESTAMPTZ  NOT NULL,
    max_deadline            TIMESTAMPTZ  NOT NULL CHECK (launch_deadline <= max_deadline),
    winner_cluster          VARCHAR(128),
    winner_pod_uid          VARCHAR(128),
    claim_uuid              UUID         UNIQUE,
    lease_until             TIMESTAMPTZ,
    last_heartbeat_sequence BIGINT       CHECK (last_heartbeat_sequence >= 0),
    last_heartbeat_lease    TIMESTAMPTZ,
    created_at              TIMESTAMPTZ  NOT NULL,
    updated_at              TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uq_ai_runtime_attempt_number UNIQUE (run_uuid, attempt_no),
    CONSTRAINT uq_ai_runtime_attempt_run_uuid UNIQUE (run_uuid, uuid),
    CONSTRAINT ck_ai_runtime_claim_fields CHECK (
        (winner_cluster IS NULL AND winner_pod_uid IS NULL AND claim_uuid IS NULL AND lease_until IS NULL
            AND last_heartbeat_sequence IS NULL AND last_heartbeat_lease IS NULL)
        OR (winner_cluster IS NOT NULL AND btrim(winner_cluster) <> ''
            AND winner_pod_uid IS NOT NULL AND btrim(winner_pod_uid) <> '' AND claim_uuid IS NOT NULL
            AND lease_until IS NOT NULL AND last_heartbeat_sequence IS NOT NULL AND last_heartbeat_lease IS NOT NULL
            AND lease_until = last_heartbeat_lease AND lease_until <= max_deadline)),
    CONSTRAINT ck_ai_runtime_attempt_claim_state CHECK (
        (state = 'LAUNCHING' AND claim_uuid IS NULL AND failure_reason IS NULL)
        OR (state = 'CLAIMED' AND claim_uuid IS NOT NULL AND failure_reason IS NULL)
        OR (state = 'FENCED' AND failure_reason IS NOT NULL))
);

CREATE UNIQUE INDEX uq_ai_runtime_live_attempt ON ai_runtime_attempt (run_uuid)
    WHERE state IN ('LAUNCHING', 'CLAIMED');

ALTER TABLE ai_runtime_run
    ADD CONSTRAINT fk_ai_runtime_current_attempt FOREIGN KEY (uuid, current_attempt_uuid)
        REFERENCES ai_runtime_attempt (run_uuid, uuid) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE ai_runtime_launch
(
    attempt_uuid         UUID         NOT NULL PRIMARY KEY REFERENCES ai_runtime_attempt (uuid),
    cluster              VARCHAR(128) NOT NULL CHECK (btrim(cluster) <> ''),
    namespace_name       VARCHAR(63)  NOT NULL CHECK (btrim(namespace_name) <> ''),
    namespace_uid        VARCHAR(128) NOT NULL CHECK (btrim(namespace_uid) <> ''),
    service_account_name VARCHAR(253) NOT NULL CHECK (btrim(service_account_name) <> ''),
    service_account_uid  VARCHAR(128) NOT NULL CHECK (btrim(service_account_uid) <> ''),
    job_name             VARCHAR(63)  NOT NULL CHECK (job_name = 'ilm-ai-' || replace(attempt_uuid::text, '-', '')),
    template_digest      VARCHAR(71)  NOT NULL CHECK (template_digest ~ '^sha256:[0-9a-f]{64}$'),
    runtime_class        VARCHAR(253) NOT NULL CHECK (btrim(runtime_class) <> ''),
    job_uid              VARCHAR(128) CHECK (btrim(job_uid) <> ''),
    observation_sequence BIGINT       NOT NULL CHECK (observation_sequence >= 0),
    cleanup_state        VARCHAR(16)  NOT NULL CHECK (cleanup_state IN ('NONE', 'DUE', 'DONE')),
    created_at           TIMESTAMPTZ  NOT NULL,
    updated_at           TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uq_ai_runtime_launch_name UNIQUE (cluster, namespace_uid, job_name),
    CONSTRAINT uq_ai_runtime_launch_cluster UNIQUE (attempt_uuid, cluster)
);

CREATE TABLE ai_runtime_workload
(
    cluster                 VARCHAR(128) NOT NULL CHECK (btrim(cluster) <> ''),
    pod_uid                 VARCHAR(128) NOT NULL CHECK (btrim(pod_uid) <> ''),
    attempt_uuid            UUID         NOT NULL,
    pod_name                VARCHAR(253) NOT NULL CHECK (btrim(pod_name) <> ''),
    job_uid                 VARCHAR(128) NOT NULL CHECK (btrim(job_uid) <> ''),
    state                   VARCHAR(16)  NOT NULL CHECK (state IN ('ELIGIBLE', 'REGISTERED', 'CLOSED')),
    observation_sequence    BIGINT       NOT NULL CHECK (observation_sequence > 0),
    observation_valid_until TIMESTAMPTZ  NOT NULL,
    first_pending_at        TIMESTAMPTZ,
    pending_deadline        TIMESTAMPTZ,
    pending_returns         INTEGER      NOT NULL DEFAULT 0 CHECK (pending_returns BETWEEN 0 AND 11),
    bootstrap_consumed_at   TIMESTAMPTZ,
    created_at              TIMESTAMPTZ  NOT NULL,
    updated_at              TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (cluster, pod_uid),
    CONSTRAINT uq_ai_runtime_workload_attempt UNIQUE (attempt_uuid, cluster, pod_uid),
    CONSTRAINT fk_ai_runtime_workload_launch FOREIGN KEY (attempt_uuid, cluster)
        REFERENCES ai_runtime_launch (attempt_uuid, cluster),
    CONSTRAINT ck_ai_runtime_pending CHECK (
        (pending_returns = 0 AND first_pending_at IS NULL AND pending_deadline IS NULL)
        OR (pending_returns > 0 AND first_pending_at IS NOT NULL AND pending_deadline IS NOT NULL
            AND first_pending_at <= pending_deadline))
);

ALTER TABLE ai_runtime_attempt
    ADD CONSTRAINT fk_ai_runtime_winner FOREIGN KEY (uuid, winner_cluster, winner_pod_uid)
        REFERENCES ai_runtime_workload (attempt_uuid, cluster, pod_uid) DEFERRABLE INITIALLY DEFERRED;
