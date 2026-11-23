CREATE SCHEMA IF NOT EXISTS f07_proof;
CREATE TABLE IF NOT EXISTS f07_proof.conversation (
    uuid UUID PRIMARY KEY, owner_uuid UUID NOT NULL, ra_profile_uuid UUID NOT NULL,
    scope_revision BIGINT NOT NULL CHECK (scope_revision >= 1), next_ordinal BIGINT NOT NULL CHECK (next_ordinal >= 0),
    title VARCHAR(80) NOT NULL, last_run_uuid UUID
);
CREATE TABLE IF NOT EXISTS f07_proof.retained_certificate (
    conversation_uuid UUID NOT NULL REFERENCES f07_proof.conversation(uuid) ON DELETE CASCADE,
    certificate_uuid UUID NOT NULL, PRIMARY KEY(conversation_uuid, certificate_uuid)
);
CREATE TABLE IF NOT EXISTS f07_proof.run_record (
    uuid UUID PRIMARY KEY, conversation_uuid UUID NOT NULL REFERENCES f07_proof.conversation(uuid),
    state VARCHAR(16) NOT NULL CHECK (state IN ('QUEUED','RUNNING','COMPLETE','CANCELLED')),
    UNIQUE(conversation_uuid, uuid)
);
CREATE UNIQUE INDEX IF NOT EXISTS f07_one_active_run ON f07_proof.run_record(conversation_uuid)
    WHERE state IN ('QUEUED','RUNNING');
CREATE TABLE IF NOT EXISTS f07_proof.command_record (
    actor_uuid UUID NOT NULL, conversation_uuid UUID NOT NULL REFERENCES f07_proof.conversation(uuid),
    command_key VARCHAR(128) NOT NULL CHECK (command_key ~ '^[!-~]+$'),
    kind VARCHAR(16) NOT NULL CHECK (kind IN ('START','FOLLOW_UP','CANCEL')),
    body_digest VARCHAR(64) NOT NULL CHECK (body_digest ~ '^[0-9a-f]{64}$'),
    target_run_uuid UUID, run_uuid UUID NOT NULL,
    PRIMARY KEY(actor_uuid, conversation_uuid, command_key),
    FOREIGN KEY(conversation_uuid, run_uuid) REFERENCES f07_proof.run_record(conversation_uuid, uuid),
    CHECK ((kind = 'CANCEL') = (target_run_uuid IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS f07_proof.timeline_event (
    cursor_uuid UUID PRIMARY KEY, conversation_uuid UUID NOT NULL, ordinal BIGINT NOT NULL CHECK (ordinal >= 1),
    run_uuid UUID NOT NULL, value TEXT NOT NULL CHECK (octet_length(value) <= 30000),
    cursor_expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE(conversation_uuid, ordinal),
    FOREIGN KEY(conversation_uuid, run_uuid) REFERENCES f07_proof.run_record(conversation_uuid, uuid)
);
