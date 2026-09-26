CREATE TABLE "key_import"
(
    "uuid"                UUID        NOT NULL PRIMARY KEY,
    "key_reference"       UUID        NOT NULL,
    "idempotency_key"     VARCHAR     NOT NULL,
    "requester_uuid"      UUID        NOT NULL,
    "requester_name"      VARCHAR     NOT NULL,
    "token_instance_uuid" UUID        NOT NULL,
    "token_profile_uuid"  UUID        NOT NULL,
    "key_request_type"    VARCHAR     NOT NULL,
    "key_algorithm"       VARCHAR     NOT NULL,
    "spki_fingerprint"    VARCHAR     NOT NULL,
    "name"                VARCHAR     NOT NULL,
    "exportable"          BOOLEAN     NOT NULL,
    "state"               VARCHAR     NOT NULL,
    "operation_meta"      JSONB,
    "secret_digests"      JSONB       NOT NULL,
    "error_message"       VARCHAR,
    "key_uuid"            UUID,
    "created_at"          TIMESTAMPTZ NOT NULL,
    "updated_at"          TIMESTAMPTZ NOT NULL
);

CREATE INDEX "idx_key_import_idempotency_key" ON "key_import" ("idempotency_key");

-- A key has at most one import whose outcome is still to be learned.
CREATE UNIQUE INDEX "uq_key_import_open_attempt" ON "key_import" ("spki_fingerprint")
    WHERE "state" IN ('REQUESTED', 'ACCEPTED');
