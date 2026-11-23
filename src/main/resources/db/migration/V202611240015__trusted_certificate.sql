CREATE TABLE "trusted_certificate" (
    "uuid"                      UUID        NOT NULL PRIMARY KEY,
    "certificate_uuid"          UUID        NOT NULL,
    "validation"                BOOLEAN     NOT NULL,
    "platform"                  BOOLEAN     NOT NULL,
    "platform_removal_pending"  BOOLEAN     NOT NULL DEFAULT FALSE,
    "platform_uuid"             VARCHAR(36),
    "platform_state"            TEXT,
    "platform_state_message"    TEXT,
    "platform_state_checked_at" TIMESTAMPTZ,
    "created_at"                TIMESTAMPTZ NOT NULL,
    "updated_at"                TIMESTAMPTZ NOT NULL,
    CONSTRAINT "uq_trusted_certificate_certificate" UNIQUE ("certificate_uuid"),
    CONSTRAINT "fk_trusted_certificate_certificate" FOREIGN KEY ("certificate_uuid")
        REFERENCES "certificate" ("uuid") ON DELETE RESTRICT,
    CONSTRAINT "ck_trusted_certificate_purpose" CHECK ("validation" OR "platform" OR "platform_removal_pending")
);

CREATE TABLE "trusted_certificate_sync" (
    "uuid"                     UUID        NOT NULL PRIMARY KEY,
    "initial_import_done"      BOOLEAN     NOT NULL,
    "last_successful_check_at" TIMESTAMPTZ,
    "last_error"               TEXT
);

INSERT INTO "trusted_certificate_sync" ("uuid", "initial_import_done")
VALUES ('00000000-0000-0000-0000-000000000001', FALSE);

-- Validation trust moves into the new table as it is; trusted_ca stays and is written by the trust service from now on.
INSERT INTO "trusted_certificate" ("uuid", "certificate_uuid", "validation", "platform", "platform_removal_pending",
                                   "created_at", "updated_at")
SELECT gen_random_uuid(), "uuid", TRUE, FALSE, FALSE, now(), now()
FROM "certificate"
WHERE "trusted_ca" = TRUE;
