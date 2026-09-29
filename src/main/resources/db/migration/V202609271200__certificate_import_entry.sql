CREATE TABLE "certificate_import_entry" (
    "uuid"             UUID         NOT NULL PRIMARY KEY,
    "requester_uuid"   UUID         NOT NULL,
    "import_id"        VARCHAR(256) NOT NULL,
    "digest"           VARCHAR(64)  NOT NULL,
    "state"            VARCHAR(16)  NOT NULL,
    "certificate_uuid" UUID,
    "key_uuid"         UUID,
    "created_at"       TIMESTAMPTZ  NOT NULL,
    "updated_at"       TIMESTAMPTZ  NOT NULL,
    CONSTRAINT "uq_certificate_import_entry" UNIQUE ("requester_uuid", "import_id")
);
