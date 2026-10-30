CREATE TABLE "comment"
(
    "uuid"                 UUID        NOT NULL PRIMARY KEY,
    "resource"             TEXT        NOT NULL,
    "object_uuid"          UUID        NOT NULL,
    "parent_uuid"          UUID        NULL,
    "author_uuid"          UUID        NOT NULL,
    "author_username"      TEXT        NOT NULL,
    "created_at"           TIMESTAMPTZ NOT NULL DEFAULT now(),
    "body"                 TEXT        NOT NULL,
    "resolved_at"          TIMESTAMPTZ NULL,
    "resolved_by_uuid"     UUID        NULL,
    "resolved_by_username" TEXT        NULL,
    CONSTRAINT "fk_comment_parent" FOREIGN KEY ("parent_uuid") REFERENCES "comment" ("uuid") ON DELETE CASCADE,
    CONSTRAINT "ck_comment_reply_not_resolved" CHECK ("parent_uuid" IS NULL
        OR ("resolved_at" IS NULL AND "resolved_by_uuid" IS NULL AND "resolved_by_username" IS NULL))
);

CREATE INDEX "idx_comment_resource_object_uuid" ON "comment" ("resource", "object_uuid");

CREATE INDEX "idx_comment_parent_uuid" ON "comment" ("parent_uuid");
