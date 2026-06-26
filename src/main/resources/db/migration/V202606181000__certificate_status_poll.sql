CREATE TABLE "certificate_status_poll"
(
    "uuid"             UUID        NOT NULL PRIMARY KEY,
    "certificate_uuid" UUID        NOT NULL,
    "operation"        VARCHAR     NOT NULL,
    "attempt"          INTEGER     NOT NULL DEFAULT 0,
    "next_poll_at"     TIMESTAMPTZ NOT NULL,
    "i_cre"            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT "uq_certificate_status_poll_certificate" UNIQUE ("certificate_uuid"),
    CONSTRAINT "fk_certificate_status_poll_certificate" FOREIGN KEY ("certificate_uuid")
        REFERENCES "certificate" ("uuid") ON DELETE CASCADE
);

CREATE INDEX "idx_certificate_status_poll_next_poll_at" ON "certificate_status_poll" ("next_poll_at");
