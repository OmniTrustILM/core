-- Durable authorization record for a pre-registered certificate: the encrypted challenge, issuance window,
-- failed-attempt count, and lifecycle state that let a later renew or rekey prove the registered subject.
-- One row per certificate. Distinct from the transient certificate_registration binding, which is cleared at
-- issuance; this record survives issuance to authorize follow-up operations.
CREATE TABLE "certificate_registration_authorization"
(
    "uuid"             UUID        NOT NULL PRIMARY KEY,
    "certificate_uuid" UUID        NOT NULL,
    "challenge"        TEXT        NOT NULL,
    "expires_at"       TIMESTAMPTZ NULL,
    "failed_attempts"  INT         NOT NULL DEFAULT 0,
    "state"            VARCHAR     NOT NULL,
    "i_author"         VARCHAR,
    "i_cre"            TIMESTAMPTZ NOT NULL DEFAULT now(),
    "i_upd"            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT "uq_certificate_registration_authorization_certificate" UNIQUE ("certificate_uuid"),
    CONSTRAINT "fk_certificate_registration_authorization_certificate" FOREIGN KEY ("certificate_uuid")
        REFERENCES "certificate" ("uuid") ON DELETE CASCADE
);
