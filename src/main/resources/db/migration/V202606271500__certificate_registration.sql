-- Register->issue binding: persists the connector-returned CA tracking handle (meta) so a later
-- register-bound issue can lock the binding, replay the handle, and clear it. One row per certificate;
-- its presence marks the certificate register-bound even when the connector returned no meta.
CREATE TABLE "certificate_registration"
(
    "uuid"             UUID        NOT NULL PRIMARY KEY,
    "certificate_uuid" UUID        NOT NULL,
    "meta"             TEXT        NULL     DEFAULT NULL,
    "i_cre"            TIMESTAMPTZ NOT NULL DEFAULT now(),
    "i_upd"            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT "uq_certificate_registration_certificate" UNIQUE ("certificate_uuid"),
    CONSTRAINT "fk_certificate_registration_certificate" FOREIGN KEY ("certificate_uuid")
        REFERENCES "certificate" ("uuid") ON DELETE CASCADE
);
