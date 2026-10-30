-- Feed entries the CBOM header sync could not store, kept for a bounded retry. The repository search offers a
-- document once: the next run lists from (start of the last successful run - overlap), so an entry whose document
-- could not be read or whose row could not be written would otherwise be lost silently while the run still counted
-- as successful. A row is deleted the moment the document is stored; a row whose attempt budget is spent stays
-- PERMANENTLY_SKIPPED and is not loaded by a run again -- retention and an operator's view of it are follow-up work.
CREATE TABLE "cbom_sync_skip"
(
    "uuid"                  UUID        NOT NULL,
    -- The identity the repository serves documents by; no FK to cbom, which by definition has no row for it.
    "serial_number"         TEXT        NOT NULL,
    "version"               INT         NOT NULL,
    -- Shaped by Core, never a driver message: this string is operator-visible.
    "reason"                TEXT        NOT NULL,
    -- Sync runs that tried the entry, the first failure included.
    "attempts"              INT         NOT NULL,
    "first_skipped_at"      TIMESTAMPTZ NOT NULL,
    "last_attempt_at"       TIMESTAMPTZ NOT NULL,
    "state"                 TEXT        NOT NULL,
    -- The counts the feed reported, so a recovered entry gets the same header a first-try entry gets.
    "algorithms_count"      INT         NOT NULL,
    "certificates_count"    INT         NOT NULL,
    "protocols_count"       INT         NOT NULL,
    "crypto_material_count" INT         NOT NULL,
    "total_assets_count"    INT         NOT NULL,
    PRIMARY KEY ("uuid"),
    -- Target of the ON CONFLICT that counts another attempt.
    CONSTRAINT "uq_cbom_sync_skip_serial_version" UNIQUE ("serial_number", "version"),
    CONSTRAINT "ck_cbom_sync_skip_state" CHECK ("state" IN ('RETRYING', 'PERMANENTLY_SKIPPED'))
);
