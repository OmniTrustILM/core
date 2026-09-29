ALTER TABLE "key_import" ADD COLUMN "next_check_at" TIMESTAMPTZ;
ALTER TABLE "key_import" ADD COLUMN "last_sent_at" TIMESTAMPTZ;

-- An import open when the reconciliation arrives was last sent when it last changed, since only a send and the
-- connector's acceptance of it change an open import, and it is looked at once its requester had the default retry
-- window.
UPDATE "key_import" SET "last_sent_at" = "updated_at", "next_check_at" = "updated_at" + INTERVAL '15 minutes'
    WHERE "state" IN ('REQUESTED', 'ACCEPTED');

-- A settled import is taken as last sent when it was recorded.
UPDATE "key_import" SET "last_sent_at" = "created_at" WHERE "last_sent_at" IS NULL;
ALTER TABLE "key_import" ALTER COLUMN "last_sent_at" SET NOT NULL;

-- An import recorded by an instance that does not know the columns yet is scheduled in the same way, with the default
-- retry window.
ALTER TABLE "key_import" ALTER COLUMN "next_check_at" SET DEFAULT now() + INTERVAL '15 minutes';
ALTER TABLE "key_import" ALTER COLUMN "last_sent_at" SET DEFAULT now();

-- A key has at most one import whose outcome is open, including one the reconciliation is undoing.
DROP INDEX "uq_key_import_open_attempt";
CREATE UNIQUE INDEX "uq_key_import_open_attempt" ON "key_import" ("spki_fingerprint")
    WHERE "state" IN ('REQUESTED', 'ACCEPTED', 'COMPENSATING');

-- The reconciliation looks only at the imports it still has to settle.
CREATE INDEX "idx_key_import_next_check_at" ON "key_import" ("next_check_at")
    WHERE "state" IN ('REQUESTED', 'ACCEPTED', 'COMPENSATING');
