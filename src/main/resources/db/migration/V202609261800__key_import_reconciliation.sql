ALTER TABLE "key_import" ADD COLUMN "next_check_at" TIMESTAMPTZ;
ALTER TABLE "key_import" ADD COLUMN "last_sent_at" TIMESTAMPTZ;

-- An import open when the reconciliation arrives is looked at once its requester had the retry window to retry it.
UPDATE "key_import" SET "next_check_at" = "created_at" + INTERVAL '15 minutes'
    WHERE "state" IN ('REQUESTED', 'ACCEPTED');

-- An import recorded so far is taken as last sent when it was recorded.
UPDATE "key_import" SET "last_sent_at" = "created_at";
ALTER TABLE "key_import" ALTER COLUMN "last_sent_at" SET NOT NULL;

-- An import recorded by an instance that does not know the columns yet is scheduled in the same way.
ALTER TABLE "key_import" ALTER COLUMN "next_check_at" SET DEFAULT now() + INTERVAL '15 minutes';
ALTER TABLE "key_import" ALTER COLUMN "last_sent_at" SET DEFAULT now();

-- The reconciliation looks only at the imports it still has to settle.
CREATE INDEX "idx_key_import_next_check_at" ON "key_import" ("next_check_at")
    WHERE "state" IN ('REQUESTED', 'ACCEPTED', 'COMPENSATING');
