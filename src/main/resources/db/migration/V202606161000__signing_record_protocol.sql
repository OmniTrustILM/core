-- Record the signing protocol actually used.
ALTER TABLE "signing_record"        ADD COLUMN "protocol" VARCHAR;
ALTER TABLE "signing_record_outbox" ADD COLUMN "protocol" VARCHAR;

UPDATE "signing_record"        SET "protocol" = 'TSP' WHERE "protocol" IS NULL;
UPDATE "signing_record_outbox" SET "protocol" = 'TSP' WHERE "protocol" IS NULL;

ALTER TABLE "signing_record"        ALTER COLUMN "protocol" SET NOT NULL;
ALTER TABLE "signing_record_outbox" ALTER COLUMN "protocol" SET NOT NULL;
