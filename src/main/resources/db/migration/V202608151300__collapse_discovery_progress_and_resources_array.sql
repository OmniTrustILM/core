-- The progress_* columns collapse into a single jsonb snapshot and resources becomes TEXT[]; the rationale
-- lives on the entity fields. Both columns are unwritten so far, hence plain drop-and-add.
ALTER TABLE "discovery"
    DROP COLUMN "progress_processed",
    DROP COLUMN "progress_total_estimate",
    DROP COLUMN "progress_by_resource",
    DROP COLUMN "progress_phase",
    ADD COLUMN "progress" JSONB,
    DROP COLUMN "resources",
    ADD COLUMN "resources" TEXT[];
