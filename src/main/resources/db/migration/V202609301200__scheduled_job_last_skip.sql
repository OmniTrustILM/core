-- A task that declines a run (ScheduledJobSkippedException) has its history row removed, so these columns are what
-- remains of the run: when the job last declined one, and the task's own reason. They are written in place, on the
-- job, so a job that declines most of its runs adds nothing per skip.
--
-- Null means the job has never declined a run, which is what every row holds today.
ALTER TABLE "scheduled_job" ADD COLUMN "last_skipped_at" TIMESTAMPTZ;
ALTER TABLE "scheduled_job" ADD COLUMN "last_skip_reason" VARCHAR;
