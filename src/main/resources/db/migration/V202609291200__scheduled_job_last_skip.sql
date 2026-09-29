-- A task that declines a run (ScheduledJobSkippedException) has its history row deleted by design, so an hourly job
-- that mostly has nothing to do -- the PQC sweep on a quiet estate -- showed two history rows five days apart and read
-- as stalled. A row per skip is not the answer: an hourly job that skips 23 hours a day writes 8 760 rows a year
-- saying nothing happened. The skip is recorded on the job itself instead, in place, so the count never grows: when
-- the job last declined a run, and the task's own reason -- which is also what makes a week of "the CBOM repository
-- answered 503" visible where a deleted row said nothing.
--
-- Null means the job has never declined a run, which is what every row holds today.
ALTER TABLE "scheduled_job" ADD COLUMN "last_skipped_at" TIMESTAMPTZ;
ALTER TABLE "scheduled_job" ADD COLUMN "last_skip_reason" VARCHAR;
