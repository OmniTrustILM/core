-- scheduled_job.job_name is the key every caller looks a job up by -- SchedulerServiceImpl.runScheduledJob,
-- registerScheduler, enable, disable and delete all go through findByJobName -- and nothing declared it unique.
-- Registration is a read-then-write with no transaction of its own and no cluster lock, so two nodes booting together
-- both see "absent" and both insert. Optional<ScheduledJob> findByJobName then throws
-- IncorrectResultSizeDataAccessException on every one of those paths, and the job never runs again: silent until an
-- operator wonders why a schedule has fired nothing.
--
-- The window has been open for every system job since deployments started carrying scheduled_job rows; for the ones
-- registered on a first-ever boot there was no cluster to race, but a job added to an estate that is already running
-- and will be rolling-restarted lands squarely in it.

-- Any duplicates already written keep their history, which is repointed at the row that survives: the history's
-- foreign key is ON DELETE CASCADE, so deleting the loser outright would take the runs recorded against it.
UPDATE "scheduled_job_history" h
   SET "scheduled_job_uuid" = keep."uuid"
  FROM "scheduled_job" victim
  JOIN "scheduled_job" keep ON keep."job_name" = victim."job_name" AND keep."uuid" < victim."uuid"
 WHERE h."scheduled_job_uuid" = victim."uuid"
   AND NOT EXISTS (SELECT 1 FROM "scheduled_job" earlier
                    WHERE earlier."job_name" = victim."job_name" AND earlier."uuid" < keep."uuid");

DELETE FROM "scheduled_job" victim
 WHERE EXISTS (SELECT 1 FROM "scheduled_job" keep
                WHERE keep."job_name" = victim."job_name" AND keep."uuid" < victim."uuid");

ALTER TABLE "scheduled_job" ADD CONSTRAINT "uq_scheduled_job_job_name" UNIQUE ("job_name");
