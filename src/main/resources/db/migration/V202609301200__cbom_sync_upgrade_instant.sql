-- The instant this release was installed, read by a CBOM sync pass that lists the whole repository. Up to 2.19 deleting
-- a CBOM removed its row and left no tombstone, so a document listed before this instant that Core neither holds nor
-- has tombstoned may be one an operator deleted then; such a pass does not store it. Written only where the sync job is
-- already registered, which every earlier Core did at boot: a database no Core has run against holds no such deletion,
-- and a whole listing there must bring in a repository that predates the install. Internal, not an operator setting:
-- the settings API reads and writes utils rows by name and never this one.
INSERT INTO setting (uuid, i_author, i_cre, i_upd, "section", category, "name", "value")
SELECT gen_random_uuid(), 'system', now(), now(), 'PLATFORM', 'utils', 'cbomSyncUpgradedAt',
       to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
WHERE EXISTS (SELECT 1 FROM scheduled_job WHERE job_name = 'CbomSyncTask')
  AND NOT EXISTS (SELECT 1 FROM setting
                   WHERE "section" = 'PLATFORM' AND category = 'utils' AND "name" = 'cbomSyncUpgradedAt');
