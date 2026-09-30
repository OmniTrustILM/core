-- The instant this release was installed, read by the weekly CBOM reconcile. Up to 2.19 deleting a CBOM removed its row
-- and left no tombstone, so a document listed before this instant that Core neither holds nor has tombstoned may be one
-- an operator deleted then; the reconcile does not store it. Internal, not an operator setting: the settings API reads
-- and writes utils rows by name and never this one.
INSERT INTO setting (uuid, i_author, i_cre, i_upd, "section", category, "name", "value")
VALUES (gen_random_uuid(), 'system', now(), now(), 'PLATFORM', 'utils', 'cbomSyncUpgradedAt',
        to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
