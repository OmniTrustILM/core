-- Flyway runs this file in a single transaction; the explicit locks block concurrent writers (e.g. the
-- notification listener on a not-yet-migrated instance) so no pending_notification row can be written
-- against pre-renumbering version numbers between the statements below. Reads stay unblocked and the
-- repair is a few local statements, so the lock window is short.
LOCK TABLE "pending_notification", "notification_profile_version" IN SHARE ROW EXCLUSIVE MODE;

-- Concurrent profile edits could assign the same version number before the application serialized
-- version assignment. Renumber the versions of affected profiles into a dense sequence ordered by
-- version, then creation time, so the unique constraint below can be added. Profiles without
-- duplicate version numbers are left untouched.
--
-- pending_notification rows reference profile versions by (notification_profile_uuid, version) and
-- must be remapped consistently. This runs BEFORE the renumbering so the old->new mapping can be
-- computed from the untouched data. A reference to a duplicated version number is inherently
-- ambiguous (several rows claimed it); it maps to the latest-created of those rows, which is the
-- row the version-resolution query would most plausibly have meant.
UPDATE "pending_notification" pn
SET "version" = mapping.mapped_version
FROM (
    SELECT "notification_profile_uuid",
           "version" AS old_version,
           MAX(new_version) AS mapped_version
    FROM (
        SELECT "notification_profile_uuid",
               "version",
               ROW_NUMBER() OVER (
                   PARTITION BY "notification_profile_uuid"
                   ORDER BY "version", "created_at", "uuid"
               ) AS new_version
        FROM "notification_profile_version"
        WHERE "notification_profile_uuid" IN (
            SELECT "notification_profile_uuid"
            FROM "notification_profile_version"
            GROUP BY "notification_profile_uuid", "version"
            HAVING COUNT(*) > 1
        )
    ) renumbered
    GROUP BY "notification_profile_uuid", old_version
) mapping
WHERE pn."notification_profile_uuid" = mapping."notification_profile_uuid"
  AND pn."version" = mapping.old_version;

UPDATE "notification_profile_version" npv
SET "version" = renumbered.new_version
FROM (
    SELECT "uuid",
           ROW_NUMBER() OVER (
               PARTITION BY "notification_profile_uuid"
               ORDER BY "version", "created_at", "uuid"
           ) AS new_version
    FROM "notification_profile_version"
    WHERE "notification_profile_uuid" IN (
        SELECT "notification_profile_uuid"
        FROM "notification_profile_version"
        GROUP BY "notification_profile_uuid", "version"
        HAVING COUNT(*) > 1
    )
) renumbered
WHERE npv."uuid" = renumbered."uuid";

ALTER TABLE "notification_profile_version"
    ADD CONSTRAINT "uq_notification_profile_version" UNIQUE ("notification_profile_uuid", "version");
