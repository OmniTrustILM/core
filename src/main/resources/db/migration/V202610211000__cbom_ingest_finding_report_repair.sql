-- Reports written before the report was served named the exception class for a component whose reading threw, and
-- stamped each line with its own time. A SYNCED CBOM is never read again, so its stored report is repaired here, to
-- what the current writer would have recorded: the fixed reason, with the occurrences of every class it replaces.
WITH "legacy" AS (
    DELETE FROM "cbom_ingest_finding"
    WHERE "kind" = 'SKIP'
      AND "detail" ~ '^the component could not be turned into an asset: [A-Za-z_$][A-Za-z0-9_$]*$'
    RETURNING "cbom_uuid", "component_name", "occurrences", "recorded_at"
)
INSERT INTO "cbom_ingest_finding" AS "f"
    ("uuid", "cbom_uuid", "kind", "component_name", "detail", "occurrences", "recorded_at")
SELECT gen_random_uuid(), "cbom_uuid", 'SKIP', min("component_name"),
       'the component could not be turned into an asset: reading it failed', sum("occurrences"), max("recorded_at")
FROM "legacy"
GROUP BY "cbom_uuid"
ON CONFLICT ("cbom_uuid", "kind", "detail") DO UPDATE
    SET "occurrences" = "f"."occurrences" + EXCLUDED."occurrences",
        "recorded_at" = greatest("f"."recorded_at", EXCLUDED."recorded_at");

-- One report is one sync attempt, and it now carries one recordedAt: the time its last line was written.
UPDATE "cbom_ingest_finding" AS "f"
SET "recorded_at" = "report"."recorded_at"
FROM (SELECT "cbom_uuid", max("recorded_at") AS "recorded_at" FROM "cbom_ingest_finding" GROUP BY "cbom_uuid") AS "report"
WHERE "f"."cbom_uuid" = "report"."cbom_uuid"
  AND "f"."recorded_at" <> "report"."recorded_at";
