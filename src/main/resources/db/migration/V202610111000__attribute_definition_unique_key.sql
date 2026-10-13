-- Keep one attribute definition per key: fold existing duplicates, then add two unique keys. Two concurrent first
-- registrations could each insert a row, and a duplicate makes every lookup of its definition fail.
--
-- A connector's definitions are unique by connector, attribute UUID and name; global metadata by name. A definition of
-- any other type without a connector is the platform's own and is keyed under one fixed connector UUID. A metadata
-- definition without a connector was left by a deleted connector; two of them may share a UUID and name and are not
-- folded.
--
-- Global metadata folds by name only where the engine looks it up by name: a row without a connector, or one whose
-- stored definition declares it global. Metadata an operator promoted to global keeps the connector's own declaration
-- unless an operator has since edited it, so the engine still looks it up by its connector; folding it away would split
-- that connector's values over a fresh row. Any other promoted row under the name is demoted rather than merged: it
-- keeps its connector and values and loses only the global flag.
--
-- An edited promotion stores the same declaration as a global its connector declares, so nothing tells the two apart.
-- A global with a connector is therefore kept over one without, which is found by name only and folds safely into it.
-- Where two globals of different connectors or attribute UUIDs fold, the folded one is listed: if it was an edited
-- promotion, its connector's next registration starts a new definition.
--
-- A duplicate folds into the kept row only when it reads its values the same way: the same content type, version and
-- protection level. A metadata duplicate that differs is detached instead: its connector is cleared, as deleting the
-- connector would, and so is its global flag, so the global-name key holds. Its values stay on the objects that hold
-- them and it stops matching lookups. A data or group duplicate that differs but holds nothing (no value, relation,
-- notification mapping or list-view binding) is dropped, which loses nothing: a connector's attribute listing registers
-- definitions without values, so racing listings of two connector versions leave such a row. One that holds something
-- is not one the fold can decide, so it is refused rather than guessed at.

-- Old pods keep running through a rolling upgrade: their writes and reads of definitions wait until the fold and both
-- keys are in place, so none of them inserts a duplicate, or binds a value to one, behind the fold.
-- Value inserts check their foreign key against this table, so they wait too.
-- While the lock is queued, old pods' reads of definitions queue behind it, so the wait is bounded: if old pods hold
-- the table longer than a minute, the migration fails, is rolled back whole, and runs again on the next start.
SET LOCAL lock_timeout = '60s';
LOCK TABLE "attribute_definition" IN ACCESS EXCLUSIVE MODE;

CREATE TEMP TABLE "attribute_definition_merge" (
    "duplicate_uuid" UUID PRIMARY KEY,
    "keep_uuid" UUID NOT NULL
) ON COMMIT DROP;

CREATE TEMP TABLE "attribute_definition_value_merge" (
    "duplicate_uuid" UUID PRIMARY KEY,
    "keep_uuid" UUID NOT NULL
) ON COMMIT DROP;

-- Rewrites the attributeDefinitionUuids binding of each stored column or filter that names a folded duplicate. Nothing
-- else in the entry changes: a filter's value may hold any text, a UUID included.
CREATE FUNCTION pg_temp.rebind_list_view_entries(entries JSONB) RETURNS JSONB AS $$
    SELECT COALESCE(jsonb_agg(
        CASE
            WHEN jsonb_typeof("stored"."entry" -> 'attributeDefinitionUuids') = 'array' AND EXISTS (
                SELECT 1
                  FROM jsonb_array_elements_text("stored"."entry" -> 'attributeDefinitionUuids') AS "bound"("uuid")
                  JOIN "attribute_definition_merge" AS "folded" ON "folded"."duplicate_uuid"::TEXT = "bound"."uuid"
            ) THEN jsonb_set("stored"."entry", '{attributeDefinitionUuids}', (
                SELECT COALESCE(jsonb_agg(to_jsonb("rebound"."uuid") ORDER BY "rebound"."position"), '[]'::JSONB)
                  FROM (SELECT COALESCE("folded"."keep_uuid"::TEXT, "bound"."uuid") AS "uuid",
                               min("bound"."position") AS "position"
                          FROM jsonb_array_elements_text("stored"."entry" -> 'attributeDefinitionUuids')
                               WITH ORDINALITY AS "bound"("uuid", "position")
                          LEFT JOIN "attribute_definition_merge" AS "folded"
                            ON "folded"."duplicate_uuid"::TEXT = "bound"."uuid"
                         GROUP BY 1) AS "rebound"))
            ELSE "stored"."entry"
        END
        ORDER BY "stored"."position"), '[]'::JSONB)
    FROM jsonb_array_elements(entries) WITH ORDINALITY AS "stored"("entry", "position")
$$ LANGUAGE SQL STABLE;

-- Whether a stored list view binds the definition: in a column, a filter or the sort, as the rebinding below reads them.
CREATE FUNCTION pg_temp.list_view_binds(definition UUID) RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1
          FROM "list_view" AS "view"
         WHERE "view"."sort_attribute_definition_uuids" @> ARRAY[definition]
            OR EXISTS (
                SELECT 1
                  FROM jsonb_array_elements(
                           CASE WHEN jsonb_typeof("view"."columns") = 'array' THEN "view"."columns" ELSE '[]'::JSONB END
                           || CASE WHEN jsonb_typeof("view"."filters") = 'array' THEN "view"."filters" ELSE '[]'::JSONB END
                       ) AS "stored"("entry")
                 WHERE jsonb_typeof("stored"."entry" -> 'attributeDefinitionUuids') = 'array'
                   AND "stored"."entry" -> 'attributeDefinitionUuids' @> jsonb_build_array(definition::TEXT)))
$$ LANGUAGE SQL STABLE;

-- Takes every duplicate the pass collected that reads its values differently from its kept row out of the fold.
CREATE FUNCTION pg_temp.split_incompatible_attribute_definitions() RETURNS VOID AS $$
DECLARE
    "dropped_uuids" TEXT;
    "refused" TEXT;
    "detached_uuids" TEXT;
BEGIN
    WITH "unused" AS (
        DELETE FROM "attribute_definition_merge" AS "folded"
         USING "attribute_definition" AS "duplicate", "attribute_definition" AS "kept"
         WHERE "duplicate"."uuid" = "folded"."duplicate_uuid"
           AND "kept"."uuid" = "folded"."keep_uuid"
           AND "duplicate"."type" <> 'META'
           AND ("duplicate"."content_type" IS DISTINCT FROM "kept"."content_type"
                OR "duplicate"."version" <> "kept"."version"
                OR COALESCE("duplicate"."protection_level", 'NONE') <> COALESCE("kept"."protection_level", 'NONE'))
           AND NOT EXISTS (SELECT 1 FROM "attribute_content_item" AS "item"
                            WHERE "item"."attribute_definition_uuid" = "duplicate"."uuid")
           AND NOT EXISTS (SELECT 1 FROM "attribute_relation" AS "relation"
                            WHERE "relation"."attribute_definition_uuid" = "duplicate"."uuid")
           AND NOT EXISTS (SELECT 1 FROM "notification_instance_mapped_attributes" AS "mapped"
                            WHERE "mapped"."attribute_definition_uuid" = "duplicate"."uuid")
           AND NOT pg_temp.list_view_binds("duplicate"."uuid")
        RETURNING "folded"."duplicate_uuid", "folded"."keep_uuid"
    ), "dropped" AS (
        DELETE FROM "attribute_definition"
         WHERE "uuid" IN (SELECT "duplicate_uuid" FROM "unused")
        RETURNING 1
    )
    SELECT string_agg("unused"."duplicate_uuid"::TEXT || ' (kept ' || "unused"."keep_uuid"::TEXT || ')', ', '
                      ORDER BY "unused"."duplicate_uuid")
      INTO "dropped_uuids"
      FROM "unused";

    IF "dropped_uuids" IS NOT NULL THEN
        RAISE NOTICE 'Attribute definitions dropped, as they read their values differently from the definition kept and hold nothing: %', "dropped_uuids";
    END IF;

    SELECT string_agg("folded"."duplicate_uuid"::TEXT || ' (kept ' || "folded"."keep_uuid"::TEXT || ')', ', ')
      INTO "refused"
      FROM "attribute_definition_merge" AS "folded"
      JOIN "attribute_definition" AS "duplicate" ON "duplicate"."uuid" = "folded"."duplicate_uuid"
      JOIN "attribute_definition" AS "kept" ON "kept"."uuid" = "folded"."keep_uuid"
     WHERE "duplicate"."type" <> 'META'
       AND ("duplicate"."content_type" IS DISTINCT FROM "kept"."content_type"
            OR "duplicate"."version" <> "kept"."version"
            OR COALESCE("duplicate"."protection_level", 'NONE') <> COALESCE("kept"."protection_level", 'NONE'));
    IF "refused" IS NOT NULL THEN
        RAISE EXCEPTION 'Duplicate attribute definitions differ in content type, version or protection level and cannot be merged: %. Resolve these pairs before upgrading; the 2.20.0 upgrade notes describe how.', "refused";
    END IF;

    WITH "detached" AS (
        DELETE FROM "attribute_definition_merge" AS "folded"
         USING "attribute_definition" AS "duplicate", "attribute_definition" AS "kept"
         WHERE "duplicate"."uuid" = "folded"."duplicate_uuid"
           AND "kept"."uuid" = "folded"."keep_uuid"
           AND ("duplicate"."content_type" IS DISTINCT FROM "kept"."content_type"
                OR "duplicate"."version" <> "kept"."version"
                OR COALESCE("duplicate"."protection_level", 'NONE') <> COALESCE("kept"."protection_level", 'NONE'))
        RETURNING "folded"."duplicate_uuid", "folded"."keep_uuid"
    ), "updated" AS (
        UPDATE "attribute_definition"
           SET "connector_uuid" = NULL, "global" = FALSE
         WHERE "uuid" IN (SELECT "duplicate_uuid" FROM "detached")
        RETURNING 1
    )
    SELECT string_agg("detached"."duplicate_uuid"::TEXT || ' (kept ' || "detached"."keep_uuid"::TEXT || ')', ', '
                      ORDER BY "detached"."duplicate_uuid")
      INTO "detached_uuids"
      FROM "detached";

    IF "detached_uuids" IS NOT NULL THEN
        RAISE NOTICE 'Attribute definitions detached from their connector, as they read their values differently from the definition kept: %', "detached_uuids";
    END IF;
END
$$ LANGUAGE plpgsql;

-- Folds every duplicate the pass collected into its kept row, then deletes it.
CREATE FUNCTION pg_temp.fold_attribute_definitions() RETURNS VOID AS $$
BEGIN
    -- A kept row whose group held a global definition takes over the global name.
    UPDATE "attribute_definition" AS "kept"
       SET "global" = TRUE
      FROM "attribute_definition_merge" AS "folded"
      JOIN "attribute_definition" AS "duplicate" ON "duplicate"."uuid" = "folded"."duplicate_uuid"
     WHERE "kept"."uuid" = "folded"."keep_uuid"
       AND "duplicate"."global" IS TRUE
       AND "kept"."global" IS NOT TRUE;

    -- One value per kept definition and digest, chosen across the whole group: the kept row's own value when it has
    -- one, otherwise the lowest of the duplicates' copies. Deciding over the group at once matters when two duplicates
    -- hold a value the kept row lacks.
    TRUNCATE "attribute_definition_value_merge";
    INSERT INTO "attribute_definition_value_merge" ("duplicate_uuid", "keep_uuid")
    SELECT "ranked"."uuid", "ranked"."keep_uuid"
      FROM (SELECT "item"."uuid",
                   first_value("item"."uuid") OVER (
                       PARTITION BY "member"."keep_uuid", "item"."json_digest"
                       ORDER BY ("item"."attribute_definition_uuid" = "member"."keep_uuid") DESC, "item"."uuid"
                   ) AS "keep_uuid"
              FROM "attribute_content_item" AS "item"
              JOIN (SELECT "duplicate_uuid" AS "definition_uuid", "keep_uuid" FROM "attribute_definition_merge"
                    UNION
                    SELECT "keep_uuid", "keep_uuid" FROM "attribute_definition_merge") AS "member"
                ON "member"."definition_uuid" = "item"."attribute_definition_uuid"
             WHERE "item"."json_digest" IS NOT NULL) AS "ranked"
     WHERE "ranked"."uuid" <> "ranked"."keep_uuid";

    UPDATE "attribute_content_2_object" AS "mapping"
       SET "attribute_content_item_uuid" = "folded"."keep_uuid"
      FROM "attribute_definition_value_merge" AS "folded"
     WHERE "mapping"."attribute_content_item_uuid" = "folded"."duplicate_uuid";

    -- An object mapped to more than one of the folded values now holds the same mapping twice: keep one.
    DELETE FROM "attribute_content_2_object" AS "mapping"
     USING "attribute_content_2_object" AS "kept"
     WHERE "mapping"."attribute_content_item_uuid" IN (SELECT "keep_uuid" FROM "attribute_definition_value_merge")
       AND "kept"."attribute_content_item_uuid" = "mapping"."attribute_content_item_uuid"
       AND "kept"."uuid" < "mapping"."uuid"
       AND "kept"."object_type" = "mapping"."object_type"
       AND "kept"."object_uuid" = "mapping"."object_uuid"
       AND "kept"."connector_uuid" IS NOT DISTINCT FROM "mapping"."connector_uuid"
       AND "kept"."source_object_type" IS NOT DISTINCT FROM "mapping"."source_object_type"
       AND "kept"."source_object_uuid" IS NOT DISTINCT FROM "mapping"."source_object_uuid"
       AND "kept"."purpose" IS NOT DISTINCT FROM "mapping"."purpose"
       AND "kept"."object_version" IS NOT DISTINCT FROM "mapping"."object_version";

    -- Deleted before the remaining values move, so the value constraint never sees two rows at once.
    DELETE FROM "attribute_content_item" AS "item"
     USING "attribute_definition_value_merge" AS "folded"
     WHERE "item"."uuid" = "folded"."duplicate_uuid";

    UPDATE "attribute_content_item" AS "item"
       SET "attribute_definition_uuid" = "folded"."keep_uuid"
      FROM "attribute_definition_merge" AS "folded"
     WHERE "item"."attribute_definition_uuid" = "folded"."duplicate_uuid";

    UPDATE "attribute_relation" AS "relation"
       SET "attribute_definition_uuid" = "folded"."keep_uuid"
      FROM "attribute_definition_merge" AS "folded"
     WHERE "relation"."attribute_definition_uuid" = "folded"."duplicate_uuid";

    DELETE FROM "attribute_relation" AS "relation"
     USING "attribute_relation" AS "kept"
     WHERE "relation"."attribute_definition_uuid" IN (SELECT "keep_uuid" FROM "attribute_definition_merge")
       AND "kept"."attribute_definition_uuid" = "relation"."attribute_definition_uuid"
       AND "kept"."uuid" < "relation"."uuid"
       AND "kept"."resource" = "relation"."resource"
       AND "kept"."function_group_code" IS NOT DISTINCT FROM "relation"."function_group_code"
       AND "kept"."kind" IS NOT DISTINCT FROM "relation"."kind";

    -- Before the definitions go: this foreign key cascades, so deleting first would drop the mapping silently.
    UPDATE "notification_instance_mapped_attributes" AS "mapped"
       SET "attribute_definition_uuid" = "folded"."keep_uuid"
      FROM "attribute_definition_merge" AS "folded"
     WHERE "mapped"."attribute_definition_uuid" = "folded"."duplicate_uuid";

    DELETE FROM "notification_instance_mapped_attributes" AS "mapped"
     USING "notification_instance_mapped_attributes" AS "kept"
     WHERE "mapped"."attribute_definition_uuid" IN (SELECT "keep_uuid" FROM "attribute_definition_merge")
       AND "kept"."attribute_definition_uuid" = "mapped"."attribute_definition_uuid"
       AND "kept"."uuid" < "mapped"."uuid"
       AND "kept"."notification_instance_ref_uuid" = "mapped"."notification_instance_ref_uuid"
       AND "kept"."mapping_attribute_uuid" IS NOT DISTINCT FROM "mapped"."mapping_attribute_uuid";

    UPDATE "list_view"
       SET "columns" = pg_temp.rebind_list_view_entries("columns")
     WHERE jsonb_typeof("columns") = 'array'
       AND pg_temp.rebind_list_view_entries("columns") IS DISTINCT FROM "columns";

    UPDATE "list_view"
       SET "filters" = pg_temp.rebind_list_view_entries("filters")
     WHERE jsonb_typeof("filters") = 'array'
       AND pg_temp.rebind_list_view_entries("filters") IS DISTINCT FROM "filters";

    UPDATE "list_view"
       SET "sort_attribute_definition_uuids" = ARRAY(
               SELECT "rebound"."uuid"
                 FROM (SELECT COALESCE("folded"."keep_uuid", "bound"."uuid") AS "uuid",
                              min("bound"."position") AS "position"
                         FROM unnest("list_view"."sort_attribute_definition_uuids")
                              WITH ORDINALITY AS "bound"("uuid", "position")
                         LEFT JOIN "attribute_definition_merge" AS "folded"
                           ON "folded"."duplicate_uuid" = "bound"."uuid"
                        GROUP BY 1) AS "rebound"
                ORDER BY "rebound"."position")
     WHERE "sort_attribute_definition_uuids" && ARRAY(SELECT "duplicate_uuid" FROM "attribute_definition_merge");

    DELETE FROM "attribute_definition" AS "definition"
     USING "attribute_definition_merge" AS "folded"
     WHERE "definition"."uuid" = "folded"."duplicate_uuid";

    TRUNCATE "attribute_definition_merge";
END
$$ LANGUAGE plpgsql;

-- First pass: global definitions, one per type and name. A row is shared when the engine looks it up by name, and
-- promoted otherwise. The kept row is a shared one when the group has any, then a data row with an operation, then a
-- row with a connector, then the oldest. Every other shared row folds into it, or is detached when it reads its values
-- differently. Every other promoted row is demoted instead and never enters the fold; a promoted row alone under its
-- name stays global.
CREATE FUNCTION pg_temp.collect_global_attribute_definitions() RETURNS VOID AS $$
DECLARE
    "demoted_uuids" TEXT;
BEGIN
    WITH "ranked" AS (
        SELECT "uuid", "promoted",
               first_value("uuid") OVER (
                   PARTITION BY "type", "name"
                   ORDER BY "promoted", ("type" = 'DATA' AND "operation" IS NULL), ("connector_uuid" IS NULL),
                            "created_at", "uuid"
               ) AS "keep_uuid"
          FROM (SELECT *,
                       "connector_uuid" IS NOT NULL
                           AND ("definition" -> 'properties' ->> 'global') IS DISTINCT FROM 'true' AS "promoted"
                  FROM "attribute_definition"
                 WHERE "global" IS TRUE) AS "flagged"
    ), "demoted" AS (
        UPDATE "attribute_definition"
           SET "global" = FALSE
         WHERE "uuid" IN (SELECT "ranked"."uuid"
                            FROM "ranked"
                           WHERE "ranked"."promoted"
                             AND "ranked"."uuid" <> "ranked"."keep_uuid")
        RETURNING "uuid"
    ), "collected" AS (
        INSERT INTO "attribute_definition_merge" ("duplicate_uuid", "keep_uuid")
        SELECT "ranked"."uuid", "ranked"."keep_uuid"
          FROM "ranked"
         WHERE NOT "ranked"."promoted"
           AND "ranked"."uuid" <> "ranked"."keep_uuid"
        RETURNING 1
    )
    SELECT string_agg("demoted"."uuid"::TEXT, ', ' ORDER BY "demoted"."uuid")
      INTO "demoted_uuids"
      FROM "demoted";

    IF "demoted_uuids" IS NOT NULL THEN
        RAISE NOTICE 'Global metadata demoted to its connector, as another global definition holds its name: %', "demoted_uuids";
    END IF;
END
$$ LANGUAGE plpgsql;

-- Lists the global rows with a connector that the first pass folds into a row of another connector or attribute UUID.
CREATE FUNCTION pg_temp.report_global_folds_across_connectors() RETURNS VOID AS $$
DECLARE
    "folded_uuids" TEXT;
BEGIN
    SELECT string_agg("folded"."duplicate_uuid"::TEXT || ' (kept ' || "folded"."keep_uuid"::TEXT || ')', ', '
                      ORDER BY "folded"."duplicate_uuid")
      INTO "folded_uuids"
      FROM "attribute_definition_merge" AS "folded"
      JOIN "attribute_definition" AS "duplicate" ON "duplicate"."uuid" = "folded"."duplicate_uuid"
      JOIN "attribute_definition" AS "kept" ON "kept"."uuid" = "folded"."keep_uuid"
     WHERE "duplicate"."connector_uuid" IS NOT NULL
       AND ("duplicate"."connector_uuid", "duplicate"."attribute_uuid")
           IS DISTINCT FROM ("kept"."connector_uuid", "kept"."attribute_uuid");

    IF "folded_uuids" IS NOT NULL THEN
        RAISE NOTICE 'Global metadata folded into the global definition of another connector or attribute UUID; if an operator had edited it after promoting it, its connector registers its next values to a new definition: %', "folded_uuids";
    END IF;
END
$$ LANGUAGE plpgsql;

SELECT pg_temp.collect_global_attribute_definitions();
SELECT pg_temp.split_incompatible_attribute_definitions();
SELECT pg_temp.report_global_folds_across_connectors();
SELECT pg_temp.fold_attribute_definitions();

-- Second pass: every definition with a connector key, globals kept by the first pass and promoted rows it demoted
-- included, so a global and a connector row with the same key cannot both survive. It keeps a data row with an
-- operation first, then a global row, then the oldest. The global row is kept even when the connector row is older:
-- other connectors share it and the API addresses it by its UUID.
INSERT INTO "attribute_definition_merge" ("duplicate_uuid", "keep_uuid")
SELECT "ranked"."uuid", "ranked"."keep_uuid"
  FROM (SELECT "uuid",
               first_value("uuid") OVER (
                   PARTITION BY "type", "connector_key", "attribute_uuid", "name"
                   ORDER BY ("type" = 'DATA' AND "operation" IS NULL), ("global" IS NOT TRUE), "created_at", "uuid"
               ) AS "keep_uuid"
          FROM (SELECT *,
                       CASE WHEN "type" = 'META' THEN "connector_uuid"
                            ELSE COALESCE("connector_uuid", '00000000-0000-0000-0000-000000000000'::UUID)
                       END AS "connector_key"
                  FROM "attribute_definition") AS "keyed"
         WHERE "connector_key" IS NOT NULL) AS "ranked"
 WHERE "ranked"."uuid" <> "ranked"."keep_uuid";

SELECT pg_temp.split_incompatible_attribute_definitions();
SELECT pg_temp.fold_attribute_definitions();

ALTER TABLE "attribute_definition"
    ADD COLUMN "connector_key" UUID
        GENERATED ALWAYS AS (CASE WHEN "type" = 'META' THEN "connector_uuid"
                                  ELSE COALESCE("connector_uuid", '00000000-0000-0000-0000-000000000000'::UUID)
                             END) STORED,
    ADD COLUMN "global_name" TEXT GENERATED ALWAYS AS (CASE WHEN "global" THEN "name" END) STORED;

ALTER TABLE "attribute_definition"
    ADD CONSTRAINT "uq_attribute_definition_key" UNIQUE ("type", "connector_key", "attribute_uuid", "name");

ALTER TABLE "attribute_definition"
    ADD CONSTRAINT "uq_attribute_definition_global_name" UNIQUE ("type", "global_name");

DROP FUNCTION pg_temp.fold_attribute_definitions();
DROP FUNCTION pg_temp.collect_global_attribute_definitions();
DROP FUNCTION pg_temp.report_global_folds_across_connectors();
DROP FUNCTION pg_temp.split_incompatible_attribute_definitions();
DROP FUNCTION pg_temp.rebind_list_view_entries(JSONB);
DROP FUNCTION pg_temp.list_view_binds(UUID);
