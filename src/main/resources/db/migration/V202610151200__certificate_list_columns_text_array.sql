-- The three list-valued X.509 properties were stored as JSON text. Builds before 2024 wrote the text null for a
-- certificate without the extension, and an empty list was written as [] -- both mean the property is absent.
-- ALTER ... USING cannot run a subquery, so the conversion goes through a function dropped again below.
CREATE FUNCTION json_text_array_to_text_array(value TEXT) RETURNS TEXT[]
    LANGUAGE sql
    IMMUTABLE AS
$$
SELECT CASE
           WHEN value IS NULL OR value IN ('', 'null', '[]') THEN NULL
           ELSE ARRAY(SELECT jsonb_array_elements_text(value::jsonb))
           END
$$;

-- One statement, so the table is rewritten once. It holds an exclusive lock while it runs.
ALTER TABLE "certificate"
    ALTER COLUMN "extended_key_usage" TYPE TEXT[] USING json_text_array_to_text_array("extended_key_usage"),
    ALTER COLUMN "qc_type" TYPE TEXT[] USING json_text_array_to_text_array("qc_type"),
    ALTER COLUMN "qc_cc_legislation" TYPE TEXT[] USING json_text_array_to_text_array("qc_cc_legislation");

DROP FUNCTION json_text_array_to_text_array(TEXT);

CREATE INDEX "idx_certificate_extended_key_usage" ON "certificate" USING GIN ("extended_key_usage");
