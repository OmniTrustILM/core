-- Support dynamic attribute mapping in execution items.
-- When source_field_source is set (META, DATA, or CUSTOM), the execution reads a live attribute
-- value from that source instead of using static data.
-- source_field_identifier format: name|ContentType (e.g., "certAttr|STRING").
-- Both columns are nullable; NULL means no source mapping is configured.
ALTER TABLE execution_item ADD COLUMN source_field_source TEXT NULL DEFAULT NULL;
ALTER TABLE execution_item ADD COLUMN source_field_identifier TEXT NULL DEFAULT NULL;
